/*
 * FIO I/O engine for NVMeDirect
 *
 * Copyright (c) 2016 Computer Systems Laboratory, Sungkyunkwan University.
 * http://csl.skku.edu
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the therm and condotions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include <lib_nvmed.h>
#define LAST_POS(f)	((f)->engine_data)

struct nvmed_aio_data {
	struct io_u **aio_events;
	unsigned int queued;
	struct nvmed_handle *handle;

	int cbc;
	int iodepth;

	int head, tail;
};

static struct io_u *fio_nvmed_event_aio(struct thread_data *td, int event)
{
	struct nvmed_aio_data* aiod = td->io_ops->data;
	struct io_u* io_u = NULL;

    if (aiod->head != aiod->tail) {
		io_u = aiod->aio_events[aiod->head];
		if(++aiod->head > aiod->iodepth) aiod->head = 0;
	}

	return io_u;
}

static void fio_nvmed_completion_cb(const struct nvmed_aio_ctx* context, void* data) {
	struct io_u *io_u = (struct io_u*)data;
	struct nvmed_aio_data *aiod = context->private;
	io_u->seen = 1;
	io_u->resid = 0;
	aiod->queued--;
	aiod->cbc++;
	aiod->aio_events[aiod->tail] = io_u;
	if (++aiod->tail > aiod->iodepth) aiod->tail = 0;
	return;
}

static int fill_timespec(struct timespec *ts)
{
#ifdef CONFIG_CLOCK_GETTIME
#ifdef CONFIG_CLOCK_MONOTONIC
	clockid_t clk = CLOCK_MONOTONIC;
#else
	clockid_t clk = CLOCK_REALTIME;
#endif
	if (!clock_gettime(clk, ts))
		return 0;

	perror("clock_gettime");
	return 1;
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
	return 0;
#endif
}
static unsigned long long ts_utime_since_now(struct timespec *t)
{
	long long sec, nsec;
	struct timespec now;

	if (fill_timespec(&now))
		return 0;
	
	sec = now.tv_sec - t->tv_sec;
	nsec = now.tv_nsec - t->tv_nsec;
	if (sec > 0 && nsec < 0) {
		sec--;
		nsec += 1000000000;
	}

	sec *= 1000000;
	nsec /= 1000;
	return sec + nsec;
}

static int numResultSum = 0;
static int fio_nvmed_getevents_aio(struct thread_data *td, unsigned int min,
				  unsigned int max, const struct timespec *t)
{
	struct nvmed_aio_data* aiod = td->io_ops->data;
	unsigned int result = 0;
	int have_timeout = 0;
	struct timespec start;

	if (t && !fill_timespec(&start))
		have_timeout = 1;
	else
		memset(&start, 0, sizeof(start));

	for(;;) {
		result += nvmed_handle_complete(aiod->handle);
		if(result>=min) break;
		if (have_timeout) {
			unsigned long long usec;

			usec = (t->tv_sec * 1000000) + (t->tv_nsec / 1000);
			if (ts_utime_since_now(&start) > usec)
				break;
		}
	}
	numResultSum+= result;
	return result;
}

static int fio_nvmed_cancel(struct thread_data *td, struct io_u *io_u)
{
	return 0;
}

static int fio_nvmed_queue_aio(struct thread_data *td, struct io_u *io_u)
{
	struct nvmed_aio_data* aiod = td->io_ops->data;
	struct nvmed_handle* handle = aiod->handle;
	struct nvmed_aio_ctx *context = &io_u->nvmed_context;
	int ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ) {
		ret = nvmed_aio_read(context);
	}
	else if (io_u->ddir == DDIR_WRITE) {
		ret = nvmed_aio_write(context);
	}
	else if (io_u->ddir == DDIR_TRIM) {
		ret = nvmed_discard(handle, io_u->offset, io_u->xfer_buflen);
		return FIO_Q_COMPLETED;
	} else {
		ret = nvmed_flush(handle);
		return FIO_Q_COMPLETED;
	}
	
	if(ret == NVMED_AIO_BUSY)
		return FIO_Q_BUSY;

	aiod->queued++;
	return FIO_Q_QUEUED;
}

/*
 * The ->prep() function is called for each io_u prior to being submitted
 * with ->queue(). This hook allows the io engine to perform any
 * preparatory actions on the io_u, before being submitted. Not required.
 */
static int fio_nvmed_prep_aio(struct thread_data *td, struct io_u *io_u)
{
	struct nvmed_aio_data* aiod = td->io_ops->data;
	struct nvmed_handle* handle = aiod->handle;
	struct nvmed_aio_ctx* context = &io_u->nvmed_context;

	context->handle = handle;

	if(io_u->ddir == DDIR_READ) context->opcode = nvme_cmd_read;
	else context->opcode = nvme_cmd_write;

	context->start_lba = io_u->offset;
	context->len = io_u->xfer_buflen;
	context->buf = io_u->xfer_buf;
	context->status = AIO_INIT;
	context->num_init_io = 0;
	context->num_complete_io = 0;
	context->aio_callback = fio_nvmed_completion_cb;
	context->private = (void *)aiod;
	context->cb_userdata = (void *)io_u;

	if(io_u->prp_translated) {
		context->prpList = io_u->prpList;
	}
	else {
		context->prpList = NULL;
	}
	io_u->seen = 0;

	return 0;
}

/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
pthread_mutex_t nvme_mutex = PTHREAD_MUTEX_INITIALIZER;
struct nvmed* nvmed = NULL;
struct nvmed_queue* squeue = NULL;

static int fio_nvmed_init_sd_aio(struct thread_data *td)
{
	struct fio_file *f = td->files[0];
	
	struct nvmed_handle* handle;
	struct nvmed_queue* queue;
	
	struct nvmed_aio_data *aiod;

	struct io_u *io_u;
	int i;

	if(f->file_offset) {
		if(f->file_offset % 4096 != 0) {
			printf("File offset should be aligned to 4KB\n");
			return 1;
		}
	}

	pthread_mutex_lock(&nvme_mutex);


	nvmed = nvmed_open(f->file_name, 0);

	queue = nvmed_queue_create(nvmed, 0);
	handle = nvmed_handle_create(queue, 0);
	nvmed_handle_feature_set(handle, HANDLE_DIRECT_IO, true);

	aiod = malloc(sizeof(*aiod));
	memset(aiod, 0, sizeof(*aiod));
	aiod->aio_events = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(aiod->aio_events, 0, td->o.iodepth * sizeof(struct io_u *));
	
	aiod->cbc=0;
	aiod->head = 0;
	aiod->tail = 0;

	aiod->iodepth = td->o.iodepth;

	aiod->handle = handle;
	
	if(f->file_offset) {
		nvmed_lseek(handle, f->file_offset, SEEK_SET);
	}

	td->io_ops->data = aiod;

	io_u_qiter(&td->io_u_all, io_u, i) {
		virt_to_phys(nvmed, io_u->buf, io_u->prpList, td_max_bs(td));
		io_u->prp_translated = 1;
	}

	pthread_mutex_unlock(&nvme_mutex);
	return 0;
}

static int fio_nvmed_commit_aio(struct thread_data *td)
{
	struct nvmed_aio_data *aiod = td->io_ops->data;
	int ret = 0;

	nvmed_aio_queue_submit(aiod->handle);

	return ret;
}

static void fio_nvmed_cleanup_sd_aio(struct thread_data *td)
{
	struct nvmed* nvmed;
	struct nvmed_queue* queue;
	struct nvmed_handle* handle;
	struct nvmed_aio_data* aiod;

	pthread_mutex_lock(&nvme_mutex);

	aiod = td->io_ops->data;
	handle = aiod->handle;
	queue = handle->queue;
	nvmed = queue->nvmed;

	nvmed_handle_destroy(handle);

	free(aiod->aio_events);
	free(aiod);

	nvmed_queue_destroy(queue);

	if(nvmed->numQueue == 0) {
		nvmed_close(nvmed);
	}
	
	pthread_mutex_unlock(&nvme_mutex);
}

/*
 * Hook for opening the given file. Unless the engine has special
 * needs, it usually just provides generic_file_open() as the handler.
 */
static int fio_nvmed_open(struct thread_data *td, struct fio_file *f)
{
	return generic_open_file(td, f);
}

/*
 * Hook for closing a file. See fio_nvmed_open().
 */
static int fio_nvmed_close(struct thread_data *td, struct fio_file *f)
{
	return generic_close_file(td, f);
}

struct ioengine_ops ioengine_sd_aio = {
	.name		= "nvmed_aio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_nvmed_init_sd_aio,
	.prep		= fio_nvmed_prep_aio,
	.queue		= fio_nvmed_queue_aio,
	.commit		= fio_nvmed_commit_aio,
	.cancel		= fio_nvmed_cancel,
	.getevents	= fio_nvmed_getevents_aio,
	.event		= fio_nvmed_event_aio,
	.cleanup	= fio_nvmed_cleanup_sd_aio,
	.open_file	= fio_nvmed_open,
	.close_file	= fio_nvmed_close,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO,

};

static void fio_init fio_nvmed_register(void)
{
	register_ioengine(&ioengine_sd_aio);
}

static void fio_exit fio_nvmed_unregister(void)
{
	unregister_ioengine(&ioengine_sd_aio);
}

