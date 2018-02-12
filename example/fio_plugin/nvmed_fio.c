/*
 * FIO I/O engine for NVMeDirect
 *
 * Copyright (c) 2016 Computer Systems Laboratory, Sungkyunkwan University.
 * http://csl.skku.edu
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <assert.h>
#include <pthread.h>

#include <lib_nvmed.h>
#include <nvmed.h>
#include <nvme_hdr.h>
#include "fio.h"
#include "optgroup.h"

#if 0
	#define FUNC_DEBUG()	fprintf(stderr, "%s Called\n", __func__);
#else
	#define FUNC_DEBUG()
#endif
#if 0
    #define DEBUG(fmt, arg...)  printf("#" fmt "\n", ##arg)
#else
    #define DEBUG(fmt, arg...)
#endif

#define TDEBUG(fmt, arg...) DEBUG("%s[%d] " fmt, __func__, td->thread_number, ##arg)

typedef struct {
	pthread_mutex_t mutex;
	NVMED*			nvmed;
	uint64_t		dev_size;
	int				active_queue;
} nvmed_context_t;

typedef struct {
	NVMED_QUEUE*	queue;
	NVMED_HANDLE*	handle;

    struct io_u**           iocq;   // io completion queue
    int                     head;   // head of the io completion queue
    int                     tail;   // tail of the io completion queue
    int                     cbc;    // completion callback count
} nvmed_io_thread_t;

typedef struct {
	struct thread_data* td;
	struct io_u* io_u;

	NVMED_AIO_CTX context;
	void* buf;
} nvmed_io_u_t;

static nvmed_context_t nvmed = { .nvmed = NULL,
								 .mutex = PTHREAD_MUTEX_INITIALIZER,
								 .active_queue = 0, };
/*
 * The ->init() function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
static int fio_nvmed_init(struct thread_data *td)
{
	FUNC_DEBUG();
	nvmed_io_thread_t *nvmed_io_handle;
	NVMED_QUEUE *queue;
	NVMED_HANDLE *handle;
	nvmed_io_handle = calloc(1, sizeof(nvmed_io_thread_t));
	
    pthread_mutex_lock(&nvmed.mutex);

	queue = nvmed_queue_create(nvmed.nvmed, 0);
	handle = nvmed_handle_create(queue, 0);
	nvmed.active_queue++;

    pthread_mutex_unlock(&nvmed.mutex);

	nvmed_handle_feature_set(handle, HANDLE_DIRECT_IO, true);
	nvmed_handle_feature_set(handle, HANDLE_HINT_DMEM, true);

	nvmed_io_handle->queue	= queue;
	nvmed_io_handle->handle = handle;

	nvmed_io_handle->iocq = calloc(td->o.iodepth + 1, sizeof(void*));
	if(!nvmed_io_handle->iocq) {
		free(nvmed_io_handle);
		return 1;
	}

	td->io_ops_data = nvmed_io_handle;

	return 0;
}

/*
 * This is paired with the ->init() function and is called when a thread is
 * done doing io. Should tear down anything setup by the ->init() function.
 * Not required.
 */
static void fio_nvmed_cleanup(struct thread_data *td)
{
	FUNC_DEBUG();
	nvmed_io_thread_t *nvmed_io_handle = td->io_ops_data;
	NVMED_QUEUE *queue = nvmed_io_handle->queue;
	NVMED_HANDLE *handle = nvmed_io_handle->handle;

    pthread_mutex_lock(&nvmed.mutex);

	nvmed_handle_destroy(handle);
	nvmed_queue_destroy(queue);

	nvmed.active_queue--;
	
	free(nvmed_io_handle->iocq);
	free(nvmed_io_handle);

	if(nvmed.active_queue == 0) {
		nvmed_close(nvmed.nvmed);
		nvmed.nvmed = NULL;
	}

    pthread_mutex_unlock(&nvmed.mutex);
}

/*
 * The ->event() hook is called to match an event number with an io_u.
 * After the core has called ->getevents() and it has returned eg 3,
 * the ->event() hook must return the 3 events that have completed for
 * subsequent calls to ->event() with [0-2]. Required.
 */
static struct io_u* fio_nvmed_event(struct thread_data *td, int event)
{
	FUNC_DEBUG();
    nvmed_io_thread_t* nvmed_io_handle = td->io_ops_data;
    struct io_u* io_u = NULL;

    if (nvmed_io_handle->head != nvmed_io_handle->tail) {
        io_u = nvmed_io_handle->iocq[nvmed_io_handle->head];
        if (++nvmed_io_handle->head > td->o.iodepth) nvmed_io_handle->head = 0;
        TDEBUG("GET iou=%p head=%d", io_u, nvmed_io_handle->head);
    }

    return io_u;
}

/*
 * Completion callback function.
 */
static void nvmed_completion_cb(const NVMED_AIO_CTX* context, void* data)
{
	FUNC_DEBUG();
	struct io_u *io_u = (struct io_u*)data;
	nvmed_io_u_t *nvmed_iou = io_u->engine_data;
	nvmed_io_thread_t *nvmed_io_handle = nvmed_iou->td->io_ops_data;

	nvmed_io_handle->iocq[nvmed_io_handle->tail] = io_u;
	if(++nvmed_io_handle->tail > nvmed_iou->td->o.iodepth) nvmed_io_handle->tail = 0;
	nvmed_io_handle->cbc++;
}

/*
 * The ->getevents() hook is used to reap completion events from an async
 * io engine. It returns the number of completed events since the last call,
 * which may then be retrieved by calling the ->event() hook with the event
 * numbers. Required.
 */
static int fio_nvmed_getevents(struct thread_data *td, unsigned int min,
                              unsigned int max, const struct timespec *t)
{
	FUNC_DEBUG();
	nvmed_io_thread_t *nvmed_io_handle = td->io_ops_data;
    int events = 0;
    struct timespec t0, t1;
    uint64_t timeout = 0;

    if (t) {
        timeout = t->tv_sec * 1000000000L + t->tv_nsec;
        clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
    }

    for (;;) {
		nvmed_aio_handle_complete(nvmed_io_handle->handle);

        // wait for completion
        while (nvmed_io_handle->cbc) {
            nvmed_io_handle->cbc--;
            events++;
            TDEBUG("events=%d cbc=%d", events, nvmed_io_handle->cbc);
            if (events >= min) return events;
        }

        if (t) {
            clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
            uint64_t elapse = ((t1.tv_sec - t0.tv_sec) * 1000000000L)
                              + t1.tv_nsec - t0.tv_nsec;
            if (elapse > timeout) break;
        }
    }

    return events;
}

/*
 * The ->prep() function is called for each io_u prior to being submitted
 * with ->queue(). This hook allows the io engine to perform any
 * preparatory actions on the io_u, before being submitted. Not required.
 */
static int fio_nvmed_prep_aio(struct thread_data *td, struct io_u *io_u)
{
	FUNC_DEBUG();
	nvmed_io_thread_t *nvmed_io_handle = td->io_ops_data;
	nvmed_io_u_t *nvmed_iou = io_u->engine_data;
	NVMED_AIO_CTX *context = &nvmed_iou->context;

	context->handle = nvmed_io_handle->handle;
	context->start_lba = io_u->offset;
	context->len = io_u->xfer_buflen;
	context->buf = nvmed_iou->buf;
	context->aio_callback = nvmed_completion_cb;
	context->cb_userdata = (void *)io_u;

	return 0;
}
/*
 * The ->queue() hook is responsible for initiating io on the io_u
 * being passed in. If the io engine is a synchronous one, io may complete
 * before ->queue() returns. Required.
 *
 * The io engine must transfer in the direction noted by io_u->ddir
 * to the buffer pointed to by io_u->xfer_buf for as many bytes as
 * io_u->xfer_buflen. Residual data count may be set in io_u->resid
 * for a short read/write.
 */
static int fio_nvmed_queue(struct thread_data *td, struct io_u *io_u)
{
	int ret = 1;
    nvmed_io_u_t* nvmed_iou = io_u->engine_data;

    fio_ro_check(td, io_u);

    switch (io_u->ddir) {
    case DDIR_READ:
		ret = nvmed_aio_read(&nvmed_iou->context);
        TDEBUG("READ iou=%p lba=%ld %d", io_u, nvmed_iou->context.start_lba, ret);
        break;
    case DDIR_WRITE:
		ret = nvmed_aio_write(&nvmed_iou->context);
        TDEBUG("WRITE iou=%p lba=%ld %d", io_u, nvmed_iou->context.start_lba, ret);
        break;
    default:
        break;
    }

    /*
     * Could return FIO_Q_QUEUED for a queued request,
     * FIO_Q_COMPLETED for a completed request, and FIO_Q_BUSY
     * if we could queue no more at this point (you'd have to
     * define ->commit() to handle that.
     */
    return (ret==NVMED_AIO_QUEUED) ? FIO_Q_QUEUED : FIO_Q_COMPLETED;
}

/*
 * Hook for opening the given file. Unless the engine has special
 * needs, it usually just provides generic_file_open() as the handler.
 */
static int fio_nvmed_open(struct thread_data *td, struct fio_file *f)
{
    return 0;
}

/*
 * Hook for closing a file. See fio_nvmed_open().
 */
static int fio_nvmed_close(struct thread_data *td, struct fio_file *f)
{
    return 0;
}

/*
 * The ->io_u_init() function is called once for each queue depth entry
 * (numjobs x iodepth) prior to .init and after .get_file_size.
 * It is needed if io_u buffer needs to be remapped.
 */
static int fio_nvmed_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	FUNC_DEBUG();
	nvmed_io_u_t *nvmed_iou = calloc(1, sizeof(nvmed_io_u_t));
	unsigned int maxlen = 0;
	unsigned int num_pages;
	if(!nvmed_iou) return 1;

	maxlen = td_max_bs(td);
	num_pages = maxlen / PAGE_SIZE;
	nvmed_iou->buf = nvmed_get_buffer(nvmed.nvmed, num_pages);

	if(!nvmed_iou->buf) {
		free(nvmed_iou);
		return 1;
	}

	nvmed_iou->td = td;
	nvmed_iou->io_u = io_u;
	io_u->engine_data = nvmed_iou;
	
    return 0;
}

/*
 * The ->io_u_free() function is called once for each queue depth entry
 * (numjobs x iodepth) prior to .init and after .get_file_size.
 * It is needed if io_u buffer needs to be remapped.
 */
static void fio_nvmed_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	FUNC_DEBUG();
	nvmed_io_u_t *nvmed_iou = io_u->engine_data;

	if(nvmed_iou) {
		assert(nvmed_iou->io_u == io_u);
		nvmed_put_buffer(nvmed_iou->buf);
		free(nvmed_iou);
		io_u->engine_data = NULL;
	}
}

/*
 * The ->get_file_size() is called once for every job (i.e. numjobs)
 * before all other functions.  This is called after ->setup() but
 * is simpler to initialize here since we only care about the device name
 * (given as file_name) and just have to specify the device size.
 */
static int fio_nvmed_get_file_size(struct thread_data *td, struct fio_file *f)
{
	FUNC_DEBUG();
	pthread_mutex_lock(&nvmed.mutex);

	if(nvmed.nvmed == NULL) {
		nvmed.nvmed = nvmed_open((char*)f->file_name, 0);
		nvmed.dev_size = nvmed.nvmed->dev_info->capacity;
	}

	f->filetype = FIO_TYPE_CHAR;
	f->real_file_size = nvmed.dev_size;
	fio_file_set_size_known(f);

	pthread_mutex_unlock(&nvmed.mutex);

    return 0;
}

// Note that the structure is exported, so that fio can get it via
// dlsym(..., "ioengine");
struct ioengine_ops ioengine = {
    .name               = "nvmedirect",
    .version            = FIO_IOOPS_VERSION,
    .init               = fio_nvmed_init,
    .cleanup            = fio_nvmed_cleanup,
	.prep				= fio_nvmed_prep_aio,
    .queue              = fio_nvmed_queue,
    .getevents          = fio_nvmed_getevents,
    .event              = fio_nvmed_event,
    .io_u_init          = fio_nvmed_io_u_init,
    .io_u_free          = fio_nvmed_io_u_free,
    .open_file          = fio_nvmed_open,
    .close_file         = fio_nvmed_close,
    .get_file_size      = fio_nvmed_get_file_size,
    .flags              = FIO_NOEXTEND | FIO_RAWIO,
};

