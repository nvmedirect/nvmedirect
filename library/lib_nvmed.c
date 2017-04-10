/*
 * NVMeDirect Userspace Library
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

#include "../include/nvmed.h"
#include "../include/nvme_hdr.h"
#include "../include/lib_nvmed.h"
#include "../include/radix-tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>

#define nvmed_printf(fmt, args...) fprintf(stdout, fmt, ##args)
#define nvmed_err(fmt, args...) fprintf(stderr, fmt, ##args)

ssize_t nvmed_io_rw(NVMED_HANDLE* nvmed_handle, u8 opcode, void* buf, 
		unsigned long start_lba, unsigned int len, void* private);
ssize_t nvmed_cache_io_rw(NVMED_HANDLE* nvmed_handle, u8 opcode, NVMED_CACHE *__cache, 
		unsigned long start_lba, unsigned int len, int __flag);
ssize_t nvmed_buffer_read(NVMED_HANDLE* nvmed_handle, u8 opcode, void* buf, 
		unsigned long start_lba, unsigned int len, void* private);
ssize_t nvmed_buffer_write(NVMED_HANDLE* nvmed_handle, u8 opcode, void* buf, 
		unsigned long start_lba, unsigned int len, void* private);

/*
 * Translate virtual memory address to physical memory address
 */
int virt_to_phys(NVMED* nvmed, void* addr, u64* paArr, unsigned int num_bytes) {
	struct nvmed_buf nvmed_buf;
	unsigned int num_pages;
	int ret;

	num_pages = num_bytes / PAGE_SIZE;
	if(num_bytes % PAGE_SIZE > 0) num_pages++;

	nvmed_buf.addr = addr;
	nvmed_buf.size = num_pages;
	nvmed_buf.pfnList = paArr;
	
	ret = ioctl(nvmed->ns_fd, NVMED_IOCTL_GET_BUFFER_ADDR, &nvmed_buf);
	if(ret < 0) return 0;

	return num_pages;
}

/*
 * Allocation cache slot and memory
 */
int nvmed_cache_alloc(NVMED* nvmed, unsigned int size, bool lazy_init) {
	int i;
	unsigned int req_size;
	NVMED_CACHE_SLOT *slot;
	NVMED_CACHE *info;
	u64 *paList;

	pthread_spin_lock(&nvmed->mngt_lock);

	if(size == 0) return -NVMED_FAULT;
	if(size == nvmed->num_cache_size) return 0;
	if(size < nvmed->num_cache_size) {
		nvmed_printf("%s: Cache shrinking is not supported\n", nvmed->ns_path);
		return -NVMED_FAULT;
	}
	
	req_size = size - nvmed->num_cache_size;
	slot = malloc(sizeof(NVMED_CACHE_SLOT));
	
	slot->cache_info = malloc(sizeof(NVMED_CACHE) * req_size);
	slot->cache_ptr = mmap(NULL, PAGE_SIZE * req_size, PROT_READ | PROT_WRITE, 
			MAP_ANONYMOUS | MAP_LOCKED | MAP_SHARED, -1, 0);
	slot->size = req_size;
	LIST_INSERT_HEAD(&nvmed->slot_head, slot, slot_list);
	
	/* Initialize memory and translate virt to phys addr */
	if(!lazy_init) {
		paList = malloc(sizeof(u64) * req_size);
		virt_to_phys(nvmed, slot->cache_ptr, paList, PAGE_SIZE * req_size);
	}

	/* fill cache info and add to free list */
	for(i=0; i<req_size; i++) {
		info = slot->cache_info + i;
		info->lpaddr = 0;
		info->ref = 0;
		if(lazy_init == false) {
			info->paddr = paList[i];
			FLAG_SET(info, CACHE_FREE);
		}
		else {
			info->paddr = 0;
			FLAG_SET(info, CACHE_UNINIT | CACHE_FREE);
		}
		info->ptr = slot->cache_ptr + (i*PAGE_SIZE);

		TAILQ_INSERT_HEAD(&nvmed->free_head, info, cache_list);
	}
	
	nvmed->num_cache_size = size;

	pthread_spin_unlock(&nvmed->mngt_lock);

	return req_size;
}

/*
 * Get PRP Buffer of Handle 
 */
void* nvmed_handle_get_prp(NVMED_HANDLE* nvmed_handle, u64* pa) {
	void* ret_addr;
	int head;

	while(1) {
		pthread_spin_lock(&nvmed_handle->prpBuf_lock);
		if(nvmed_handle->prpBuf_curr != 0) {
			head = nvmed_handle->prpBuf_head;
			ret_addr = nvmed_handle->prpBuf[head];
			*pa = nvmed_handle->pa_prpBuf[head];
			if(++head == nvmed_handle->prpBuf_size) head = 0;
			nvmed_handle->prpBuf_curr--;
			pthread_spin_unlock(&nvmed_handle->prpBuf_lock);
			break;
		}
		pthread_spin_unlock(&nvmed_handle->prpBuf_lock);
	}

	return ret_addr;
}

/*
 * Put PRP Buffer of Handle
 */
int nvmed_handle_put_prp(NVMED_HANDLE* nvmed_handle, void* buf, u64 pa) {
	int tail;
	pthread_spin_lock(&nvmed_handle->prpBuf_lock);
	tail = nvmed_handle->prpBuf_tail;
	nvmed_handle->prpBuf[tail] = buf;
	nvmed_handle->pa_prpBuf[tail] = pa;
	if(++tail == nvmed_handle->prpBuf_size) tail = 0;
	nvmed_handle->prpBuf_curr++;
	pthread_spin_unlock(&nvmed_handle->prpBuf_lock);

	return 0;
}

/*
 * Complete IOD
 * (put PRP Buffer or AIO Callback
 */
void nvmed_complete_iod(NVMED_IOD* iod) {
	NVMED_HANDLE* nvmed_handle;
	NVMED_CACHE* cache;
	int i;

	nvmed_handle = iod->nvmed_handle;
	if(iod->prp_addr != NULL)
		nvmed_handle_put_prp(nvmed_handle, iod->prp_addr, iod->prp_pa);

	if(iod->context != NULL) { 
		iod->context->num_complete_io++;
		if(iod->context->num_init_io == iod->context->num_complete_io) {
			iod->context->status = AIO_COMPLETE;
			if(iod->context->aio_callback) {
				iod->context->aio_callback(iod->context, iod->context->cb_userdata);
				iod->context = NULL;
			}
		}
	}

	if(iod->num_cache != 0) {
		for(i=0; i<iod->num_cache; i++) {
			cache = iod->cache[i];
			FLAG_UNSET_SYNC(cache, CACHE_LOCKED | CACHE_DIRTY);
			FLAG_SET_SYNC(cache, CACHE_UPTODATE);
		}
	}

	iod->status = IO_COMPLETE;
}

/*
 * Polling specific Completion queue for AIO
 * return : number of completed I/O
 */
#define COMPLETE_QUEUE_MAX_PROC 32
int nvmed_queue_complete(NVMED_QUEUE* nvmed_queue) {
	NVMED* nvmed;
	NVMED_IOD* iod;
	volatile struct nvme_completion *cqe;
	u16 head, phase;
	int num_proc = 0;
	nvmed = nvmed_queue->nvmed;
	
	pthread_spin_lock(&nvmed_queue->cq_lock);
	head = nvmed_queue->cq_head;
	phase = nvmed_queue->cq_phase;
	for(;;) {
		cqe = (volatile struct nvme_completion *)&nvmed_queue->cqes[head];
		if((cqe->status & 1) != nvmed_queue->cq_phase)
			break;

		if(++head == nvmed->dev_info->q_depth) {
			head = 0;
			phase = !phase;
		}
		
		iod = nvmed_queue->iod_arr + cqe->command_id;
		nvmed_complete_iod(iod);
		num_proc++;
		if(head == 0 || num_proc == COMPLETE_QUEUE_MAX_PROC) break;
	}
	if(head == nvmed_queue->cq_head && phase == nvmed_queue->cq_phase) {
		pthread_spin_unlock(&nvmed_queue->cq_lock);
		return num_proc;
	}

	COMPILER_BARRIER();
	*(volatile u32 *)nvmed_queue->cq_db = head;
	nvmed_queue->cq_head = head;
	nvmed_queue->cq_phase = phase;
	pthread_spin_unlock(&nvmed_queue->cq_lock);

	return num_proc;
}

/*
 * I/O Completion of specific handle ( for AIO )
 */
int nvmed_aio_handle_complete(NVMED_HANDLE* nvmed_handle) {
	NVMED_QUEUE* nvmed_queue = HtoQ(nvmed_handle);

	return nvmed_queue_complete(nvmed_queue);
}

/*
 * I/O Completion of specific I/O
 * target_id : submission id
 */
void nvmed_io_polling(NVMED_HANDLE* nvmed_handle, u16 target_id) {
	NVMED* nvmed;
	NVMED_QUEUE* nvmed_queue;
	NVMED_IOD* iod;
	volatile struct nvme_completion *cqe;
	u16 head, phase;
	nvmed_queue = HtoQ(nvmed_handle);
	nvmed = HtoD(nvmed_handle);

	pthread_spin_lock(&nvmed_queue->cq_lock);
	while(1) {
		head = nvmed_queue->cq_head;
		phase = nvmed_queue->cq_phase;
		iod = nvmed_queue->iod_arr + target_id;
		if(iod->status == IO_COMPLETE) {
			break;
		}
		cqe = (volatile struct nvme_completion *)&nvmed_queue->cqes[head];
		for (;;) {
			if((cqe->status & 1) == nvmed_queue->cq_phase)
				break;
		}

		if(++head == nvmed->dev_info->q_depth) {
			head = 0;
			phase = !phase;
		}

		iod = nvmed_queue->iod_arr + cqe->command_id;
		nvmed_complete_iod(iod);

		COMPILER_BARRIER();
		*(volatile u32 *)nvmed_queue->cq_db = head;
		nvmed_queue->cq_head = head;
		nvmed_queue->cq_phase = phase;
	}
	pthread_spin_unlock(&nvmed_queue->cq_lock);
}

/*
 * Create I/O handle
 */
NVMED_HANDLE* nvmed_handle_create(NVMED_QUEUE* nvmed_queue, int flags) {
	NVMED_HANDLE* nvmed_handle;
	void* tempPtr;
	int i;

	pthread_spin_lock(&nvmed_queue->mngt_lock);

	nvmed_handle = malloc(sizeof(NVMED_HANDLE));
	nvmed_handle->queue = nvmed_queue;
	nvmed_handle->flags = flags;
	nvmed_handle->offset = 0;
	nvmed_handle->bufOffs = 0;

	/* PRP Buffer Create */
	nvmed_handle->prpBuf_size = NVMED_NUM_PREALLOC_PRP;
	nvmed_handle->prpBuf = malloc(sizeof(void *) * nvmed_handle->prpBuf_size);
	nvmed_handle->pa_prpBuf = malloc(sizeof(u64) * nvmed_handle->prpBuf_size);
	tempPtr = mmap(NULL, PAGE_SIZE * nvmed_handle->prpBuf_size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_LOCKED | MAP_SHARED, -1, 0);
	
	memset(tempPtr, 0, PAGE_SIZE * nvmed_handle->prpBuf_size);

	virt_to_phys(nvmed_queue->nvmed, tempPtr, nvmed_handle->pa_prpBuf, 
			PAGE_SIZE * nvmed_handle->prpBuf_size);

	for(i=0; i<nvmed_handle->prpBuf_size; i++) {
		nvmed_handle->prpBuf[i] = tempPtr + (PAGE_SIZE*i);
	}

	nvmed_handle->prpBuf_curr = nvmed_handle->prpBuf_size;
	nvmed_handle->prpBuf_head = 0;
	nvmed_handle->prpBuf_tail = 0;

	if(__FLAG_ISSET(flags, HANDLE_DIRECT_IO)) {
		nvmed_handle->read_func 	= nvmed_io_rw; 
		nvmed_handle->write_func	= nvmed_io_rw;
	}
	else {
		nvmed_handle->read_func 	= nvmed_buffer_read;
		nvmed_handle->write_func 	= nvmed_buffer_write;
	}

	nvmed_queue->numHandle++;

	pthread_spin_init(&nvmed_handle->prpBuf_lock, 0);

	pthread_spin_unlock(&nvmed_queue->mngt_lock);

	return nvmed_handle;
}

/*
 * Destroy I/O handle
 */
int nvmed_handle_destroy(NVMED_HANDLE* nvmed_handle) {
	NVMED_QUEUE* nvmed_queue;

	if(nvmed_handle == NULL) return -NVMED_NOENTRY;
	nvmed_queue = HtoQ(nvmed_handle);

	pthread_spin_lock(&nvmed_queue->mngt_lock);

	nvmed_queue->numHandle--;
	
	pthread_spin_destroy(&nvmed_handle->prpBuf_lock);

	munmap(nvmed_handle->prpBuf[0], PAGE_SIZE * nvmed_handle->prpBuf_size);
	free(nvmed_handle->pa_prpBuf);
	free(nvmed_handle);

	pthread_spin_unlock(&nvmed_queue->mngt_lock);

	return NVMED_SUCCESS;
}

/*
 * Create MQ Handle
 * (*func) should defined - callback function for pick I/O queue from MQ
 *							Argument - Handle, ops, offset, len
 */
NVMED_HANDLE* nvmed_handle_create_mq(NVMED_QUEUE** nvmed_queue, int num_mq, int flags,
		NVMED_QUEUE* (*func)(NVMED_HANDLE*, u8, unsigned long, unsigned int)) {
	NVMED_HANDLE* nvmed_handle;
	int i;

	if(func == NULL)
		return NULL;

	nvmed_handle = nvmed_handle_create(nvmed_queue[0], flags);
	if(nvmed_handle != NULL) {
		for(i=1; i<num_mq; i++) {
			pthread_spin_lock(&nvmed_queue[i]->mngt_lock);
			nvmed_queue[i]->numHandle++;
			pthread_spin_unlock(&nvmed_queue[i]->mngt_lock);
		}
		nvmed_handle->queue_mq = nvmed_queue;
		nvmed_handle->num_mq = num_mq;
		nvmed_handle->flags |= HANDLE_MQ;
		nvmed_handle->mq_get_queue = func;
	}
	else return NULL;

	return nvmed_handle;
}

/*
 * Destroy MQ Handle
 */
int nvmed_handle_destroy_mq(NVMED_HANDLE* nvmed_handle) {
	int i;

	if(nvmed_handle == NULL) return -NVMED_NOENTRY;
	if(!FLAG_ISSET(nvmed_handle, HANDLE_MQ)) {
		nvmed_printf("%s: failed to destroy MQ - not MQ\n",
				HtoD(nvmed_handle)->ns_path);

		return -NVMED_FAULT;
	}
	for(i=1; i<nvmed_handle->num_mq; i++) {
		pthread_spin_lock(&nvmed_handle->queue_mq[i]->mngt_lock);
		nvmed_handle->queue_mq[i]->numHandle--;
		pthread_spin_unlock(&nvmed_handle->queue_mq[i]->mngt_lock);
	}

	free(nvmed_handle->queue_mq);

	return nvmed_handle_destroy(nvmed_handle);
}

/*
 * Get Handle Features
 */
int nvmed_handle_feature_get(NVMED_HANDLE* nvmed_handle, int feature) {
	return FLAG_ISSET(nvmed_handle, feature);
}

/*
 * Set Handle Features
 */
int nvmed_handle_feature_set(NVMED_HANDLE* nvmed_handle, int feature, int value) {
	switch(feature) {
		case HANDLE_DIRECT_IO:
			if(value)
				FLAG_SET(nvmed_handle, HANDLE_DIRECT_IO);
			else
				FLAG_UNSET(nvmed_handle, HANDLE_DIRECT_IO);
			break;

		case HANDLE_SYNC_IO:
			if(value)
				FLAG_SET(nvmed_handle, HANDLE_SYNC_IO);
			else
				FLAG_UNSET(nvmed_handle, HANDLE_SYNC_IO);
			break;

		case HANDLE_HINT_DMEM:
			if(value)
				FLAG_SET(nvmed_handle, HANDLE_HINT_DMEM);
			else
				FLAG_UNSET(nvmed_handle, HANDLE_HINT_DMEM);
			break;
	}

	return value;
}

/*
 * Create User-space I/O queue and map to User virtual address
 */
NVMED_QUEUE* nvmed_queue_create(NVMED* nvmed, int flags) {
	int ret;
	NVMED_QUEUE* nvmed_queue;
	char pathBase[1024];
	char pathBuf[1024];
	u32 *q_dbs;
	u32	qid;

	pthread_spin_lock(&nvmed->mngt_lock);
	
	/* Request Create I/O Queues */
	ret = ioctl(nvmed->ns_fd, NVMED_IOCTL_QUEUE_CREATE, &qid);
	if(ret < 0) {
		nvmed_printf("%s: fail to create I/O queue\n", nvmed->ns_path);

		return NULL;
	}
	
	nvmed_queue = malloc(sizeof(NVMED_QUEUE));
	nvmed_queue->nvmed = nvmed;
	nvmed_queue->flags = flags;
	nvmed_queue->qid = qid;
	
	if(nvmed->dev_info->part_no != 0) {
		sprintf(pathBase, "/proc/nvmed/nvme%dn%dp%d/%d",
			nvmed->dev_info->instance, nvmed->dev_info->ns_id, nvmed->dev_info->part_no, nvmed_queue->qid);
	}
	else {
		sprintf(pathBase, "/proc/nvmed/nvme%dn%d/%d",
			nvmed->dev_info->instance, nvmed->dev_info->ns_id, nvmed_queue->qid);
	}

	/* Map SQ */
	sprintf(pathBuf, "%s/sq", pathBase);
	nvmed_queue->sq_fd = open(pathBuf, O_RDWR);
	nvmed_queue->sq_cmds = mmap(0, SQ_SIZE(nvmed->dev_info->q_depth), 
			PROT_READ | PROT_WRITE, MAP_SHARED, nvmed_queue->sq_fd, 0);

	/* Map CQ */
	sprintf(pathBuf, "%s/cq", pathBase);
	nvmed_queue->cq_fd = open(pathBuf, O_RDWR);
	nvmed_queue->cqes = mmap(0, CQ_SIZE(nvmed->dev_info->q_depth), 
			PROT_READ | PROT_WRITE, MAP_SHARED, nvmed_queue->cq_fd, 0);

	/* Map DQ */
	sprintf(pathBuf, "%s/db", pathBase);
	nvmed_queue->db_fd = open(pathBuf, O_RDWR);
	nvmed_queue->dbs = mmap(0, PAGE_SIZE*2, PROT_READ | PROT_WRITE, MAP_SHARED, nvmed_queue->db_fd, 0);

	q_dbs = nvmed_queue->dbs + PAGE_SIZE;
	nvmed_queue->sq_db = &q_dbs[nvmed_queue->qid * 2 * nvmed->dev_info->db_stride];
	nvmed_queue->cq_db = &q_dbs[(nvmed_queue->qid * 2 * nvmed->dev_info->db_stride) + nvmed->dev_info->db_stride];
	nvmed_queue->sq_head = 0;
	nvmed_queue->sq_tail = 0;
	nvmed_queue->cq_head = 0;
	nvmed_queue->cq_phase = 1;

	nvmed_queue->iod_arr = calloc(nvmed->dev_info->q_depth, sizeof(NVMED_IOD));
	nvmed_queue->iod_pos = 0;

	pthread_spin_init(&nvmed_queue->mngt_lock, 0);
	pthread_spin_init(&nvmed_queue->sq_lock, 0);
	pthread_spin_init(&nvmed_queue->cq_lock, 0);
	
	LIST_INSERT_HEAD(&nvmed->queue_head, nvmed_queue, queue_list);
	nvmed->numQueue++;

	nvmed_queue->numHandle = 0;

	pthread_spin_unlock(&nvmed->mngt_lock);

	return nvmed_queue;
}

/*
 * Destroy User-space I/O queue
 */
int nvmed_queue_destroy(NVMED_QUEUE* nvmed_queue) {
	NVMED* nvmed;
	int ret;
	
	if(nvmed_queue == NULL) return -NVMED_NOENTRY;
	if(nvmed_queue->numHandle) return -NVMED_FAULT;

	nvmed = nvmed_queue->nvmed;
	
	pthread_spin_lock(&nvmed->mngt_lock);
	
	if(nvmed->process_cq_status != TD_STATUS_STOP) {
		while(nvmed->process_cq_status == TD_STATUS_REQ_SUSPEND);
	
		if(nvmed->process_cq_status == TD_STATUS_RUNNING) {
			nvmed->process_cq_status = TD_STATUS_REQ_SUSPEND;
			while(nvmed->process_cq_status == TD_STATUS_REQ_SUSPEND);
		}
	}

	munmap(nvmed_queue->dbs, PAGE_SIZE * 2);
	close(nvmed_queue->db_fd);

	munmap((void *)nvmed_queue->cqes, CQ_SIZE(nvmed->dev_info->q_depth));
	close(nvmed_queue->cq_fd);

	munmap(nvmed_queue->sq_cmds, SQ_SIZE(nvmed->dev_info->q_depth));
	close(nvmed_queue->sq_fd);

	pthread_spin_destroy(&nvmed_queue->mngt_lock);
	pthread_spin_destroy(&nvmed_queue->sq_lock);
	pthread_spin_destroy(&nvmed_queue->cq_lock);
	
	ret = ioctl(nvmed->ns_fd, NVMED_IOCTL_QUEUE_DELETE, &nvmed_queue->qid);
	if(ret==0) {
		LIST_REMOVE(nvmed_queue, queue_list);
		pthread_mutex_lock(&nvmed->process_cq_mutex);
		pthread_cond_signal(&nvmed->process_cq_cond);
		pthread_mutex_unlock(&nvmed->process_cq_mutex);
		
		nvmed->numQueue--;
	}
	free(nvmed_queue);

	pthread_spin_unlock(&nvmed->mngt_lock);

	return NVMED_SUCCESS;
}

/*
 * Process CQ Thread
 */
void* nvmed_process_cq(void *data) {
	NVMED* nvmed = data;
	NVMED_QUEUE* nvmed_queue;

	while(1) {
		if(nvmed->process_cq_status == TD_STATUS_REQ_SUSPEND) {
			pthread_mutex_lock(&nvmed->process_cq_mutex);
			nvmed->process_cq_status = TD_STATUS_SUSPEND;
			pthread_cond_wait(&nvmed->process_cq_cond, &nvmed->process_cq_mutex);
			pthread_mutex_unlock(&nvmed->process_cq_mutex);
			nvmed->process_cq_status = TD_STATUS_RUNNING;

		}

		if(nvmed->process_cq_status == TD_STATUS_REQ_STOP) {
			break;
		}
		
		for (nvmed_queue = nvmed->queue_head.lh_first; 
				nvmed_queue != NULL; nvmed_queue = nvmed_queue->queue_list.le_next) {
			nvmed_queue_complete(nvmed_queue);
		}
	};

	nvmed->process_cq_status = TD_STATUS_STOP;

	pthread_exit((void *)NULL);
}

/*
 * Translate /dev/nvmeXnY -> /proc/nvmed/nvmeXnY/admin
 *							or /proc/nvmed/nvmeXnYpZ/admin
 */
int get_path_from_blkdev(char* blkdev, char** admin_path) {
	char temp_path[16];
	char *proc_path;
	int path_len;
	
	strcpy(temp_path, blkdev+9);
	path_len = 23;
	path_len+= strlen(temp_path);

	proc_path = malloc(sizeof(char) * path_len);
	sprintf(proc_path, "/proc/nvmed/nvme%s/admin", temp_path);

	if(access(proc_path, F_OK) < 0) {
		free(proc_path);
		return -NVMED_NOENTRY;
	}

	*admin_path = proc_path;
	return NVMED_SUCCESS;
}

/*
 * Open NVMe device
 */
NVMED* nvmed_open(char* path, int flags) {
	char* admin_path;
	int result;
	NVMED_DEVICE_INFO *dev_info;
	NVMED* nvmed;
	int fd;
	int devfd;
	int ret;
	unsigned int num_cache;

	if((devfd = open(path, O_RDWR)) < 0) {
		nvmed_err("%s: fail to open device file\n", path);
		return NULL;
	}

	result = get_path_from_blkdev(path, &admin_path);
	if(result < 0) {
		nvmed_printf("%s: fail to open nvme device file\n", path);
		return NULL;
	}
	
	fd = open(admin_path, 0);
	if(fd < 0) {
		nvmed_printf("%s: fail to open nvme device file\n", admin_path);
		return NULL;
	}

	//IOCTL - Get Device Info
	dev_info = malloc(sizeof(*dev_info));
	ret = ioctl(fd, NVMED_IOCTL_NVMED_INFO, dev_info);
	if(ret<0) {
		close(fd);
		
		return NULL;
	}

	//nvmed = malloc(sizeof(NVMED));
	nvmed = malloc(sizeof(*nvmed));
	if(nvmed==NULL) {
		free(admin_path);
		free(dev_info);
		close(fd);
		
		nvmed_printf("%s: fail to allocation nvmed buffer\n", admin_path);

		return NULL;
	}

	// Getting NVMe Device Info
	nvmed->ns_path = admin_path;
	nvmed->ns_fd = fd;
	nvmed->dev_fd = devfd;
	nvmed->dev_info = dev_info;
	nvmed->flags = flags;

	// QUEUE
	nvmed->numQueue = 0;
	LIST_INIT(&nvmed->queue_head);
	
	pthread_spin_init(&nvmed->mngt_lock, 0);

	// PROCESS_CQ THREAD
	nvmed->process_cq_status = TD_STATUS_STOP;

	pthread_cond_init(&nvmed->process_cq_cond, NULL);
	pthread_mutex_init(&nvmed->process_cq_mutex, NULL);
	//pthread_create(&nvmed->process_cq_td, NULL, &nvmed_process_cq, (void*)nvmed);

	if(!__FLAG_ISSET(flags, NVMED_NO_CACHE)) {
		// CACHE
		if((nvmed->dev_info->max_hw_sectors * 512) / PAGE_SIZE > NVMED_CACHE_INIT_NUM_PAGES)
			num_cache = (nvmed->dev_info->max_hw_sectors * 512) / PAGE_SIZE;
		else
			num_cache = NVMED_CACHE_INIT_NUM_PAGES;

		nvmed->num_cache_usage = 0;
	
		TAILQ_INIT(&nvmed->lru_head);
		TAILQ_INIT(&nvmed->free_head);
		pthread_rwlock_init(&nvmed->cache_radix_lock, 0);
		pthread_spin_init(&nvmed->cache_list_lock, 0);
	
		// CACHE - INIT
		LIST_INIT(&nvmed->slot_head);
		nvmed_cache_alloc(nvmed, num_cache, 
				__FLAG_ISSET(flags, NVMED_CACHE_LAZY_INIT));

		INIT_RADIX_TREE(&nvmed->cache_root);
		radix_tree_init();
	}

	return nvmed;
}

/*
 * Close NVMe device
 */
int nvmed_close(NVMED* nvmed) {
	NVMED_CACHE_SLOT* slot;
	void *status;

	if(nvmed==NULL || nvmed->ns_fd==0) return -NVMED_NOENTRY;
	if(nvmed->numQueue) return -NVMED_FAULT;

	close(nvmed->ns_fd);
	close(nvmed->dev_fd);

	free(nvmed->ns_path);

	//END PROCESS_CQ THREAD
	if(nvmed->process_cq_status != TD_STATUS_STOP) {
		if(nvmed->process_cq_status == TD_STATUS_RUNNING) {
			nvmed->process_cq_status = TD_STATUS_REQ_SUSPEND;
		}

		while(nvmed->process_cq_status == TD_STATUS_REQ_SUSPEND);

		if(nvmed->process_cq_status == TD_STATUS_SUSPEND) {
			pthread_mutex_lock(&nvmed->process_cq_mutex);
			pthread_cond_signal(&nvmed->process_cq_cond);
			pthread_mutex_unlock(&nvmed->process_cq_mutex);
		}

		while(nvmed->process_cq_status != TD_STATUS_RUNNING);
		nvmed->process_cq_status = TD_STATUS_REQ_STOP;
		pthread_join(nvmed->process_cq_td, (void **)&status);
	}
	//CACHE REMOVE
	while (nvmed->slot_head.lh_first != NULL) {
		slot = nvmed->slot_head.lh_first;
		free(slot->cache_info);
		munmap(slot->cache_ptr, PAGE_SIZE * slot->size);
		LIST_REMOVE(slot, slot_list);
	}

	pthread_spin_destroy(&nvmed->mngt_lock);

	free(nvmed);

	return NVMED_SUCCESS;
}

/*
 * Get NVMeD (NVMeDirect wide) features
 */
int nvmed_feature_get(NVMED* nvmed, int feature) {
	switch(feature) {
		case NVMED_CACHE_LAZY_INIT:
			return FLAG_ISSET(nvmed, NVMED_CACHE_LAZY_INIT);
			break;
		case NVMED_CACHE_SIZE:
			return nvmed->num_cache_size;
	};

	return 0;
}

/*
 * Set NVMeD (NVMeDirect wide) features
 */
int nvmed_feature_set(NVMED* nvmed, int feature, int value) {
	switch(feature) {
		case NVMED_CACHE_LAZY_INIT:
			FLAG_SET(nvmed, NVMED_CACHE_LAZY_INIT);
			break;
		case NVMED_CACHE_SIZE:
			return nvmed_cache_alloc(nvmed, value, 
					nvmed_feature_get(nvmed, NVMED_CACHE_LAZY_INIT));
	};

	return value;
}

/*
 * Send I/O to submission queue and ring SQ Doorbell
 */
ssize_t nvmed_io(NVMED_HANDLE* nvmed_handle, u8 opcode, 
		u64 prp1, u64 prp2, void* prp2_addr, NVMED_CACHE *__cache, 
		unsigned long start_lba, unsigned int len, int flags, NVMED_AIO_CTX* context) {
	NVMED_QUEUE* nvmed_queue;
	NVMED* nvmed;
	struct nvme_command *cmnd;
	NVMED_IOD* iod;
	u16	target_id;
	NVMED_CACHE *cache = NULL;
	int i, num_cache;

	nvmed_queue = HtoQ(nvmed_handle);
	nvmed = HtoD(nvmed_handle);

	pthread_spin_lock(&nvmed_queue->sq_lock);

	while(1) {
		target_id = nvmed_queue->iod_pos++;
		iod = nvmed_queue->iod_arr + target_id;
		if(nvmed_queue->iod_pos == nvmed->dev_info->q_depth)
			nvmed_queue->iod_pos = 0;
		if(iod->status != IO_INIT)
			break;
	}

	iod->sq_id = nvmed_queue->sq_tail;
	iod->prp_addr = prp2_addr;
	iod->prp_pa = prp2;
	iod->status = IO_INIT;
	iod->num_cache = 0;
	iod->cache = NULL;
	iod->nvmed_handle = nvmed_handle;
	iod->context = context;
	if(iod->context!=NULL) {
		iod->context->num_init_io++;
		iod->context->status = AIO_PROCESS;
	}

	if(__cache != NULL) {
		num_cache = len / PAGE_SIZE;
		cache = __cache;
		iod->cache = calloc(len / PAGE_SIZE, sizeof(NVMED_CACHE*));
		for(i=0; i<num_cache; i++) {
			iod->cache[i] = cache;
			cache = cache->cache_list.tqe_next;
		}
		iod->num_cache = num_cache;
	}

	cmnd = &nvmed_queue->sq_cmds[nvmed_queue->sq_tail];
	memset(cmnd, 0, sizeof(*cmnd));

	//remap start_lba
	start_lba += nvmed->dev_info->start_sect;

	switch(opcode) {
		case nvme_cmd_flush:
			cmnd->rw.opcode = nvme_cmd_flush;
			cmnd->rw.command_id = target_id;
			cmnd->rw.nsid = nvmed->dev_info->ns_id;
			
			break;

		case nvme_cmd_write:
		case nvme_cmd_read:
			cmnd->rw.opcode = opcode;
			cmnd->rw.command_id = target_id;
			cmnd->rw.nsid = nvmed->dev_info->ns_id;
			cmnd->rw.prp1 = prp1;
			cmnd->rw.prp2 = prp2;
			cmnd->rw.slba = start_lba >> nvmed->dev_info->lba_shift;
			cmnd->rw.length = (len >> nvmed->dev_info->lba_shift) - 1;
			cmnd->rw.control = 0;
			cmnd->rw.dsmgmt = 0;
			
			break;
		
		case nvme_cmd_dsm:
			cmnd->dsm.opcode = nvme_cmd_dsm;
			cmnd->dsm.command_id = target_id;
			cmnd->dsm.nsid = nvmed->dev_info->ns_id;
			cmnd->dsm.prp1 = prp1;
			cmnd->dsm.prp2 = 0;
			cmnd->dsm.nr = 0;
			cmnd->dsm.attributes = NVME_DSMGMT_AD;
			
			break;
	}

	if(++nvmed_queue->sq_tail == nvmed->dev_info->q_depth) 
		nvmed_queue->sq_tail = 0;

	COMPILER_BARRIER();
	*(volatile u32 *)nvmed_queue->sq_db = nvmed_queue->sq_tail;

	pthread_spin_unlock(&nvmed_queue->sq_lock);
	
	/* If Sync I/O => Polling */
	if(__FLAG_ISSET(flags, HANDLE_SYNC_IO)) {
		nvmed_io_polling(nvmed_handle, target_id);
	}

	return len;
}

/* Get CACHE from free list or evict */
NVMED_CACHE* nvmed_get_cache(NVMED_HANDLE* nvmed_handle) {
	NVMED* nvmed = HtoD(nvmed_handle);
	NVMED_CACHE *cache = nvmed->free_head.tqh_first;
	NVMED_CACHE *__cache;
	NVMED_CACHE *ret_cache;
	int i;
	unsigned int start_lpaddr, end_lpaddr;
	TAILQ_HEAD(cache_list, nvmed_cache) temp_head;

	pthread_rwlock_wrlock(&nvmed->cache_radix_lock);
	pthread_spin_lock(&nvmed->cache_list_lock);

	if(cache==NULL)  {
		//HEAD -> LRU, //TAIL -> MRU
		//EVICT - LRU
		cache = nvmed->lru_head.tqh_first;
		if(!FLAG_ISSET(cache, CACHE_DIRTY)) {
			TAILQ_REMOVE(&nvmed->lru_head, cache, cache_list);
			LIST_REMOVE(cache, handle_cache_list);
			radix_tree_delete(&nvmed->cache_root, cache->lpaddr);
			FLAG_SET_FORCE(cache, 0);
			ret_cache = cache;
		}
		else {
			TAILQ_INIT(&temp_head);
			
			while(FLAG_ISSET_SYNC(cache, CACHE_LOCKED) || cache->ref != 0) {
				usleep(1);
			}
			
			start_lpaddr = cache->lpaddr;
			end_lpaddr = cache->lpaddr;
			
			__cache = cache->cache_list.tqe_next;

			TAILQ_REMOVE(&nvmed->lru_head, cache, cache_list);
			radix_tree_delete(&nvmed->cache_root, cache->lpaddr);
			TAILQ_INSERT_HEAD(&temp_head, cache, cache_list);

			for(i=1; i<NVMED_CACHE_FORCE_EVICT_MAX; i++) {
				cache = __cache;
				if(FLAG_ISSET_SYNC(cache, CACHE_LOCKED)) break;
				if(!FLAG_ISSET(cache, CACHE_DIRTY)) break;
				if(start_lpaddr != 0 && cache->lpaddr == start_lpaddr-1 ) {
					//front_merge
					start_lpaddr--;
					__cache = cache->cache_list.tqe_next;
					TAILQ_REMOVE(&nvmed->lru_head, cache, cache_list);
					radix_tree_delete(&nvmed->cache_root, cache->lpaddr);
					TAILQ_INSERT_HEAD(&temp_head, cache, cache_list);

					continue;
				}
				else if(cache->lpaddr == end_lpaddr+1) {
					//back_merge
					end_lpaddr++;
					__cache = cache->cache_list.tqe_next;
					TAILQ_REMOVE(&nvmed->lru_head, cache, cache_list);
					radix_tree_delete(&nvmed->cache_root, cache->lpaddr);
					TAILQ_INSERT_TAIL(&temp_head, cache, cache_list);

					continue;
				}
				else {
					break;
				}
			}
			
			if(FLAG_ISSET(cache, CACHE_DIRTY))
			nvmed_cache_io_rw(nvmed_handle, nvme_cmd_write, temp_head.tqh_first, 
					start_lpaddr * PAGE_SIZE, (end_lpaddr - start_lpaddr) * PAGE_SIZE, 
					HANDLE_SYNC_IO);

			cache = temp_head.tqh_first;
			FLAG_SET_FORCE(cache, 0);
			ret_cache = cache;

			TAILQ_REMOVE(&temp_head, cache, cache_list);
			LIST_REMOVE(cache, handle_cache_list);

			while(temp_head.tqh_first != NULL) {
				TAILQ_REMOVE(&temp_head, temp_head.tqh_first, cache_list);
				TAILQ_INSERT_HEAD(&nvmed->free_head, temp_head.tqh_first, cache_list);
				nvmed->num_cache_usage--;
			}
		}
	}
	else {
		// Remove From Free Queue
		TAILQ_REMOVE(&nvmed->free_head, cache, cache_list);
		FLAG_UNSET_SYNC(cache, CACHE_FREE);
		if(FLAG_ISSET(cache, CACHE_UNINIT)) {
			memset(cache->ptr, 0, PAGE_SIZE);
			virt_to_phys(nvmed, cache->ptr, &cache->paddr, 4096);
			FLAG_UNSET_SYNC(cache, CACHE_UNINIT);
		}
		ret_cache = cache;
	}

	INIT_SYNC(ret_cache->ref);
	pthread_spin_unlock(&nvmed->cache_list_lock);
	pthread_rwlock_unlock(&nvmed->cache_radix_lock);

	return ret_cache;
}

unsigned int nvmed_check_buffer(void* nvmed_buf) {
	size_t buf_size;
	unsigned int predict_size, actual_size=0;
	unsigned int *magic;

	if(nvmed_buf == NULL) return 0;

	buf_size = malloc_usable_size(nvmed_buf);
	if(buf_size < PAGE_SIZE) return 0;

	predict_size = buf_size / PAGE_SIZE;
	if(predict_size >= 512)
		predict_size -= predict_size >> 9;

	magic = nvmed_buf + (PAGE_SIZE * predict_size);
	if(*magic == NVMED_BUF_MAGIC) {
		actual_size = *(++magic);
	}
	else {
		predict_size--;
		magic = nvmed_buf + (PAGE_SIZE * predict_size);
		if(*magic == NVMED_BUF_MAGIC) {
			actual_size = *(++magic);
		}
	}

	return actual_size;
}

/*
 *  Buffer Format
 *  [User Buf(4KB * num_pages)][MAGIC(4Bytes)][Num Pages(4Bytes)][PA LIST u64 * num_pages]
 */
void* nvmed_get_buffer(NVMED* nvmed, unsigned int num_pages) {
	struct nvmed_buf nvmed_buf;
	void *bufAddr;
	int ret;
	unsigned int *magic, *size;
	int req_size = (PAGE_SIZE * num_pages) + (sizeof(u64) * num_pages) + 8;
	
	if(num_pages == 0) return NULL;
	
	posix_memalign(&bufAddr, PAGE_SIZE, req_size);
	if(bufAddr == NULL) return NULL;
	mlock(bufAddr, PAGE_SIZE * req_size);

	memset(bufAddr, 0, req_size);

	nvmed_buf.addr = bufAddr;
	nvmed_buf.size = num_pages;
	nvmed_buf.pfnList = bufAddr + (PAGE_SIZE * num_pages) + 8;
	
	ret = ioctl(nvmed->ns_fd, NVMED_IOCTL_GET_BUFFER_ADDR, &nvmed_buf);

	if(ret < 0) {
		free(bufAddr);
		return NULL;
	}

	magic = bufAddr + (PAGE_SIZE * num_pages);
	*magic = NVMED_BUF_MAGIC;
	size = bufAddr + (PAGE_SIZE * num_pages)+4;
	*size = num_pages;
	
	return bufAddr;
}

void nvmed_put_buffer(void* nvmed_buf) {
	int buf_size, buf_len;
	buf_size = nvmed_check_buffer(nvmed_buf);
	buf_len = *(int *)(nvmed_buf + (PAGE_SIZE * buf_size) + 4);
	buf_len = (PAGE_SIZE * buf_len) + (sizeof(u64) * buf_len) + 8;

	munlock(nvmed_buf, buf_len);

	free(nvmed_buf);

	return;
}

/*
 * Make PRP List for Multiple page I/O from user buffer
 */
int make_prp_list(NVMED_HANDLE* nvmed_handle, void* buf, 
		unsigned long lba_offs, unsigned int io_size, u64* __paBase, 
		u64* prp1, u64* prp2, void** prp2_addr) {
	unsigned int startBufPos = lba_offs / PAGE_SIZE;
	unsigned int numBuf = io_size / PAGE_SIZE;
	unsigned int i;
	u64 *prpTmp;
	u64 *prpBuf;

	u64 *paBase = __paBase;
	u64 __prp1, __prp2;

	u64 paList[64];
	unsigned int bufOffs;

	*prp2_addr = NULL;

	if(io_size % PAGE_SIZE > 0) numBuf ++;

	if(paBase == NULL) {
		numBuf = virt_to_phys(HtoD(nvmed_handle), buf, paList, numBuf * PAGE_SIZE);
		bufOffs = (unsigned long)buf % PAGE_SIZE;
		__prp1 = paList[0] + bufOffs;
		if(numBuf == 1) {
			__prp2 = 0;
		}
		else if(numBuf == 2) {
			__prp2 = paList[1];
		}
		else {
			prpBuf = nvmed_handle_get_prp(nvmed_handle, &__prp2);
			*prp2_addr = prpBuf;
			for(i = 1; i < numBuf; i++) {
				prpBuf[i-1] = paList[i];
			}
		}
	}
	else {
		paBase += startBufPos;
		prpTmp = paBase;
		__prp1 = *prpTmp;
		if(numBuf == 1) {
			__prp2 = 0;
		}
		else if(numBuf == 2) {
			__prp2 = *(prpTmp+1);
		}
		else {
			prpBuf = nvmed_handle_get_prp(nvmed_handle, &__prp2);
			*prp2_addr = prpBuf;
			for(i = 1; i < numBuf; i++) {
				prpBuf[i-1] = paBase[i];
			}
		}

	}
	*prp1 = __prp1;
	*prp2 = __prp2;

	return 0;
}

/*
 * Make PRP List for Multiple page I/O from NVMeDirect Cache
 */
int make_prp_list_from_cache(NVMED_HANDLE* nvmed_handle, NVMED_CACHE *__cache, 
		int num_list, u64* prp1, u64* prp2, void** prp2_addr) {
	NVMED_CACHE *cache;
	u64 *prpBuf;
	u64 __prp1, __prp2 = 0;
	int i;

	*prp2_addr = NULL;

	cache = __cache;
	__prp1 = cache->paddr;
	if(num_list == 2) {
		cache = cache->cache_list.tqe_next;
		__prp2 = cache->paddr;
	}
	else {
		prpBuf = nvmed_handle_get_prp(nvmed_handle, &__prp2);
		*prp2_addr = prpBuf;
		for(i=1; i<num_list; i++) {
			cache = cache->cache_list.tqe_next;
			prpBuf[i-1] = cache->paddr;
		}
	}

	*prp1 = __prp1;
	*prp2 = __prp2;

	return 0;
}

/*
 * Make I/O request from NVMeDirect Cache
 */
ssize_t nvmed_cache_io_rw(NVMED_HANDLE* nvmed_handle, u8 opcode, NVMED_CACHE *__cache, 
		unsigned long start_lba, unsigned int len, int __flag) {
	NVMED_QUEUE* nvmed_queue;
	NVMED* nvmed;
	NVMED_CACHE* cache;
	int num_cache;
	int flag;
	ssize_t remain = 0;
	ssize_t io_size, io = 0, total_io = 0;
	unsigned long io_lba;

	u64 prp1, prp2;
	void* prp2_addr;

	if(len % PAGE_SIZE) return 0;

	if(__flag != 0) flag = __flag;
	else flag = nvmed_handle->flags;

	if(FLAG_ISSET(nvmed_handle, HANDLE_MQ)) {
		nvmed_queue = nvmed_handle->mq_get_queue(nvmed_handle, opcode, 
				start_lba, len);

		if(nvmed_queue == NULL)
			return 0;
	}
	else {
		nvmed_queue = HtoQ(nvmed_handle);
	}
	nvmed = nvmed_queue->nvmed;
	
	remain = len;
	cache = __cache;

	num_cache = len / PAGE_SIZE;
	while(num_cache-- > 0) {
		FLAG_SET_SYNC(cache, CACHE_LOCKED);
		cache = cache->cache_list.tqe_next;
	}

	cache = __cache;
	while(remain > 0) {
		if(remain > nvmed->dev_info->max_hw_sectors * 512 )
			io_size = nvmed->dev_info->max_hw_sectors * 512;
		else
			io_size = remain;

		io_lba = total_io + start_lba;

		num_cache = io_size / PAGE_SIZE;

		make_prp_list_from_cache(nvmed_handle, cache, num_cache, &prp1, &prp2, &prp2_addr);
		io = nvmed_io(nvmed_handle, opcode, prp1, prp2, prp2_addr, cache, 
				io_lba, io_size, flag, NULL);
		
		if(io <= 0) break;
		
		remain -= io;
		total_io += io;
		io_lba += io;

		while(num_cache-- > 0)
			cache = cache->cache_list.tqe_next;
	}
	
	return total_io;
}

bool nvmed_rw_verify_area(NVMED_HANDLE* nvmed_handle, 
		unsigned long __start_lba, unsigned int len) {
	NVMED *nvmed = HtoD(nvmed_handle);
	NVMED_DEVICE_INFO *dev_info = nvmed->dev_info;
	unsigned long start_lba = nvmed->dev_info->start_sect + __start_lba;

	if(start_lba < dev_info->start_sect)
		return false;

	if((dev_info->start_sect + dev_info->nr_sects) < start_lba)
		return false;

	if((dev_info->start_sect + dev_info->nr_sects)
			< (start_lba + len))
		return false;

	return true;
}

/*
 * Make I/O request from User memory
 */
ssize_t nvmed_io_rw(NVMED_HANDLE* nvmed_handle, u8 opcode, void* buf, 
		unsigned long start_lba, unsigned int len, void* private) {
	NVMED_AIO_CTX* context = private;
	NVMED_QUEUE* nvmed_queue;
	NVMED* nvmed;

	unsigned long io_lba;
	unsigned int io_size;
	ssize_t remain = 0;
	ssize_t io = 0, total_io = 0;
	unsigned int nvmed_buf_size = 0;
	u64* paBase = NULL;
	u64 prp1, prp2;
	void* next_buf = buf;
	void* prp2_addr;

	// DIRECT - No copy - must do sync
	// Buffered - Copy to buffer
	//  - Using page cache
	// Sync - Polling
	// Async - return wo/poll
	
	if(len % 512) return 0;

	if(!nvmed_rw_verify_area(nvmed_handle, start_lba, len))
		return -1;

	if(FLAG_ISSET(nvmed_handle, HANDLE_MQ)) {
		nvmed_queue = nvmed_handle->mq_get_queue(nvmed_handle, opcode, 
				start_lba, len);

		if(nvmed_queue == NULL)
			return 0;
	}
	else {
		nvmed_queue = HtoQ(nvmed_handle);
	}
	nvmed = nvmed_queue->nvmed;

	remain = len;
	if(FLAG_ISSET(nvmed_handle, HANDLE_HINT_DMEM)) {
		nvmed_buf_size = nvmed_check_buffer(buf);
		paBase = buf + (PAGE_SIZE * nvmed_buf_size) + 8;
	}
	if(context != NULL && context->prpList != NULL)
		paBase = context->prpList;

	// if Buf aligned -> Fn ==> non-cp fn
	// Not aligned -> Fn ==> mem_cp fn
	while(remain > 0) {
		if(remain > nvmed->dev_info->max_hw_sectors * 512 )
			io_size = nvmed->dev_info->max_hw_sectors * 512;
		else
			io_size = remain;
		io_lba = total_io + start_lba;
		make_prp_list(nvmed_handle, next_buf, total_io , io_size, 
					paBase, &prp1, &prp2, &prp2_addr);
		io = nvmed_io(nvmed_handle, opcode, prp1, prp2, prp2_addr, NULL, 
				io_lba, io_size, nvmed_handle->flags, context);
		
		if(io <= 0) break;

		remain -= io;
		total_io += io;
		io_lba += io;
		nvmed_handle->offset += io;
		next_buf += io;
	}

	return total_io;
}

off_t nvmed_lseek(NVMED_HANDLE* nvmed_handle, off_t offset, int whence) {
	int ret = -1;

	if(whence == SEEK_SET) {
		if(offset < HtoD(nvmed_handle)->dev_info->capacity) {
			nvmed_handle->offset = offset;
			ret = nvmed_handle->offset;
		}
		else 
			ret = -1;
	}
	else if(whence == SEEK_CUR) {
		if(offset + nvmed_handle->offset < HtoD(nvmed_handle)->dev_info->capacity) {
			nvmed_handle->offset += offset;
			ret = nvmed_handle->offset;
		}
		else
			ret = -1;
	}
	else if(whence == SEEK_END) {
		if(offset <= HtoD(nvmed_handle)->dev_info->capacity) {
			nvmed_handle->offset = HtoD(nvmed_handle)->dev_info->capacity - offset;
			ret = nvmed_handle->offset;
		}
		else
			ret = -1;
	}

	return ret;
}

int nvmed_aio_queue_submit(NVMED_HANDLE* handle) {
	NVMED_QUEUE* nvmed_queue;
	int num_submit = 0;

	nvmed_queue = HtoQ(handle);

	num_submit = nvmed_queue->aio_q_head;
	nvmed_queue->aio_q_head = 0;

	return num_submit;
}

int nvmed_aio_enqueue(NVMED_AIO_CTX* context) {
	NVMED_HANDLE *handle = context->handle;
	NVMED_QUEUE *queue = HtoQ(handle);

	if(!nvmed_rw_verify_area(handle, context->start_lba, context->len))
		return NVMED_AIO_ERROR;

	queue->aio_q_head++;
	context->status = AIO_INIT;
	context->num_init_io = 0;
	context->num_complete_io = 0;

	nvmed_io_rw(context->handle, context->opcode,
				context->buf, context->start_lba, context->len, context);

	return NVMED_AIO_QUEUED;
}


int nvmed_aio_read(NVMED_AIO_CTX* context) {
	context->opcode = nvme_cmd_read;
	return nvmed_aio_enqueue(context);
}

int nvmed_aio_write(NVMED_AIO_CTX* context) {
	context->opcode = nvme_cmd_write;
	return nvmed_aio_enqueue(context);
}

ssize_t nvmed_buffer_read(NVMED_HANDLE* nvmed_handle, u8 opcode, void* buf, 
		unsigned long start_lba, unsigned int len, void* private) {
	NVMED_QUEUE *nvmed_queue = HtoQ(nvmed_handle);
	NVMED *nvmed = nvmed_queue->nvmed;
	NVMED_CACHE **cacheP, *cache, *__cache;
	NVMED_CACHE **cacheTarget;
	ssize_t total_read = 0;
	unsigned long start_block, end_block, io_blocks;
	unsigned int  find_blocks, final_num_blocks;
	unsigned long	io_start, io_nums = 0;
	int i = 0, block_idx;
	int cache_idx = 0;
	unsigned int buf_offs, buf_copy_size, cache_offs;
	TAILQ_HEAD(cache_list, nvmed_cache) temp_head;

	if(!nvmed_rw_verify_area(nvmed_handle, start_lba, len))
		return -1;

	start_block = start_lba / PAGE_SIZE;
	end_block = (start_lba + len - 1) / PAGE_SIZE;
	io_blocks = end_block - start_block + 1;

	cacheP = calloc(io_blocks, sizeof(NVMED_CACHE*));

	pthread_rwlock_rdlock(&nvmed->cache_radix_lock);
	find_blocks = radix_tree_gang_lookup(&nvmed->cache_root, 
			(void **)cacheP, start_block, io_blocks);
	pthread_rwlock_unlock(&nvmed->cache_radix_lock);

	TAILQ_INIT(&temp_head);

	if(find_blocks > 0) {
		cache = *(cacheP + 0);
		if(cache->lpaddr > end_block)
			find_blocks = 0;
		else {
			final_num_blocks = 0;
			for(i=0; i<find_blocks; i++) {
				cache = *(cacheP + i);
				if(cache->lpaddr >= start_block && end_block <= cache->lpaddr)
					final_num_blocks++;
			}
			find_blocks = final_num_blocks;
		}
	}

	if(find_blocks == 0) {
		//read all
		for(i=0; i<io_blocks; i++) {
			cache = nvmed_get_cache(nvmed_handle);
			TAILQ_INSERT_TAIL(&temp_head, cache, cache_list);
		}
		nvmed_cache_io_rw(nvmed_handle, nvme_cmd_read, temp_head.tqh_first, 
				start_block * PAGE_SIZE, io_blocks * PAGE_SIZE, HANDLE_SYNC_IO);

		cache_idx = 0;
		while(temp_head.tqh_first != NULL) {
			cache = temp_head.tqh_first;

			TAILQ_REMOVE(&temp_head, cache, cache_list);

			cache->lpaddr = start_block + cache_idx;
			FLAG_SET_SYNC(cache, CACHE_LRU | CACHE_UPTODATE);

			if(cache_idx==0) {
				cache_offs = start_lba % PAGE_SIZE;
				if(cache_offs + len <= PAGE_SIZE) {
					buf_copy_size  = len;
				}
				else {
					buf_copy_size = PAGE_SIZE - cache_offs;
				}
				memcpy(buf, cache->ptr + cache_offs, buf_copy_size);
				buf_offs = buf_copy_size;
			}
			else if(cache_idx == io_blocks -1) {
				buf_copy_size = len - buf_offs;
				memcpy(buf + buf_offs, cache->ptr, buf_copy_size);
			}
			else {
				buf_copy_size = PAGE_SIZE;
				memcpy(buf + buf_offs, cache->ptr, buf_copy_size);
				buf_offs+= PAGE_SIZE;
			}
			
			DEC_SYNC(cache->ref);

			pthread_rwlock_wrlock(&nvmed->cache_radix_lock);
			pthread_spin_lock(&nvmed->cache_list_lock);
			TAILQ_INSERT_TAIL(&nvmed->lru_head, cache, cache_list);
			radix_tree_insert(&nvmed->cache_root, cache->lpaddr, cache);
			pthread_spin_unlock(&nvmed->cache_list_lock);
			pthread_rwlock_unlock(&nvmed->cache_radix_lock);

			INIT_SYNC(cache->ref);
			nvmed->num_cache_usage++;
			cache_idx++;
		}
	}
	else {
		//find empty block
		if(find_blocks != io_blocks) {
			//Find Hole?

			cacheTarget = malloc(sizeof(NVMED_CACHE*) * io_blocks);
			
			io_nums = 0;
			io_start = 0;

			i=0;
			for(block_idx = start_block; block_idx <= end_block; block_idx++) {
				cache = *(cacheP + i);
				if(cache != NULL && cache->lpaddr == block_idx) {

					if(io_nums != 0) {
						nvmed_cache_io_rw(nvmed_handle, nvme_cmd_read, temp_head.tqh_first, 
							io_start * PAGE_SIZE, io_nums * PAGE_SIZE, HANDLE_SYNC_IO);
						
						pthread_rwlock_wrlock(&nvmed->cache_radix_lock);
						pthread_spin_lock(&nvmed->cache_list_lock);

						while(temp_head.tqh_first != NULL) {
							__cache = temp_head.tqh_first;
							TAILQ_REMOVE(&temp_head, __cache, cache_list);
							TAILQ_INSERT_TAIL(&nvmed->lru_head, __cache, cache_list);
							radix_tree_insert(&nvmed->cache_root, __cache->lpaddr, __cache);
							FLAG_SET_SYNC(__cache, CACHE_LRU);
						}

						pthread_spin_unlock(&nvmed->cache_list_lock);
						pthread_rwlock_unlock(&nvmed->cache_radix_lock);

						io_nums = 0;
					}
					else
						INC_SYNC(cache->ref);

					i++;

					cacheTarget[block_idx-start_block] = cache;
					pthread_spin_lock(&nvmed->cache_list_lock);
					TAILQ_REMOVE(&nvmed->lru_head, cache, cache_list);
					TAILQ_INSERT_TAIL(&nvmed->lru_head,cache, cache_list);
					pthread_spin_unlock(&nvmed->cache_list_lock);
				}
				else {

					cache = nvmed_get_cache(nvmed_handle);
					cache->lpaddr = block_idx;
					TAILQ_INSERT_TAIL(&temp_head, cache, cache_list);
					io_nums++;
					if(io_nums == 1) io_start = cache->lpaddr;

					nvmed->num_cache_usage++;

					cacheTarget[block_idx-start_block] = cache;
				}
			}

			for(i=0; i<io_blocks; i++)
				*(cacheP + i) = cacheTarget[i];

			free(cacheTarget);
		}

		if(io_nums != 0) {
			nvmed_cache_io_rw(nvmed_handle, nvme_cmd_read, temp_head.tqh_first, 
					io_start * PAGE_SIZE, io_nums * PAGE_SIZE, HANDLE_SYNC_IO);

			pthread_rwlock_wrlock(&nvmed->cache_radix_lock);
			pthread_spin_lock(&nvmed->cache_list_lock);

			while(temp_head.tqh_first != NULL) {
				__cache = temp_head.tqh_first;
				TAILQ_REMOVE(&temp_head, __cache, cache_list);
				TAILQ_INSERT_TAIL(&nvmed->lru_head, __cache, cache_list);
				radix_tree_insert(&nvmed->cache_root, __cache->lpaddr, __cache);
				FLAG_SET_SYNC(__cache, CACHE_LRU);
			}

			pthread_spin_unlock(&nvmed->cache_list_lock);
			pthread_rwlock_unlock(&nvmed->cache_radix_lock);
		}

		for(cache_idx=0; cache_idx<io_blocks; cache_idx++) {
			cache = *(cacheP + cache_idx);

			if(cache_idx==0) {
				cache_offs = start_lba % PAGE_SIZE;
				if(cache_offs + len <= PAGE_SIZE) {
					buf_copy_size  = len;
				}
				else {
					buf_copy_size = PAGE_SIZE - cache_offs;
				}
				memcpy(buf, cache->ptr + cache_offs, buf_copy_size);
				buf_offs = buf_copy_size;
			}
			else if(cache_idx == io_blocks -1) {
				buf_copy_size = len - buf_offs;
				memcpy(buf + buf_offs, cache->ptr, buf_copy_size);
			}
			else {
				buf_copy_size = PAGE_SIZE;
				memcpy(buf + buf_offs, cache->ptr, buf_copy_size);
				buf_offs+= PAGE_SIZE;
			}

		}
	}

	total_read = len;

	free(cacheP);

	nvmed_handle->offset += total_read;

	return total_read;
}

ssize_t nvmed_buffer_write(NVMED_HANDLE* nvmed_handle, u8 opcode, void* buf, 
		unsigned long start_lba, unsigned int len, void* private) {
	NVMED *nvmed = HtoD(nvmed_handle);
	NVMED_CACHE **cacheP, *cache;
	ssize_t total_write = 0;
	unsigned long start_block, end_block, io_blocks;
	unsigned int buf_offs, buf_copy_size, cache_offs;
	unsigned int  find_blocks;
	int block_idx=0, cache_idx=0;
	bool found_from_cache;
	TAILQ_HEAD(cache_list, nvmed_cache) temp_head;

	if(!nvmed_rw_verify_area(nvmed_handle, start_lba, len))
		return -1;

	start_block = start_lba / PAGE_SIZE;
	end_block = (start_lba + len - 1) / PAGE_SIZE;
	io_blocks = end_block - start_block + 1;

	cacheP = calloc(io_blocks, sizeof(NVMED_CACHE*));

	pthread_rwlock_rdlock(&nvmed->cache_radix_lock);
	find_blocks = radix_tree_gang_lookup(&nvmed->cache_root, 
			(void **)cacheP, start_block, io_blocks);
	pthread_rwlock_unlock(&nvmed->cache_radix_lock);
	
	TAILQ_INIT(&temp_head);

	if(nvmed->process_cq_status == TD_STATUS_STOP) {
		nvmed->process_cq_status = TD_STATUS_REQ_SUSPEND;
		pthread_create(&nvmed->process_cq_td, NULL, &nvmed_process_cq, (void*)nvmed);
	}

	//find all in cache?
	if(find_blocks == io_blocks) {
		for(cache_idx=0; cache_idx<find_blocks; cache_idx++) {
			cache = *(cacheP + cache_idx);

			while(FLAG_ISSET_SYNC(cache, CACHE_LOCKED)) usleep(1);

			if(cache_idx==0) {
				cache_offs = start_lba % PAGE_SIZE;
				if(cache_offs + len <= PAGE_SIZE) {
					buf_copy_size  = len;
				}
				else {
					buf_copy_size = PAGE_SIZE - cache_offs;
				}
				memcpy(cache->ptr + cache_offs, buf, buf_copy_size);
				buf_offs = buf_copy_size;
			}
			else if(cache_idx == io_blocks -1) {
				buf_copy_size = len - buf_offs;
				memcpy(cache->ptr, buf, buf_copy_size);
			}
			else {
				buf_copy_size = PAGE_SIZE;
				memcpy(cache->ptr, buf, buf_copy_size);
				buf_offs+= PAGE_SIZE;
			}

			FLAG_SET_SYNC(cache, CACHE_DIRTY);

			pthread_spin_lock(&nvmed->cache_list_lock);
			TAILQ_REMOVE(&nvmed->lru_head, cache, cache_list);
			pthread_spin_unlock(&nvmed->cache_list_lock);
			
			TAILQ_INSERT_TAIL(&temp_head, cache, cache_list);
		}
	}
	else {
		// partial write block ?
		// fill
		cache_idx=0;
		for(block_idx = start_block; block_idx <= end_block; block_idx++) {
			cache = *(cacheP + cache_idx);
			found_from_cache = false;
			if(cache != NULL &&cache->lpaddr == block_idx) {
				found_from_cache = true;
				TAILQ_REMOVE(&nvmed->lru_head, cache, cache_list);
			}
			else {
				cache = nvmed_get_cache(nvmed_handle);
				cache->lpaddr = block_idx;
				nvmed->num_cache_usage++;
			}
			
			if(found_from_cache)
				while(FLAG_ISSET_SYNC(cache, CACHE_LOCKED)) usleep(1);
			
			if(cache_idx==0) {
				cache_offs = start_lba % PAGE_SIZE;
				if(cache_offs + len <= PAGE_SIZE) {
					buf_copy_size  = len;
				}
				else {
					buf_copy_size = PAGE_SIZE - cache_offs;
				}
				
				if(!found_from_cache && buf_copy_size != PAGE_SIZE) {
					nvmed_cache_io_rw(nvmed_handle, nvme_cmd_read, cache, \
						cache->lpaddr * PAGE_SIZE, PAGE_SIZE, HANDLE_SYNC_IO);
				}
				memcpy(cache->ptr + cache_offs, buf, buf_copy_size);
				buf_offs = buf_copy_size;
			}
			else if(cache_idx == io_blocks -1) {
				buf_copy_size = len - buf_offs;

				if(!found_from_cache && buf_copy_size != PAGE_SIZE) {
					nvmed_cache_io_rw(nvmed_handle, nvme_cmd_read, cache, \
						cache->lpaddr * PAGE_SIZE, PAGE_SIZE, HANDLE_SYNC_IO);
				}

				memcpy(cache->ptr, buf, buf_copy_size);
			}
			else {
				buf_copy_size = PAGE_SIZE;
				memcpy(cache->ptr, buf, buf_copy_size);
				buf_offs+= PAGE_SIZE;
			}
			
			if(!found_from_cache) {
				pthread_rwlock_wrlock(&nvmed->cache_radix_lock);
				radix_tree_insert(&nvmed->cache_root, cache->lpaddr, cache);
				pthread_rwlock_unlock(&nvmed->cache_radix_lock);
			}
			else {
				cache_idx++;
			}

			FLAG_SET_SYNC(cache, CACHE_DIRTY);
		
			TAILQ_INSERT_TAIL(&temp_head, cache, cache_list);
		}
	}

	if(nvmed->process_cq_status == TD_STATUS_SUSPEND) {
		pthread_mutex_lock(&nvmed->process_cq_mutex);
		pthread_cond_signal(&nvmed->process_cq_cond);
		pthread_mutex_unlock(&nvmed->process_cq_mutex);
	}

	nvmed_cache_io_rw(nvmed_handle, nvme_cmd_write, temp_head.tqh_first, \
			start_block * PAGE_SIZE, io_blocks * PAGE_SIZE, nvmed_handle->flags);
	
	while(temp_head.tqh_first != NULL) {
		cache = temp_head.tqh_first;
		TAILQ_REMOVE(&temp_head, cache, cache_list);
	
		pthread_spin_lock(&nvmed->cache_list_lock);
		TAILQ_INSERT_TAIL(&nvmed->lru_head, cache, cache_list);
		LIST_INSERT_HEAD(&nvmed_handle->dirty_list, cache, handle_cache_list);
		pthread_spin_unlock(&nvmed->cache_list_lock);
	}

	total_write = len;

	nvmed_handle->offset += total_write;

	free(cacheP);

	return total_write;
}


//offset, length -> should be 512B Aligned
ssize_t nvmed_read(NVMED_HANDLE* nvmed_handle, void* buf, size_t count) {
	ssize_t ret;
	
	ret = nvmed_handle->read_func(nvmed_handle, nvme_cmd_read, 
			buf, nvmed_handle->offset, count, NULL);

	return ret;
}

//offset, length -> should be 512B Aligned
ssize_t nvmed_write(NVMED_HANDLE* nvmed_handle, void* buf, size_t count) {
	ssize_t ret;
	
	ret = nvmed_handle->write_func(nvmed_handle, nvme_cmd_write, 
			buf, nvmed_handle->offset, count, NULL);

	return ret;
}

void nvmed_flush_handle(NVMED_HANDLE* nvmed_handle) {
	NVMED_CACHE *cache;

	while (nvmed_handle->dirty_list.lh_first != NULL) {
		cache = nvmed_handle->dirty_list.lh_first;
		nvmed_cache_io_rw(nvmed_handle, nvme_cmd_write, cache, 
				cache->lpaddr * PAGE_SIZE, PAGE_SIZE, HANDLE_SYNC_IO);
		LIST_REMOVE(cache, handle_cache_list);
	}
}

int nvmed_flush(NVMED_HANDLE* nvmed_handle) {
	nvmed_flush_handle(nvmed_handle);
	if(HtoD(nvmed_handle)->dev_info->vwc != 0) 
		nvmed_io(nvmed_handle, nvme_cmd_flush, 0, 0, 0, NULL, 0, 0, HANDLE_SYNC_IO, NULL);

	return 0;
}

int nvmed_discard(NVMED_HANDLE* nvmed_handle, unsigned long start, unsigned int len) {
	struct nvme_dsm_range *range;
	u64 __prp;

	if(start % 512 || len % 512) return -NVMED_FAULT;
	
	range = nvmed_handle_get_prp(nvmed_handle, &__prp);

	range->cattr = 0;
	range->nlb = 0;
	range->slba = 0;//start

	nvmed_io(nvmed_handle, nvme_cmd_dsm, __prp, 0, 0, NULL, 0, 0, HANDLE_SYNC_IO, NULL);

	return 0;
}

/* 
 * (for nvmed_admin tools) Set NVMeDirect Queue Permission
 */
int nvmed_set_user_quota(NVMED* nvmed, uid_t uid, unsigned int num_queue,
		unsigned int* max_queue, unsigned int* current_queue) {
	NVMED_USER_QUOTA quota;
	int ret;

	quota.uid = uid;
	quota.queue_max = num_queue;

	ret = ioctl(nvmed->ns_fd, NVMED_IOCTL_SET_USER, &quota);
	if(ret < 0) return ret;

	if(max_queue != NULL) *max_queue = quota.queue_max;
	if(current_queue != NULL) *current_queue = quota.queue_used;

	return NVMED_SUCCESS;
}

/* 
 * (for nvmed_admin tools) Get NVMeDirect Queue Permission
 */
int nvmed_get_user_quota(NVMED* nvmed, uid_t uid,
		unsigned int* max_queue, unsigned int* current_queue) {
	NVMED_USER_QUOTA quota;
	int ret;

	quota.uid = uid;

	ret = ioctl(nvmed->ns_fd, NVMED_IOCTL_GET_USER, &quota);
	if(ret < 0) return ret;

	if(max_queue != NULL) *max_queue = quota.queue_max;
	if(current_queue != NULL) *current_queue = quota.queue_used;

	return NVMED_SUCCESS;
}

