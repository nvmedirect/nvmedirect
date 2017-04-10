/*
 * NVMeDirect Device Driver
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

#ifndef _NVMED_H
#define _NVMED_H

#include <linux/types.h>

#ifndef MODULE
#include <sys/types.h>
#endif

#define NVMED_IOCTL_NVMED_INFO		_IOW('N', 0x50, struct nvmed_device_info)
#define NVMED_IOCTL_QUEUE_CREATE	_IOR('N', 0x51, unsigned int)
#define NVMED_IOCTL_QUEUE_DELETE	_IOW('N', 0x52, unsigned int)
#define NVMED_IOCTL_GET_BUFFER_ADDR	_IOWR('N', 0x60, struct nvmed_buf)
#define NVMED_IOCTL_GET_USER		_IOWR('N', 0x70, struct nvmed_user_quota)
#define NVMED_IOCTL_SET_USER		_IOWR('N', 0x71, struct nvmed_user_quota)

// For nvmed_info (borrowed from <linux/nvme_ioctl.h>
// This ioctl() should be done to nvmed->dev_fd
#define NVMED_IOCTL_ADMIN_CMD		_IOWR('N', 0x41, struct nvme_admin_cmd)

#define NVMED_CACHE_INIT_NUM_PAGES	2560	

#define SQ_SIZE(depth)		(depth * sizeof(struct nvme_command))
#define CQ_SIZE(depth)		(depth * sizeof(struct nvme_completion))

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

typedef enum {
	NVMED_SUCCESS,
	NVMED_FAULT,
	NVMED_NOENTRY,
	NVMED_EXCEEDLIMIT,
	NVMED_NOPERM,
	NVMED_OVERQUOTA,
} NVMED_RESULT;

typedef struct nvmed_buf {
	void* addr;
	unsigned int size;
	u64* pfnList;
} NVMED_BUF;

typedef struct nvmed_device_info {
	int instance;
	int lba_shift;
	unsigned int ns_id;
	int q_depth;
	u64 capacity;
	u32 max_hw_sectors;
	u32 stripe_size;
	u32 db_stride;
	u8	vwc;

	unsigned long start_sect;
	unsigned long nr_sects;
	int part_no;

} NVMED_DEVICE_INFO;

typedef struct nvmed_user_quota {
	uid_t uid;
	unsigned int queue_max;
	unsigned int queue_used;
} NVMED_USER_QUOTA;

#endif /* _NVMED_H */
