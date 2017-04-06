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

#ifndef _NVMED_MODULE_H
#define _NVMED_MODULE_H

#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/version.h>
#include <linux/blkdev.h>

#define NVMED_ERR(string, args...) printk(KERN_ERR string, ##args)
#define NVMED_INFO(string, args...) printk(KERN_INFO string, ##args)
#define NVMED_DEBUG(string, args...) printk(KERN_DEBUG string, ##args)

#define PCI_CLASS_NVME	0x010802

#define KERNEL_VERSION_CODE	KERNEL_VERSION(KERNEL_VERSION_MAJOR, \
										KERNEL_VERSION_MINOR, 0)

#define DEV_TO_ADMINQ(dev) dev->admin_q
#define NS_TO_DEV(ns) ns->dev
#define DEV_TO_INSTANCE(dev) dev->instance
#define DEV_TO_HWSECTORS(dev) dev->max_hw_sectors
#define DEV_TO_STRIPESIZE(dev) dev->stripe_size
#define DEV_TO_VWC(dev) dev->vwc
#define DEV_TO_NS_LIST(dev) dev->namespaces

/* Legacy struct NVMe, BLK_MQ->REQ_TYPE */
#if KERNEL_VERSION_CODE < KERNEL_VERSION(4,2,0)
	#define	DEV_FROM_NVMe(nvme_dev)	&nvme_dev->pci_dev->dev
#else
	#if KERNEL_VERSION_CODE == KERNEL_VERSION(4,4,0)
		#define KERN_440
		#include "nvme.h"
	#endif
	#if KERNEL_VERSION_CODE == KERNEL_VERSION(4,5,0)
		#define KERN_450
		#include "nvme.h"
	#endif
	#if KERNEL_VERSION_CODE == KERNEL_VERSION(4,6,0)
		#define KERN_460
		#include "nvme.h"
	#endif
	#if KERNEL_VERSION_CODE == KERNEL_VERSION(4,7,0)
		#define KERN_470
		#include "nvme.h"
	#endif
	#if KERNEL_VERSION_CODE == KERNEL_VERSION(4,8,0)
		#define KERN_480
		#include "nvme.h"
	#endif
	#if KERNEL_VERSION_CODE == KERNEL_VERSION(4,9,0)
		#define KERN_490
		#include "nvme.h"
	#endif
	#if KERNEL_VERSION_CODE == KERNEL_VERSION(4,10,0)
		#define KERN_4100
		#include "nvme.h"
	#endif

	#if KERNEL_VERSION_CODE >= KERNEL_VERSION(4,5,0)
		#undef DEV_TO_ADMINQ
		#undef NS_TO_DEV
		#undef DEV_TO_INSTANCE
		#undef DEV_TO_HWSECTORS
		#undef DEV_TO_STRIPESIZE
		#undef DEV_TO_VWC
		#undef DEV_TO_NS_LIST

		#define DEV_TO_ADMINQ(dev) dev->ctrl.admin_q
		#define NS_TO_DEV(ns) container_of(ns->ctrl, struct nvme_dev, ctrl)
		#define DEV_TO_INSTANCE(dev) dev->ctrl.instance
		#define DEV_TO_HWSECTORS(dev) dev->ctrl.max_hw_sectors
		#define DEV_TO_STRIPESIZE(dev) dev->ctrl.stripe_size
		#define DEV_TO_VWC(dev) dev->ctrl.vwc
		#define DEV_TO_NS_LIST(dev) dev->ctrl.namespaces

	#endif

	#if KERNEL_VERSION_CODE >= KERNEL_VERSION(4,10,0)
		#undef DEV_TO_STRIPESIZE
		#define DEV_TO_STRIPESIZE(dev) (dev->ctrl.max_hw_sectors << 8)
	#endif

	#define	DEV_FROM_NVMe(nvme_dev)	nvme_dev->dev
#endif

//NVME_SET_FEATURES
#if KERNEL_VERSION_CODE < KERNEL_VERSION(4,5,0)
	#define NVMED_SET_FEATURES(dev_entry, fid, dword11, dma_addr, result) \
				nvmed_set_features_fn(dev_entry->dev, fid, dword11, dma_addr, result)
	int (*nvmed_set_features_fn)(struct nvme_dev *dev, unsigned fid, unsigned dword11,
		dma_addr_t dma_addr, u32 *result) = NULL;
#elif KERNEL_VERSION_CODE < KERNEL_VERSION(4,9,0)
	#define NVMED_SET_FEATURES(dev_entry, fid, dword11, dma_addr, result) \
				nvmed_set_features_fn(&dev_entry->dev->ctrl, fid, dword11, dma_addr, result)
	int (*nvmed_set_features_fn)(struct nvme_ctrl *dev, unsigned fid, unsigned dword11,
		dma_addr_t dma_addr, u32 *result) = NULL;
#else
	#define NVMED_SET_FEATURES(dev_entry, fid, dword11, dma_addr, result) \
				nvmed_set_features_fn(&dev_entry->dev->ctrl, fid, dword11, NULL, 0, result)
	int (*nvmed_set_features_fn)(struct nvme_ctrl *dev, unsigned fid, unsigned dword11,
		void *buffer, size_t buflen, u32 *result) = NULL;

#endif

#if KERNEL_VERSION_CODE < KERNEL_VERSION(3,19,0)
	#undef DEV_TO_ADMINQ
	#define DEV_TO_ADMINQ(dev) dev
	int (*nvmed_submit_cmd_mq)(void *x, ...);
#else
	int (*nvmed_submit_cmd_mq)(struct request_queue *q, struct nvme_command *cmd,
		void *buf, unsigned bufflen) = NULL;

#endif
int (*nvmed_submit_cmd)(struct nvme_dev *, struct nvme_command *, 
		u32 *result) = NULL;

#define TRUE	1
#define FALSE	0

unsigned char admin_timeout = 60;
#define ADMIN_TIMEOUT		(admin_timeout * HZ)

struct proc_dir_entry *NVMED_PROC_ROOT;

static LIST_HEAD(nvmed_dev_list);

struct async_cmd_info {
	struct kthread_work work;
	struct kthread_worker *worker;
	struct request *req;
	u32 result;
	int status;
	void *ctx;
};

struct nvme_queue {
	struct device *q_dmadev;
	struct nvme_dev *dev;
	spinlock_t q_lock;
	struct nvme_command *sq_cmds;
	struct nvme_command __iomem *sq_cmds_io;
	volatile struct nvme_completion *cqes;
	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;
	u32 __iomem *q_db;
	u16 q_depth;
	u16 sq_head;
	u16 sq_tail;
	u16 cq_head;
	u16 qid;
	u8 cq_phase;
	u8 cqe_seen;
};

typedef struct nvmed_user_quota_entry {
	kuid_t uid;
	unsigned int queue_max;
	unsigned int queue_used;

	struct list_head list;
} NVMED_USER_QUOTA_ENTRY;

typedef struct nvmed_dev_entry {
	struct nvme_dev *dev;

	spinlock_t ctrl_lock;

	unsigned int num_user_queue;
	DECLARE_BITMAP(queue_bmap, 256);

	struct list_head list;
	struct list_head ns_list;
} NVMED_DEV_ENTRY;

typedef struct nvmed_ns_entry {
	NVMED_DEV_ENTRY *dev_entry;

	struct nvme_ns *ns;
	
	struct proc_dir_entry *ns_proc_root;
	struct proc_dir_entry *proc_admin;
	
	struct list_head list;

	struct list_head queue_list;
	struct list_head user_list;
	
	int partno;

	sector_t start_sect;
	sector_t nr_sects;
} NVMED_NS_ENTRY;

typedef struct nvmed_queue_entry {
	NVMED_NS_ENTRY *ns_entry;
	
	struct proc_dir_entry *queue_proc_root;
	struct proc_dir_entry *proc_sq;
	struct proc_dir_entry *proc_cq;
	struct proc_dir_entry *proc_db;

	struct nvme_queue* nvmeq;

	kuid_t owner;

	struct list_head list;
} NVMED_QUEUE_ENTRY;

#endif
