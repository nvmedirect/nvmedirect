/*
 * NVMeDirect Device Driver
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

#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/genhd.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

#define NVMED_CORE_HEADERS

#include "./nvmed.h"


int nvmed_submit_sync_cmd(struct nvme_dev *dev, struct nvme_command* cmd, 
		void* buffer, unsigned bufflen, u32 *result) {
	int ret = 0;

	if(nvmed_submit_cmd) {
		ret = nvmed_submit_cmd(dev, cmd, result);
	}
	else {
		ret = nvmed_submit_cmd_mq(DEV_TO_ADMINQ(dev), cmd, buffer, bufflen);
	}
	return ret;
}

static int nvmed_get_features(NVMED_DEV_ENTRY *dev_entry, unsigned fid, u32 *result)
{
	return NVMED_GET_FEATURES(dev_entry, fid, result);
}

static int nvmed_set_features(NVMED_DEV_ENTRY *dev_entry, unsigned fid, unsigned dword11,
					dma_addr_t dma_addr, u32 *result)
{
	return NVMED_SET_FEATURES(dev_entry, fid, dword11, dma_addr, result);
}

static int get_queue_count(NVMED_DEV_ENTRY *dev_entry)
{
	int status;
	u32 result = 0;

	status = nvmed_get_features(dev_entry, NVME_FEAT_NUM_QUEUES, &result);
	
	if (status < 0)
		return status;
	if (status > 0) {
		dev_err(DEV_ENTRY_TO_DEVICE(dev_entry), "Could not set queue count (%d)\n", status);
		return 0;
	}
	return min(result & 0xffff, result >> 16) + 1;
}

static int set_queue_count(NVMED_DEV_ENTRY *dev_entry, int count, int *err)
{
	int status;
	u32 result = 0;
	u32 q_count = (count - 1) | ((count - 1) << 16);

	status = nvmed_set_features(dev_entry, NVME_FEAT_NUM_QUEUES, q_count, 0,
								&result);
	if (status < 0)
		return status;
	if (status > 0) {
		*err = status;
		return 0;
	}
	return min(result & 0xffff, result >> 16) + 1;
}

static struct nvme_queue *nvmed_alloc_queue(NVMED_DEV_ENTRY *dev_entry, int qid, int depth) {
	struct nvme_dev *dev = dev_entry->dev;
	struct nvme_queue *nvmeq = kzalloc(sizeof(*nvmeq), GFP_KERNEL);
	
	if(!nvmeq) return NULL;

	nvmeq->cqes = dma_zalloc_coherent(DEV_ENTRY_TO_DEVICE(dev_entry), CQ_SIZE(depth),
							&nvmeq->cq_dma_addr, GFP_KERNEL);
	if(!nvmeq->cqes)
		goto free_nvmeq;

	nvmeq->sq_cmds = dma_zalloc_coherent(DEV_ENTRY_TO_DEVICE(dev_entry), SQ_SIZE(depth),
							&nvmeq->sq_dma_addr, GFP_KERNEL);
	if(!nvmeq->sq_cmds)
		goto free_cqdma;

	nvmeq->q_dmadev = DEV_ENTRY_TO_DEVICE(dev_entry);
	nvmeq->dev = dev;
	spin_lock_init(&nvmeq->q_lock);
	nvmeq->cq_head = 0;
	nvmeq->cq_phase = 1;
	nvmeq->q_db = &dev->dbs[qid * 2 * dev->db_stride];
	nvmeq->q_depth = depth;
	nvmeq->qid = qid;

	return nvmeq;

free_cqdma:
	dma_free_coherent(DEV_ENTRY_TO_DEVICE(dev_entry), CQ_SIZE(depth), (void *)nvmeq->cqes, 
						nvmeq->cq_dma_addr);	
free_nvmeq:
	kfree(nvmeq);
	return NULL;
}

static int adapter_alloc_cq(NVMED_DEV_ENTRY *dev_entry, u16 qid,
						struct nvme_queue *nvmeq, int irq_vector)
{
	struct nvme_dev *dev = dev_entry->dev;
	struct nvme_command c;
	int flags = NVME_QUEUE_PHYS_CONTIG;

	if(irq_vector > 0)
		flags |= NVME_CQ_IRQ_ENABLED;

	/*
	 * Note: we (ab)use the fact the the prp fields survive if no data
	 * is attached to the request.
	 */
	memset(&c, 0, sizeof(c));
	c.create_cq.opcode = nvme_admin_create_cq;
	c.create_cq.prp1 = cpu_to_le64(nvmeq->cq_dma_addr);
	c.create_cq.cqid = cpu_to_le16(qid);
	c.create_cq.qsize = cpu_to_le16(nvmeq->q_depth - 1);
	c.create_cq.cq_flags = cpu_to_le16(flags);
	c.create_cq.irq_vector = irq_vector;

	return nvmed_submit_sync_cmd(dev, &c, NULL, 0, NULL);
}

static int adapter_alloc_sq(NVMED_DEV_ENTRY *dev_entry, u16 qid,
						struct nvme_queue *nvmeq)
{
	struct nvme_dev *dev = dev_entry->dev;
	struct nvme_command c;
	int flags = NVME_QUEUE_PHYS_CONTIG | NVME_SQ_PRIO_MEDIUM;

	/*
	 * Note: we (ab)use the fact the the prp fields survive if no data
	 * is attached to the request.
	 */
	memset(&c, 0, sizeof(c));
	c.create_sq.opcode = nvme_admin_create_sq;
	c.create_sq.prp1 = cpu_to_le64(nvmeq->sq_dma_addr);
	c.create_sq.sqid = cpu_to_le16(qid);
	c.create_sq.qsize = cpu_to_le16(nvmeq->q_depth - 1);
	c.create_sq.sq_flags = cpu_to_le16(flags);
	c.create_sq.cqid = cpu_to_le16(qid);

	return nvmed_submit_sync_cmd(dev, &c, NULL, 0, NULL);
}

static int nvmed_create_queue(NVMED_QUEUE_ENTRY *queue_entry, int qid, int irq_vector) {
	NVMED_DEV_ENTRY *dev_entry = queue_entry->ns_entry->dev_entry;
	struct nvme_dev *dev = queue_entry->nvmeq->dev;
	struct nvme_queue *nvmeq = queue_entry->nvmeq;
	int result;

	result = adapter_alloc_cq(dev_entry, qid, nvmeq, irq_vector);
	if(result < 0)
		return result;

	result = adapter_alloc_sq(dev_entry, qid, nvmeq);
	if(result < 0)
		return result;

	nvmeq->sq_tail = 0;
	nvmeq->cq_head = 0;
	nvmeq->cq_phase = 1;
	nvmeq->q_db = &dev->dbs[qid * 2 * dev->db_stride];
	memset((void *)nvmeq->cqes, 0, CQ_SIZE(nvmeq->q_depth));

	return result;
}

static int adapter_delete_queue(NVMED_DEV_ENTRY *dev_entry, u8 opcode, u16 id)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.delete_queue.opcode = opcode;
	c.delete_queue.qid = cpu_to_le16(id);

	return nvmed_submit_sync_cmd(dev_entry->dev, &c, NULL, 0, NULL);
}


void nvmed_disable_queue(NVMED_DEV_ENTRY *dev_entry, NVMED_QUEUE_ENTRY *queue_entry) {
	adapter_delete_queue(dev_entry, nvme_admin_delete_sq, queue_entry->nvmeq->qid);
	adapter_delete_queue(dev_entry, nvme_admin_delete_cq, queue_entry->nvmeq->qid);
}

static NVMED_USER_QUOTA_ENTRY* nvmed_get_user_quota(NVMED_NS_ENTRY *ns_entry, kuid_t uid) {
	NVMED_USER_QUOTA_ENTRY *quota;
	
	list_for_each_entry(quota, &ns_entry->user_list, list) {
		if(quota->uid.val == uid.val) {
			return quota;
		}
	}

	return NULL;
}

/*
 * Copy NVMe device information to user
 */
static int nvmed_get_device_info(NVMED_NS_ENTRY *ns_entry, 
								NVMED_DEVICE_INFO __user *u_dev_info) {
	struct nvme_ns *ns = ns_entry->ns;
	struct nvme_dev *dev = NS_ENTRY_TO_DEV(ns_entry);
	struct nvmed_device_info dev_info;
	
	if(nvmed_get_user_quota(ns_entry, current_uid()) < 0)
		return -EPERM;

	dev_info.instance = DEV_TO_INSTANCE(dev);
	dev_info.ns_id = ns->ns_id;
	dev_info.capacity = ns->disk->part0.nr_sects << (ns->lba_shift);
	dev_info.q_depth = dev->q_depth;
	dev_info.lba_shift = ns->lba_shift;
	dev_info.max_hw_sectors = DEV_TO_HWSECTORS(dev);
	dev_info.stripe_size = DEV_TO_STRIPESIZE(dev);
	dev_info.db_stride = dev->db_stride;
	dev_info.vwc = DEV_TO_VWC(dev);
	dev_info.start_sect = ns_entry->start_sect;
	dev_info.nr_sects = ns_entry->nr_sects;
	dev_info.part_no = ns_entry->partno;

	copy_to_user(u_dev_info, &dev_info, sizeof(dev_info));

	return NVMED_SUCCESS;
}

/*
 * Get I/O queue quota per user
 * Args   : *nvmed_ns_entry, kuid_g
 * Return : 0 >= number of remaining queue quota
 *			<0 error
 */
static int nvmed_get_remain_user_quota(NVMED_NS_ENTRY *ns_entry, kuid_t uid) {
	NVMED_USER_QUOTA_ENTRY *quota;
	int ret_val = -NVMED_NOENTRY;

	quota = nvmed_get_user_quota(ns_entry, uid);
	if(quota == NULL) return 0;
	ret_val = quota->queue_max - quota->queue_used;
	if(ret_val < 0) ret_val = 0;

	return ret_val;
}

/*
 * Set I/O queue quota per user
 * Args		: *nvmed_ns_entry, kuid_t, quota(int)
 * Return	: 0 success, < 0 Error
 */
static int nvmed_set_user_quota(NVMED_NS_ENTRY *ns_entry, kuid_t uid, unsigned __quota) {
	NVMED_USER_QUOTA_ENTRY *quota;

	if(current_cred()->uid.val != 0) return -EPERM;
	
	quota = nvmed_get_user_quota(ns_entry, uid);

	if(quota == NULL) {
		quota = kzalloc(sizeof(*quota), GFP_KERNEL);
		quota->uid = uid;
		quota->queue_max = __quota;
		list_add(&quota->list, &ns_entry->user_list);
	}
	else {
		quota->queue_max = __quota;
		if(__quota == 0 && quota->queue_used == 0) {
			list_del(&quota->list);
			kfree(quota);
		}
	}

	return NVMED_SUCCESS;
}
static int nvmed_set_user_used_quota(NVMED_NS_ENTRY *ns_entry, kuid_t uid, bool isInc) {
	NVMED_USER_QUOTA_ENTRY *quota;

	quota = nvmed_get_user_quota(ns_entry, uid);

	if(quota == NULL) {
		return -NVMED_NOENTRY;
	}
	else {
		if(isInc)
			quota->queue_used++;
		else
			quota->queue_used--;
	}

	return NVMED_SUCCESS;
}

/*
 * nvmed_get_buffer_addr
 * translate virtual address to physical address, set reserved flags
 */
static int nvmed_get_buffer_addr(NVMED_NS_ENTRY *ns_entry, NVMED_BUF* __user *__buf) {
	struct task_struct *task = current;
	struct mm_struct *mm;
	NVMED_BUF u_buf;
	unsigned long vaddr, start_addr;
	int ret_val = NVMED_SUCCESS;
	int i;
	u64* pfnList;
	struct page *page_info;
	
	pgd_t *pgd;
	pte_t *ptep, pte;
	pud_t *pud;
	pmd_t *pmd;

	copy_from_user(&u_buf, __buf, sizeof(u_buf));

	start_addr = (unsigned long)u_buf.addr;

	pfnList = kzalloc(sizeof(u64) * u_buf.size, GFP_KERNEL);

	mm = task->mm;
	down_read(&mm->mmap_sem);
	for(i=0; i<u_buf.size; i++) {
		vaddr = start_addr + (PAGE_SIZE * i);
		
		pgd = pgd_offset(mm, vaddr);
		if(pgd_none(*pgd) || pgd_bad(*pgd)) {
			ret_val = -EFAULT;
			break;
		}

		pud = pud_offset(pgd, vaddr);
		if(pud_none(*pud) || pud_bad(*pud)) {
			ret_val = -EFAULT;
			break;
		}

		pmd = pmd_offset(pud, vaddr);
		if(!pmd_none(*pmd) && 
				(pmd_val(*pmd) & (_PAGE_PRESENT|_PAGE_PSE)) != _PAGE_PRESENT) {
			pte = *(pte_t *)pmd;
			pfnList[i] = (pte_pfn(pte) << PAGE_SHIFT) + (vaddr & ~PMD_MASK);
			continue;
		}
		else if (pmd_none(*pmd) || pmd_bad(*pmd)) {
			ret_val = -EFAULT;
			break;
		}

		ptep = pte_offset_map(pmd, vaddr);
		if(!ptep) {
			ret_val = -EFAULT;
			break;
		}

		pte = *ptep;
		page_info = pte_page(pte);
		pfnList[i] = pte_pfn(pte) << PAGE_SHIFT;
		pte_unmap(ptep);
	}
	up_read(&mm->mmap_sem);
	
	copy_to_user(u_buf.pfnList, pfnList, sizeof(u64)*u_buf.size);

	kfree(pfnList);

	return ret_val;
}

static int nvmed_queue_proc_open(struct inode *inode, struct file *filp) {
	NVMED_QUEUE_ENTRY *queue_entry = PDE_DATA(filp->f_inode);

	if(queue_entry->owner.val != current_uid().val)
		return -EPERM;

	return 0;
}

static int nvmed_queue_db_proc_mmap(struct file *filp, struct vm_area_struct *vma) {
	NVMED_QUEUE_ENTRY *queue_entry = PDE_DATA(filp->f_inode);
	NVMED_DEV_ENTRY *dev_entry;
	struct pci_dev *pdev;
	int ret = -1;

	dev_entry = queue_entry->ns_entry->dev_entry;

	pdev = to_pci_dev(DEV_ENTRY_TO_DEVICE(dev_entry));
	
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	ret = io_remap_pfn_range(vma, vma->vm_start, pci_resource_start(pdev,0) >> PAGE_SHIFT,
			4096*2, vma->vm_page_prot);

	return 0;
}

static int nvmed_queue_sq_proc_mmap(struct file *filp, struct vm_area_struct *vma) {
	NVMED_QUEUE_ENTRY *queue_entry = PDE_DATA(filp->f_inode);
	struct nvme_queue *nvmeq;
	struct device* dmadev;
	int ret = -1;

	nvmeq = queue_entry->nvmeq;
	dmadev = nvmeq->q_dmadev;

	ret = dma_common_mmap(dmadev, vma, 
			nvmeq->sq_cmds, nvmeq->sq_dma_addr, SQ_SIZE(nvmeq->q_depth));

	return 0;
}

static int nvmed_queue_cq_proc_mmap(struct file *filp, struct vm_area_struct *vma) {
	NVMED_QUEUE_ENTRY *queue_entry = PDE_DATA(filp->f_inode);
	struct nvme_queue *nvmeq;
	struct device* dmadev;
	int ret = -1;

	nvmeq = queue_entry->nvmeq;
	dmadev = nvmeq->q_dmadev;

	ret = dma_common_mmap(dmadev, vma, 
			(void *)nvmeq->cqes, nvmeq->cq_dma_addr, CQ_SIZE(nvmeq->q_depth));

	return 0;
}


static const struct file_operations nvme_queue_db_fops = {
	.owner	= THIS_MODULE,
	.open	= nvmed_queue_proc_open,
	.mmap	= nvmed_queue_db_proc_mmap,
};
static const struct file_operations nvme_queue_sq_fops = {
	.owner	= THIS_MODULE,
	.open	= nvmed_queue_proc_open,
	.mmap	= nvmed_queue_sq_proc_mmap,
};
static const struct file_operations nvme_queue_cq_fops = {
	.owner	= THIS_MODULE,
	.open	= nvmed_queue_proc_open,
	.mmap	= nvmed_queue_cq_proc_mmap,
};

static int nvmed_queue_create(NVMED_NS_ENTRY *ns_entry,
		NVMED_CREATE_QUEUE_ARGS __user *__args) {
	NVMED_DEV_ENTRY *dev_entry = ns_entry->dev_entry;
	struct nvme_dev *dev = NS_ENTRY_TO_DEV(ns_entry);
	unsigned int queue_count;
	NVMED_QUEUE_ENTRY *queue;
	NVMED_CREATE_QUEUE_ARGS args;
	size_t size;
	char dentry_buf[4];
	int qid;
	int err;
	int result;
	bool reqInterrupt = FALSE;
	unsigned int irq_vector = 0;

	spin_lock(&dev_entry->ctrl_lock);

	copy_from_user(&args, __args, sizeof(NVMED_CREATE_QUEUE_ARGS));
	if(args.reqInterrupt) {
		reqInterrupt = TRUE;
	}

	//check quota
	if(!nvmed_get_remain_user_quota(ns_entry, current_uid())) {
		spin_unlock(&dev_entry->ctrl_lock);
		return -NVMED_OVERQUOTA;
	}

	queue_count = dev->queue_count + dev_entry->num_user_queue;
	//db_bar_size check
	size = (queue_count+1) * 8 * dev->db_stride;
	if(size > 4096) {
		spin_unlock(&dev_entry->ctrl_lock);
		return -NVMED_EXCEEDLIMIT;
	}
	//set_queue_count
	result = set_queue_count(dev_entry, queue_count, &err);
	if(result < 0) {
		NVMED_ERR("NVMeDirect: Error on set queue count\n");
		spin_unlock(&dev_entry->ctrl_lock);
		return -NVMED_EXCEEDLIMIT;
	}
	else if(result == 0 && err == 6) {
		result = get_queue_count(dev_entry);
	}

	if(result < queue_count) {
		NVMED_ERR("NVMeDirect: Number of queues exceed limit\n");
		spin_unlock(&dev_entry->ctrl_lock);
		return -NVMED_EXCEEDLIMIT;
	}

	//user_queue_entry create
	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	queue->ns_entry = ns_entry;
	qid = find_first_zero_bit(dev_entry->queue_bmap, 256);
	set_bit(qid, dev_entry->queue_bmap);

	//queue alloc
	queue->nvmeq = nvmed_alloc_queue(dev_entry, qid, dev->q_depth);
	if(!queue->nvmeq) {
		result = -NVMED_FAULT;
		goto result_error_bmap_clear;
	}

	//get Vector Nr
	if(reqInterrupt) {
		irq_vector = find_first_zero_bit(dev_entry->vec_bmap, 
				dev_entry->vec_bmap_max);
		set_bit(irq_vector, dev_entry->vec_bmap);
	}

	result = nvmed_create_queue(queue, qid, irq_vector);
	if(result) {
		goto result_error_create_queue;
	}

	//If reqInterrupt && irq_vector?
	if(reqInterrupt && irq_vector) {
		result = nvmed_register_intr_handler(dev_entry, queue, irq_vector);
		if(result)
			goto result_error_set_intr;
		queue->irq_vector = irq_vector;
		atomic_set(&queue->nr_intr, 0);
	}

	//create proc entry
	sprintf(dentry_buf, "%d", qid);
	queue->queue_proc_root = proc_mkdir(dentry_buf, ns_entry->ns_proc_root);
	queue->proc_sq = proc_create_data("sq", S_IRWXU|S_IRWXG|S_IRWXO,
					queue->queue_proc_root, &nvme_queue_sq_fops, queue);
	queue->proc_cq = proc_create_data("cq", S_IRWXU|S_IRWXG|S_IRWXO,
					queue->queue_proc_root, &nvme_queue_cq_fops, queue);
	queue->proc_db = proc_create_data("db", S_IRWXU|S_IRWXG|S_IRWXO,
					queue->queue_proc_root, &nvme_queue_db_fops, queue);


	//set owner
	queue->owner = current_uid();
	nvmed_set_user_used_quota(ns_entry, current_uid(), TRUE);

	dev_entry->num_user_queue++;
	list_add(&queue->list, &ns_entry->queue_list);

	spin_unlock(&dev_entry->ctrl_lock);

	args.qid = qid;
	copy_to_user(__args, &args, sizeof(NVMED_CREATE_QUEUE_ARGS));

	return NVMED_SUCCESS;

result_error_set_intr:
	clear_bit(irq_vector, dev_entry->vec_bmap);
	nvmed_disable_queue(dev_entry, queue);

result_error_create_queue:
	dma_free_coherent(queue->nvmeq->q_dmadev, CQ_SIZE(queue->nvmeq->q_depth),
			(void *)queue->nvmeq->cqes, queue->nvmeq->cq_dma_addr);
	dma_free_coherent(queue->nvmeq->q_dmadev, SQ_SIZE(queue->nvmeq->q_depth),
			queue->nvmeq->sq_cmds, queue->nvmeq->sq_dma_addr);
	kfree(queue->nvmeq);

result_error_bmap_clear:
	clear_bit(qid, dev_entry->queue_bmap);
	kfree(queue);

	return result;
}

NVMED_QUEUE_ENTRY* nvmed_get_queue_from_qid(NVMED_NS_ENTRY *ns_entry, 
		unsigned int qid) {
	NVMED_QUEUE_ENTRY *queue, *ret = NULL;

	list_for_each_entry(queue, &ns_entry->queue_list, list) {
		if(queue->nvmeq->qid == qid) {
			ret = queue;
			break;
		}
	}

	return ret;
}

static int nvmed_queue_delete_kern(NVMED_NS_ENTRY *ns_entry, unsigned int qid) {
	NVMED_QUEUE_ENTRY *queue;
	NVMED_DEV_ENTRY *dev_entry; 	

	//get Queue
	queue = nvmed_get_queue_from_qid(ns_entry, qid);
	if(queue == NULL) {
		return -NVMED_NOENTRY;
	}

	dev_entry = queue->ns_entry->dev_entry;
	//Permission Check
	if(current_uid().val != 0 && queue->owner.val != get_current_user()->uid.val) {
		return -NVMED_NOPERM;
	}

	//disable queue
	nvmed_disable_queue(dev_entry, queue);
	//free queue
	dma_free_coherent(queue->nvmeq->q_dmadev, CQ_SIZE(queue->nvmeq->q_depth),
			(void *)queue->nvmeq->cqes, queue->nvmeq->cq_dma_addr);
	dma_free_coherent(queue->nvmeq->q_dmadev, SQ_SIZE(queue->nvmeq->q_depth),
			queue->nvmeq->sq_cmds, queue->nvmeq->sq_dma_addr);
	kfree(queue->nvmeq);

	//clear bitmap
	clear_bit(qid, dev_entry->queue_bmap);

	//interrupt enabled?
	if(queue->irq_vector) {
		nvmed_free_intr_handler(dev_entry, queue, qid);
	}

	//proc remove
	proc_remove(queue->proc_sq);
	proc_remove(queue->proc_cq);
	proc_remove(queue->proc_db);
	proc_remove(queue->queue_proc_root);

	//user quota
	nvmed_set_user_used_quota(queue->ns_entry, current_uid(), FALSE);
	dev_entry->num_user_queue--;
	
	//delete from list
	list_del(&queue->list);

	//delete queue_entry
	kfree(queue);

	return NVMED_SUCCESS;
}

static int nvmed_queue_delete(NVMED_NS_ENTRY *ns_entry, unsigned int __user *__qid) {
	unsigned int qid;
	
	copy_from_user(&qid, __qid, sizeof(unsigned int));

	return nvmed_queue_delete_kern(ns_entry, qid);
}

static int nvmed_get_user(NVMED_NS_ENTRY *ns_entry, NVMED_USER_QUOTA __user *__quota) {
	NVMED_USER_QUOTA quota;
	NVMED_USER_QUOTA_ENTRY *quota_entry;
	kuid_t uid;

	copy_from_user(&quota, __quota, sizeof(*__quota));
	
	uid.val = quota.uid;
	quota_entry = nvmed_get_user_quota(ns_entry, uid);
	if(quota_entry == NULL)
		return -NVMED_FAULT;

	quota.queue_max = quota_entry->queue_max;
	quota.queue_used = quota_entry->queue_used;

	copy_to_user(__quota , &quota, sizeof(quota));

	return NVMED_SUCCESS;
}

static int nvmed_set_user(NVMED_NS_ENTRY *ns_entry, NVMED_USER_QUOTA __user *__quota) {
	NVMED_USER_QUOTA quota;
	NVMED_USER_QUOTA_ENTRY *quota_entry;
	kuid_t uid;
	
	if(current_uid().val != 0) return -EPERM;

	copy_from_user(&quota, __quota, sizeof(*__quota));
	uid.val = quota.uid;

	nvmed_set_user_quota(ns_entry, uid, quota.queue_max);
	
	if(quota.queue_max == 0) {
		quota.queue_max = 0;
		quota.queue_used = 0;

	}
	else {
		quota_entry = nvmed_get_user_quota(ns_entry, uid);
		if(quota_entry == NULL)  {
			return -NVMED_FAULT;
		}
		quota.queue_max = quota_entry->queue_max;
		quota.queue_used = quota_entry->queue_used;
	}
	copy_to_user(__quota , &quota, sizeof(quota));

	return NVMED_SUCCESS;
}

/*
 * IOCTL FUNCTION of /proc/NVMeDirect/nvmeXnY/admin
 */
static long nvmed_admin_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	NVMED_NS_ENTRY *ns_entry = PDE_DATA(file->f_inode);

	switch (cmd) {
		case NVMED_IOCTL_NVMED_INFO:
			return nvmed_get_device_info(ns_entry, (void __user *)arg);

		case NVMED_IOCTL_QUEUE_CREATE:
			return nvmed_queue_create(ns_entry, (void __user *)arg);

		case NVMED_IOCTL_QUEUE_DELETE:
			return nvmed_queue_delete(ns_entry, (void __user *)arg);

		case NVMED_IOCTL_GET_BUFFER_ADDR:
			return nvmed_get_buffer_addr(ns_entry, (void __user *)arg);

		case NVMED_IOCTL_INTERRUPT_COMM:
			return nvmed_irq_comm(ns_entry, (void __user *)arg);

		case NVMED_IOCTL_GET_USER:
			return nvmed_get_user(ns_entry, (void __user *)arg);

		case NVMED_IOCTL_SET_USER:
			return nvmed_set_user(ns_entry, (void __user *)arg);

		default:
			return -ENOTTY;
	}

	return -ENOTTY;
}

static const struct file_operations nvmed_ns_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = nvmed_admin_ioctl
};

/* Scan nvme pci device, add proc entry */
static NVMED_RESULT nvmed_scan_device(void) {
	struct pci_dev *pdev = NULL;
	struct nvme_dev *dev;
	struct nvme_ns *ns;

	NVMED_DEV_ENTRY *dev_entry;
	NVMED_NS_ENTRY *ns_entry;
		
	char dev_name[32];
	int i;
	int ret;
	unsigned long lookup_ret;
	/* for Partition support */
	struct disk_part_iter piter;
	struct hd_struct *part;
	/* for sysfs link */
	struct kobject *kobj;
	char *tempPath;
	char *sysfsPath;

	ret = request_module("nvme");

	if(ret < 0) {
		NVMED_ERR("NVMeDirect: Can not find NVMe Driver %d\n", ret);
		return -NVMED_FAULT;
	}

	lookup_ret = kallsyms_lookup_name("nvme_submit_admin_cmd");
	if(lookup_ret) {
		nvmed_submit_cmd = (typeof(nvmed_submit_cmd))(uintptr_t)lookup_ret;
	}
	else {
		lookup_ret = kallsyms_lookup_name("nvme_submit_sync_cmd");
		if(lookup_ret) {
			nvmed_submit_cmd_mq = (typeof(nvmed_submit_cmd_mq))(uintptr_t)lookup_ret;
		}
	}
	
	if(!lookup_ret) {
		NVMED_ERR("NVMeDirect: Can not find Symbol [nvme_submit_admin_cmd]\n");
		return -NVMED_FAULT;
	}

	lookup_ret = kallsyms_lookup_name("nvme_set_features");
	if(!lookup_ret) {
		NVMED_ERR("NVMeDirect: Can not find Symbol [nvme_set_features]\n");
		return -NVMED_FAULT;
	}
	nvmed_set_features_fn = (typeof(nvmed_set_features_fn))(uintptr_t)lookup_ret;

	lookup_ret = kallsyms_lookup_name("nvme_get_features");
	if(!lookup_ret) {
		NVMED_ERR("NVMeDirect: Can not find Symbol [nvme_get_features]\n");
		return -NVMED_FAULT;
	}
	nvmed_get_features_fn = (typeof(nvmed_get_features_fn))(uintptr_t)lookup_ret;

	NVMED_PROC_ROOT = proc_mkdir("nvmed", NULL);
	if(!NVMED_PROC_ROOT) {
		NVMED_ERR("NVMeDirect: Fail to create proc entry\n");
		return -NVMED_FAULT;
	}

	tempPath = kzalloc(sizeof(char) * 1024, GFP_KERNEL);
	sysfsPath = kzalloc(sizeof(char) * 1024, GFP_KERNEL);

	while ((pdev = pci_get_class(PCI_CLASS_NVME, pdev))) {
		dev = pci_get_drvdata(pdev);
		if(dev == NULL) continue;

		//////////////
		// Create Sysfs symlink destination path
		memset(tempPath, 0x0, 1024);
		memset(sysfsPath, 0x0, 1024);

		kobj = &pdev->dev.kobj;
		while(kobj != NULL) {
			snprintf(tempPath, strlen(sysfsPath) + strlen(kobj->name)+2, "/%s%s", kobj->name, sysfsPath);
			memcpy(sysfsPath, tempPath, strlen(tempPath)+1);
			kobj = kobj->parent;
		}
		snprintf(tempPath, strlen(sysfsPath) + 5, "/%s%s", "sys", sysfsPath);
		memcpy(sysfsPath, tempPath, strlen(tempPath)+1);
		//////////////
		
		dev_entry = kzalloc(sizeof(*dev_entry), GFP_KERNEL);
		dev_entry->dev = dev;
		dev_entry->pdev = pdev;
		dev_entry->num_user_queue = 0;

		spin_lock_init(&dev_entry->ctrl_lock);
		
		for(i=0; i<dev->queue_count; i++) {
			set_bit(i, dev_entry->queue_bmap);
		}

		// Intr Supports
		if(check_msix(dev_entry)) {
			dev_entry->msix_entry = NULL;
			dev_entry->vec_max = dev->max_qid - 1;
			dev_entry->vec_kernel = dev->max_qid;
			dev_entry->vec_bmap_max = pci_msix_vec_count(pdev);
			dev_entry->vec_bmap = kzalloc(sizeof(unsigned long) * \
					BITS_TO_LONGS(dev_entry->vec_bmap_max), GFP_KERNEL);
			for(i=0; i<dev->max_qid; i++) {
				set_bit(i, dev_entry->vec_bmap);
			}
		}
		// End - Intr Supports

		INIT_LIST_HEAD(&dev_entry->ns_list);

		list_add(&dev_entry->list, &nvmed_dev_list);
		
		list_for_each_entry(ns, &DEV_TO_NS_LIST(dev), list) {
			disk_part_iter_init(&piter, ns->disk, DISK_PITER_INCL_PART0);
			while ((part = disk_part_iter_next(&piter))) {
				if(part != &ns->disk->part0 && !part->info) continue;

				ns_entry = kzalloc(sizeof(*ns_entry), GFP_KERNEL);
				ns_entry->dev_entry = dev_entry;
				ns_entry->ns = ns;

				ns_entry->partno = part->partno;
				ns_entry->start_sect = part->start_sect;
				ns_entry->nr_sects = part->nr_sects;

				if(part == &ns->disk->part0)
					sprintf(dev_name, "nvme%dn%u", DEV_TO_INSTANCE(dev), ns->ns_id);
				else
					sprintf(dev_name, "nvme%dn%up%u", DEV_TO_INSTANCE(dev), ns->ns_id, part->partno);

				ns_entry->ns_proc_root = proc_mkdir(dev_name, NVMED_PROC_ROOT);
				if(!ns_entry->ns_proc_root) {
					NVMED_ERR("NVMeDirect: Error creating proc directory - %s\n", dev_name);
					kfree(ns_entry);
					continue;
				}

				ns_entry->proc_admin = proc_create_data("admin", S_IRUSR|S_IRGRP|S_IROTH,
						ns_entry->ns_proc_root, &nvmed_ns_fops, ns_entry);

				if(!ns_entry->proc_admin) {
					NVMED_ERR("NVMeDirect: Error creating proc admin entry - %s\n", dev_name);
					proc_remove(ns_entry->ns_proc_root);
					kfree(ns_entry);
					continue;
				}
				
				ns_entry->proc_sysfs_link = proc_symlink("sysfs", ns_entry->ns_proc_root, sysfsPath);
				if(!ns_entry->proc_sysfs_link) {
					NVMED_ERR("NVMeDirect: Error creating symlink - %s sysfs -> %s\n", dev_name, sysfsPath);
				}

				INIT_LIST_HEAD(&ns_entry->queue_list);
				INIT_LIST_HEAD(&ns_entry->user_list);

				list_add(&ns_entry->list, &dev_entry->ns_list);

				nvmed_set_user_quota(ns_entry, current_uid(), 100);
			}
			disk_part_iter_exit(&piter);
		}
	}
	kfree(tempPath);
	kfree(sysfsPath);

	return NVMED_SUCCESS;
}

static int __init nvmed_init(void)
{
	int retval;
	retval = nvmed_scan_device();
	if(retval < 0)
		return retval;
	

	printk(KERN_INFO "NVMeDirect: Module Initialized\n");

	return 0;
}

void nvmed_cleanup_queues(NVMED_NS_ENTRY *ns_entry) {
	NVMED_QUEUE_ENTRY *queue, *queue_next;

	list_for_each_entry_safe(queue, queue_next, &ns_entry->queue_list, list) {
		nvmed_queue_delete_kern(ns_entry, queue->nvmeq->qid);
	}
}

static void __exit nvmed_cleanup(void)
{
	NVMED_DEV_ENTRY *dev_entry, *dev_next;
	NVMED_NS_ENTRY *ns_entry, *ns_next;
	/* Cleanup procfs object */
	list_for_each_entry_safe(dev_entry, dev_next, &nvmed_dev_list, list) {
		list_for_each_entry_safe(ns_entry, ns_next, &dev_entry->ns_list, list) {

			nvmed_cleanup_queues(ns_entry);

			proc_remove(ns_entry->proc_admin);
			proc_remove(ns_entry->proc_sysfs_link);
			proc_remove(ns_entry->ns_proc_root);
			list_del(&ns_entry->list);
			kfree(ns_entry);
		}
		if(check_msix(dev_entry)) {
			kfree(dev_entry->vec_bmap);
		}
		kfree(dev_entry);
	}
	proc_remove(NVMED_PROC_ROOT);

	printk(KERN_INFO "NVMeDirect: Cleaning up modules\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hyeong-Jun Kim <hjkim@csl.skku.edu>");
MODULE_DESCRIPTION("NVMeDirect Modules");
MODULE_VERSION("0.9");

module_init(nvmed_init);
module_exit(nvmed_cleanup);
