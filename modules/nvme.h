#ifdef KERN_440

#ifndef _NVMED_NVME_HEADER_H
#define _NVMED_NVME_HEADER_H

#include <linux/blk-mq.h>

struct nvme_dev {
	struct list_head node;
	struct nvme_queue **queues;
	struct request_queue *admin_q;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	int instance;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	u32 ctrl_config;
	struct msix_entry *entry;
	struct nvme_bar __iomem *bar;
	struct list_head namespaces;
	struct kref kref;
	struct device *device;
	struct work_struct reset_work;
	struct work_struct probe_work;
	struct work_struct scan_work;
	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];
	bool subsystem;
	u32 max_hw_sectors;
	u32 stripe_size;
	u32 page_size;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	u64 cmb_size;
	u32 cmbsz;
	u16 oncs;
	u16 abort_limit;
	u8 event_limit;
	u8 vwc;
};

struct nvme_ns {
	struct list_head list;

	struct nvme_dev *dev;
	struct request_queue *queue;
	struct gendisk *disk;
	struct kref kref;

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	bool ext;
	u8 pi_type;
	int type;
	u64 mode_select_num_blocks;
	u32 mode_select_block_len;
};
#endif

#endif

