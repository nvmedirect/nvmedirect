#ifndef _NVMED_NVME_HEADER_H
#define _NVMED_NVME_HEADER_H

#include <linux/blk-mq.h>

#ifdef KERN_440

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
#endif //KERN_440

#ifdef KERN_450

struct nvme_ctrl {
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct device *dev;
	struct kref kref;
	int instance;
	struct blk_mq_tag_set *tagset;
	struct list_head namespaces;
	struct mutex namespaces_mutex;
	struct device *device;	/* char device */
	struct list_head node;
	struct ida ns_ida;

	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];

	u32 ctrl_config;

	u32 page_size;
	u32 max_hw_sectors;
	u32 stripe_size;
	u16 oncs;
	atomic_t abort_limit;
	u8 event_limit;
	u8 vwc;
	u32 vs;
	bool subsystem;
	unsigned long quirks;
};

struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct kref kref;
	int instance;

	u8 eui[8];
	u8 uuid[16];

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	bool ext;
	u8 pi_type;
	int type;
	unsigned long flags;

#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1

	u64 mode_select_num_blocks;
	u32 mode_select_block_len;
};

struct nvme_dev {
	struct list_head node;
	struct nvme_queue **queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	struct msix_entry *entry;
	void __iomem *bar;
	struct work_struct reset_work;
	struct work_struct scan_work;
	struct work_struct remove_work;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	u64 cmb_size;
	u32 cmbsz;
	unsigned long flags;

#define NVME_CTRL_RESETTING    0
#define NVME_CTRL_REMOVING     1

	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
};

#endif //KERN_450

#ifdef KERN_460
struct nvme_ctrl {
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct device *dev;
	struct kref kref;
	int instance;
	struct blk_mq_tag_set *tagset;
	struct list_head namespaces;
	struct mutex namespaces_mutex;
	struct device *device;	/* char device */
	struct list_head node;
	struct ida ns_ida;

	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];
	int cntlid;

	u32 ctrl_config;

	u32 page_size;
	u32 max_hw_sectors;
	u32 stripe_size;
	u16 oncs;
	u16 vid;
	atomic_t abort_limit;
	u8 event_limit;
	u8 vwc;
	u32 vs;
	bool subsystem;
	unsigned long quirks;
};

/*
 * An NVM Express namespace is equivalent to a SCSI LUN
 */
struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct kref kref;
	int instance;

	u8 eui[8];
	u8 uuid[16];

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	bool ext;
	u8 pi_type;
	int type;
	unsigned long flags;

#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1

	u64 mode_select_num_blocks;
	u32 mode_select_block_len;
};

struct nvme_dev {
	struct nvme_queue **queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	struct msix_entry *entry;
	void __iomem *bar;
	struct work_struct reset_work;
	struct work_struct scan_work;
	struct work_struct remove_work;
	struct work_struct async_work;
	struct timer_list watchdog_timer;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	u64 cmb_size;
	u32 cmbsz;
	unsigned long flags;

#define NVME_CTRL_RESETTING    0
#define NVME_CTRL_REMOVING     1

	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
};

#endif //KERN_460

#ifdef KERN_470
struct nvme_ctrl {
	int state;
	spinlock_t lock;
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct device *dev;
	struct kref kref;
	int instance;
	struct blk_mq_tag_set *tagset;
	struct list_head namespaces;
	struct mutex namespaces_mutex;
	struct device *device;	/* char device */
	struct list_head node;
	struct ida ns_ida;

	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];
	u16 cntlid;

	u32 ctrl_config;

	u32 page_size;
	u32 max_hw_sectors;
	u32 stripe_size;
	u16 oncs;
	u16 vid;
	atomic_t abort_limit;
	u8 event_limit;
	u8 vwc;
	u32 vs;
	bool subsystem;
	unsigned long quirks;
	struct work_struct scan_work;
	struct work_struct async_event_work;
};

/*
 * An NVM Express namespace is equivalent to a SCSI LUN
 */
struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct kref kref;
	int instance;

	u8 eui[8];
	u8 uuid[16];

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	bool ext;
	u8 pi_type;
	int type;
	unsigned long flags;

#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1

	u64 mode_select_num_blocks;
	u32 mode_select_block_len;
};

struct nvme_dev {
	struct nvme_queue **queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	struct msix_entry *entry;
	void __iomem *bar;
	struct work_struct reset_work;
	struct work_struct remove_work;
	struct timer_list watchdog_timer;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	u64 cmb_size;
	u32 cmbsz;
	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
};

#endif //KERN_470

#ifdef KERN_480
struct nvme_ctrl {
	int state;
	spinlock_t lock;
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct request_queue *connect_q;
	struct device *dev;
	struct kref kref;
	int instance;
	struct blk_mq_tag_set *tagset;
	struct list_head namespaces;
	struct mutex namespaces_mutex;
	struct device *device;	/* char device */
	struct list_head node;
	struct ida ns_ida;

	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];
	u16 cntlid;

	u32 ctrl_config;

	u32 page_size;
	u32 max_hw_sectors;
	u32 stripe_size;
	u16 oncs;
	u16 vid;
	atomic_t abort_limit;
	u8 event_limit;
	u8 vwc;
	u32 vs;
	u32 sgls;
	u16 kas;
	unsigned int kato;
	bool subsystem;
	unsigned long quirks;
	struct work_struct scan_work;
	struct work_struct async_event_work;
	struct delayed_work ka_work;

	/* Fabrics only */
	u16 sqsize;
	u32 ioccsz;
	u32 iorcsz;
	u16 icdoff;
	u16 maxcmd;
	struct nvmf_ctrl_options *opts;
};

/*
 * An NVM Express namespace is equivalent to a SCSI LUN
 */
struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct kref kref;
	int instance;

	u8 eui[8];
	u8 uuid[16];

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	bool ext;
	u8 pi_type;
	int type;
	unsigned long flags;

#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1

	u64 mode_select_num_blocks;
	u32 mode_select_block_len;
};

struct nvme_dev {
	struct nvme_queue **queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	struct msix_entry *entry;
	void __iomem *bar;
	struct work_struct reset_work;
	struct work_struct remove_work;
	struct timer_list watchdog_timer;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	u64 cmb_size;
	u32 cmbsz;
	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
};

#endif // KERN_480

#ifdef KERN_490
enum nvme_ctrl_state {
	NVME_CTRL_NEW,
	NVME_CTRL_LIVE,
	NVME_CTRL_RESETTING,
	NVME_CTRL_RECONNECTING,
	NVME_CTRL_DELETING,
	NVME_CTRL_DEAD,
};

struct nvme_ctrl {
	enum nvme_ctrl_state state;
	spinlock_t lock;
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct request_queue *connect_q;
	struct device *dev;
	struct kref kref;
	int instance;
	struct blk_mq_tag_set *tagset;
	struct list_head namespaces;
	struct mutex namespaces_mutex;
	struct device *device;	/* char device */
	struct list_head node;
	struct ida ns_ida;

	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];
	u16 cntlid;

	u32 ctrl_config;

	u32 page_size;
	u32 max_hw_sectors;
	u32 stripe_size;
	u16 oncs;
	u16 vid;
	atomic_t abort_limit;
	u8 event_limit;
	u8 vwc;
	u32 vs;
	u32 sgls;
	u16 kas;
	unsigned int kato;
	bool subsystem;
	unsigned long quirks;
	struct work_struct scan_work;
	struct work_struct async_event_work;
	struct delayed_work ka_work;

	/* Fabrics only */
	u16 sqsize;
	u32 ioccsz;
	u32 iorcsz;
	u16 icdoff;
	u16 maxcmd;
	struct nvmf_ctrl_options *opts;
};

/*
 * An NVM Express namespace is equivalent to a SCSI LUN
 */
struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct nvm_dev *ndev;
	struct kref kref;
	int instance;

	u8 eui[8];
	u8 uuid[16];

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	bool ext;
	u8 pi_type;
	unsigned long flags;

#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1

	u64 mode_select_num_blocks;
	u32 mode_select_block_len;
};

/*
 * Represents an NVM Express device.  Each nvme_dev is a PCI function.
 */
struct nvme_dev {
	struct nvme_queue **queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	void __iomem *bar;
	struct work_struct reset_work;
	struct work_struct remove_work;
	struct timer_list watchdog_timer;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	u64 cmb_size;
	u32 cmbsz;
	u32 cmbloc;
	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
};

#endif // KERN_490

#ifdef KERN_4100
enum nvme_ctrl_state {
	NVME_CTRL_NEW,
	NVME_CTRL_LIVE,
	NVME_CTRL_RESETTING,
	NVME_CTRL_RECONNECTING,
	NVME_CTRL_DELETING,
	NVME_CTRL_DEAD,
};

struct nvme_ctrl {
	enum nvme_ctrl_state state;
	spinlock_t lock;
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct request_queue *connect_q;
	struct device *dev;
	struct kref kref;
	int instance;
	struct blk_mq_tag_set *tagset;
	struct list_head namespaces;
	struct mutex namespaces_mutex;
	struct device *device;	/* char device */
	struct list_head node;
	struct ida ns_ida;

	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];
	u16 cntlid;

	u32 ctrl_config;

	u32 page_size;
	u32 max_hw_sectors;
	u16 oncs;
	u16 vid;
	atomic_t abort_limit;
	u8 event_limit;
	u8 vwc;
	u32 vs;
	u32 sgls;
	u16 kas;
	unsigned int kato;
	bool subsystem;
	unsigned long quirks;
	struct work_struct scan_work;
	struct work_struct async_event_work;
	struct delayed_work ka_work;

	/* Fabrics only */
	u16 sqsize;
	u32 ioccsz;
	u32 iorcsz;
	u16 icdoff;
	u16 maxcmd;
	struct nvmf_ctrl_options *opts;
};

/*
 * An NVM Express namespace is equivalent to a SCSI LUN
 */
struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct nvm_dev *ndev;
	struct kref kref;
	int instance;

	u8 eui[8];
	u8 uuid[16];

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	bool ext;
	u8 pi_type;
	unsigned long flags;

#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1

	u64 mode_select_num_blocks;
	u32 mode_select_block_len;
};
/*
 * Represents an NVM Express device.  Each nvme_dev is a PCI function.
 */
struct nvme_dev {
	struct nvme_queue **queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	void __iomem *bar;
	struct work_struct reset_work;
	struct work_struct remove_work;
	struct timer_list watchdog_timer;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	u64 cmb_size;
	u32 cmbsz;
	u32 cmbloc;
	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
};

#endif // KERN_4100

#ifdef KERN_4110
enum nvme_ctrl_state {
	NVME_CTRL_NEW,
	NVME_CTRL_LIVE,
	NVME_CTRL_RESETTING,
	NVME_CTRL_RECONNECTING,
	NVME_CTRL_DELETING,
	NVME_CTRL_DEAD,
};

struct nvme_ctrl {
	enum nvme_ctrl_state state;
	bool identified;
	spinlock_t lock;
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct request_queue *connect_q;
	struct device *dev;
	struct kref kref;
	int instance;
	struct blk_mq_tag_set *tagset;
	struct list_head namespaces;
	struct mutex namespaces_mutex;
	struct device *device;	/* char device */
	struct list_head node;
	struct ida ns_ida;

	struct opal_dev *opal_dev;

	char name[12];
	char serial[20];
	char model[40];
	char firmware_rev[8];
	u16 cntlid;

	u32 ctrl_config;

	u32 page_size;
	u32 max_hw_sectors;
	u16 oncs;
	u16 vid;
	u16 oacs;
	atomic_t abort_limit;
	u8 event_limit;
	u8 vwc;
	u32 vs;
	u32 sgls;
	u16 kas;
	u8 npss;
	u8 apsta;
	unsigned int kato;
	bool subsystem;
	unsigned long quirks;
	//struct nvme_id_power_state psd[32];
	struct work_struct scan_work;
	struct work_struct async_event_work;
	struct delayed_work ka_work;

	/* Power saving configuration */
	u64 ps_max_latency_us;

	/* Fabrics only */
	u16 sqsize;
	u32 ioccsz;
	u32 iorcsz;
	u16 icdoff;
	u16 maxcmd;
	struct nvmf_ctrl_options *opts;
};

/*
 * An NVM Express namespace is equivalent to a SCSI LUN
 */
struct nvme_ns {
	struct list_head list;

	struct nvme_ctrl *ctrl;
	struct request_queue *queue;
	struct gendisk *disk;
	struct nvm_dev *ndev;
	struct kref kref;
	int instance;

	u8 eui[8];
	u8 uuid[16];

	unsigned ns_id;
	int lba_shift;
	u16 ms;
	bool ext;
	u8 pi_type;
	unsigned long flags;

#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD     1

	u64 mode_select_num_blocks;
	u32 mode_select_block_len;
};

/*
 * Represents an NVM Express device.  Each nvme_dev is a PCI function.
 */
struct nvme_dev {
	struct nvme_queue **queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned queue_count;
	unsigned online_queues;
	unsigned max_qid;
	int q_depth;
	u32 db_stride;
	void __iomem *bar;
	struct work_struct reset_work;
	struct work_struct remove_work;
	struct timer_list watchdog_timer;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	dma_addr_t cmb_dma_addr;
	u64 cmb_size;
	u32 cmbsz;
	u32 cmbloc;
	struct nvme_ctrl ctrl;
	struct completion ioq_wait;
};
#endif // KERNL_4110

#endif //_NVMED_NVME_HEADER_H
