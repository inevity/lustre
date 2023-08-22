/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * LGPL version 2.1 or (at your discretion) any later version.
 * LGPL version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 * Copyright (c) 2019, DDN Storage Corporation.
 */
/*
 * lustre/llite/wbc.h
 *
 * Lustre Metadata Writeback Caching (WBC)
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#ifndef LLITE_WBC_H
#define LLITE_WBC_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <uapi/linux/lustre/lustre_user.h>
#include <obd_rule.h>

enum lu_mkdir_policy {
  //cached
	MKDIR_POL_REINT,
  //clientserver mode
	MKDIR_POL_INTENT,
  //exc
  //POL policy
	MKDIR_POL_EXCL,
};

#define LPROCFS_WR_WBC_MAX_CMD 4096

#define WBC_MAX_RPCS		100
#define WBC_DEFAULT_MAX_RPCS	0

#define WBC_DEFAULT_MAX_QLEN	8192

#define WBC_DEFAULT_MAX_NRPAGES_PER_FILE	ULONG_MAX

enum wbc_remove_policy {
	WBC_RMPOL_NONE,
	WBC_RMPOL_SYNC,
	WBC_RMPOL_DEFAULT = WBC_RMPOL_SYNC,
};

/*
 * Under the protection of the root EX WBC lock, the open()/close() system
 * call does not need to communicate with MDS, can be executed locally in MemFS
 * on the client.
 * However, Lustre is a stateful filesystem. Each open keeps a certain state
 * on the MDS. WBC feature should keep transparency for applications. To
 * achieve this goal, it must reopen the non-closed files from MDS when the
 * root EX WBC lock is revoking.
 * WBC defines a Complete(C) state flag. It means:
 * - The directory or file is cached in MemFS;
 * - The directory or file is under the protection of a root EX WBC lock;
 * - The directory contains the Complete children subdirs;
 * - Results of readdir() and lookup() operations under this directory can
 *   directly be obtained from client-side MemFS. All metadata operations
 *   can be performed on MemFS without communication with the server.
 * For directories, it needs to be handled specially for the readdir() call
 * once it has opened.
 * Currently the mechanism adopted by MemFS (tmpfs) is to simply scan the
 * in-memory children dentries of the directory in dcache linearly to fill the
 * content returned to readdir call: ->dcache_readdir().
 * While Lustre new readdir implementation is much complex. It does readdir in
 * hash order and uses hash of a file name as a telldir/seekdir cookie stored
 * in the file handle.
 * Thus, it would better to bridge two implementation for readdir() call
 * carefully.
 */
enum wbc_readdir_policy {
	/*
	 * For benchmark only, use dcache_readdir() to read dentries from
	 * dcache linearly. It may read repeated or inconsistent dentries.
	 * It contains Lustre special private file data for compatibility.
	 */
	WBC_READDIR_DCACHE_COMPAT	= 1,
	/*
	 * In this policy, the sum size of all children dentries is kept
	 * accouts when create/remove a file under a directory.
	 * For small directories, it will call dcache_readdir() to read all
	 * entries in one blow if the buffer size the caller provided is large
	 * enough to fill all entries.
	 * If a directory is too large to fill all dentries in a blow, it will
	 * decomplete the directory, which means that flush all children
	 * dentries to MDT and unmask Complete(C) flag from the directory.
	 * And then it will read the children dentries from MDT in hash order.
	 */
	WBC_READDIR_DCACHE_DECOMPLETE	= 2,
	/*
	 * Build the hashed index rbtree during readdir() call in runtime,
	 * return the dentries in hash order. Upon closing the file, destroy
	 * the hashed index rbtree.
	 */
	WBC_READDIR_HTREE_RUNTIME	= 3,
	/*
	 * Use hashed index rbtree sorting according to the hash of file name.
	 * It is resident in memory for th whole life of the directory.
	 */
	WBC_READDIR_HTREE_RESIDENT	= 4,
	/* Default readdir policy. */
	WBC_READDIR_POL_DEFAULT		= WBC_READDIR_DCACHE_COMPAT,
};

enum wbc_flush_policy {
	WBC_FLUSH_POL_RQSET	= 0,
	WBC_FLUSH_POL_BATCH	= 1,
	WBC_FLUSH_POL_PTLRPCD	= 2,
	WBC_FLUSH_POL_DEFAULT	= WBC_FLUSH_POL_PTLRPCD,
};

enum wbc_dop_policy {
	/*
	 * Instantiate the file with HSM released state and create the
	 * corresponding PCC copy at the time of flushing the file.
	 */
	WBC_DOP_AT_FLUSH	= 0,
	/*
	 * When the number of cache pages in MemFS for the file is increasing
	 * exceed a certain threshold (i.e. 1GiB), instantiate the PCC copy.
	 */
	WBC_DOP_AT_WRITE	= 1,
	/*
	 * Delay to instantiate the PCC copy until commit the cache pages.
	 */
	WBC_DOP_AT_COMMIT	= 2,
	WBC_DOP_DEFAULT		= WBC_DOP_AT_FLUSH,
};

#define WBC_DEFAULT_HIWM_RATIO	0	/* Disable reclaimation. */

struct wbc_conf {
	enum lu_wbc_cache_mode	wbcc_cache_mode;
	enum lu_wbc_flush_mode	wbcc_flush_mode;
	enum wbc_remove_policy	wbcc_rmpol;
	enum wbc_readdir_policy	wbcc_readdir_pol;
	enum wbc_flush_policy	wbcc_flush_pol;

	__u32			wbcc_max_batch_count;
	__u32			wbcc_max_rpcs;
	__u32			wbcc_max_qlen;
	/*
	 * Threshold to control when to commit cache pages into persistent
	 * storage (Lustre OSTs or PCC).
	 */
	unsigned long		wbcc_max_nrpages_per_file;
	__u32			wbcc_background_async_rpc:1;
	/* Not instantiate layout during creation in batched RPCs. */
	bool			wbcc_batch_no_layout;
	/* How many inodes are allowed. */
	unsigned long		wbcc_max_inodes;
	/* How many inodes are left for allocation. */
	unsigned long		wbcc_free_inodes;
	/* How many pages are allowed. */
	unsigned long		wbcc_max_pages;
	/* How many pages are allocated. */
	struct percpu_counter	wbcc_used_pages;
	/*
	 * As a percentage of the total cache in MemFS, the number of caches
	 * at which the WBC reclaimer begins writeback of dirty data to reclaim
	 * space in MemFS.
	 */
	int			wbcc_hiwm_ratio; /* High watermark. */
	__u32			wbcc_hiwm_inodes_count;
	__u32			wbcc_hiwm_pages_count;

	/*
	 * Check the inode space of each MDT to determine whether cache the
	 * file on the client. When the inode space of one MDT is less than
	 * this value, the client will stop to cache the newly creating file
	 * under WBC. When set this value with 0, the client will skip this
	 * check.
	 */
	__u64			wbcc_mdt_iavail_low;

	/* Auto writeback caching rule */
  //cofngi filesystem rule
	struct cfs_rule		wbcc_rule;
};

struct wbc_super {
	spinlock_t		 wbcs_lock;
	__u64			 wbcs_generation;
	struct wbc_conf		 wbcs_conf;
	struct dentry		*wbcs_debugfs_dir;
  //
	struct list_head	 wbcs_roots;
	// if (wbc_flush_mode_lazy(wbci))
	struct list_head	 wbcs_lazy_roots;

	/* For cache shrinking and reclaimation. */
	/* LRU list head for reserved inodes. */
	struct list_head	 wbcs_rsvd_inode_lru;
	struct list_head	 wbcs_data_inode_lru;
	spinlock_t		 wbcs_data_lru_lock;
	struct task_struct	*wbcs_reclaim_task;
};

/* Anchor for synchronous transfer. */
struct wbc_sync_io {
	/** number of metadata updates yet to be transferred. */
	atomic_t		wsi_sync_nr;
	/** error code. */
	int			wsi_sync_rc;
	/** completion to be signaled when transfer is complete. */
	wait_queue_head_t	wsi_waitq;
};

union wbc_engine {
	struct lu_batch			*ioe_batch;
	struct ptlrpc_request_set	*ioe_rqset;
};

struct wbc_context {
	unsigned int		ioc_inited:1;
	unsigned int		ioc_sync:1;
	unsigned int		ioc_anchor_used:1;
	enum wbc_flush_policy	ioc_pol;
	struct wbc_sync_io	ioc_anchor;
	union wbc_engine	ioc_engine;
};

#define ioc_batch	ioc_engine.ioe_batch
#define ioc_rqset	ioc_engine.ioe_rqset

/* Extend for the data structure writeback_control in Linux kernel */
struct writeback_control_ext {
	long nr_to_write;		/* Write this many pages, and decrement
					   this for each page written */
	long pages_skipped;		/* Pages which were not written */

	/*
	 * For a_ops->writepages(): if start or end are non-zero then this is
	 * a hint that the filesystem need only write out the pages inside that
	 * byterange.  The byte at `end' is included in the writeout request.
	 */
	loff_t range_start;
	loff_t range_end;

	enum writeback_sync_modes sync_mode;

	unsigned for_kupdate:1;		/* A kupdate writeback */
	unsigned for_background:1;	/* A background writeback */
	unsigned tagged_writepages:1;	/* tag-and-write to avoid livelock */
	unsigned for_reclaim:1;		/* Invoked from the page allocator */
	unsigned range_cyclic:1;	/* range_start is cyclic */
	unsigned for_sync:1;		/* sync(2) WB_SYNC_ALL writeback */
	/*
	 * When writeback IOs are bounced through async layers, only the
	 * initial synchronous phase should be accounted towards inode
	 * cgroup ownership arbitration to avoid confusion.  Later stages
	 * can set the following flag to disable the accounting.
	 */
	unsigned no_cgroup_owner:1;
	unsigned punt_to_cgroup:1;	/* cgrp punting, see __REQ_CGROUP_PUNT */
	unsigned for_fsync:1;		/* fsync(2) WB_SYNC_ALL writeback */
	unsigned for_callback:1;	/* conflict DLM lock callback */
	unsigned for_decomplete:1;	/* decomplete a WBC directory */
	/* Unreserve all children from inode limit when decomplete parent. */
	unsigned unrsv_children_decomp:1;
	unsigned has_ext:1;
	unsigned unused_bit0:1,
		 unused_bit1:1,
		 unused_bit2:1,
		 unused_bit3:1,
		 unused_bit4:1,
		 unused_bit5:1,
		 unused_bit6:1,
		 unused_bit7:1;

#ifdef CONFIG_CGROUP_WRITEBACK
	struct bdi_writeback *wb;	/* wb this writeback is issued under */
	struct inode *inode;		/* inode being written out */

	/* foreign inode detection, see wbc_detach_inode() */
	int wb_id;			/* current wb id */
	int wb_lcand_id;		/* last foreign candidate wb id */
	int wb_tcand_id;		/* this foreign candidate wb id */
	size_t wb_bytes;		/* bytes written by current wb */
	size_t wb_lcand_bytes;		/* bytes written by last candidate */
	size_t wb_tcand_bytes;		/* bytes written by this candidate */
#endif
};


struct wbc_inode {
	__u32			wbci_flags;
	/* Archive ID of PCC backend to store Data on PCC (DOP) */
	__u32			wbci_archive_id;
	/*
	 * Cache mode and flush mode should be a command information shared
	 * by the whole subtree under the root WBC directory.
	 */
	enum lu_wbc_cache_mode	wbci_cache_mode;
	enum lu_wbc_flush_mode	wbci_flush_mode;
	enum lu_wbc_dirty_flags	wbci_dirty_flags;
	unsigned int		wbci_dirty_attr;
	struct list_head	wbci_root_list;
	struct list_head	wbci_rsvd_lru;
	struct list_head	wbci_data_lru;
	struct lustre_handle	wbci_lock_handle;
	struct rw_semaphore	wbci_rw_sem;
};

struct wbc_dentry {
	struct list_head	wbcd_flush_item;
	struct list_head	wbcd_fsync_item;
	struct list_head	wbcd_open_files;
	spinlock_t		wbcd_open_lock;
	__u32			wbcd_dirent_num;
};

struct wbc_file {
	struct list_head	 wbcf_open_item;
	enum wbc_readdir_policy	 wbcf_readdir_pol;
	void			*wbcf_private_data;
	bool			 wbcf_fail_evicted;
};

enum wbc_cmd_type {
	WBC_CMD_DISABLE = 0,
	WBC_CMD_ENABLE,
	WBC_CMD_CONFIG,
	WBC_CMD_CHANGE,
	WBC_CMD_CLEAR,
	WBC_CMD_RULE_SET,
	WBC_CMD_RULE_CLEAR,
};

enum wbc_cmd_op {
	WBC_CMD_OP_CACHE_MODE		= 0x0001,
	WBC_CMD_OP_FLUSH_MODE		= 0x0002,
	WBC_CMD_OP_MAX_RPCS		= 0x0004,
	WBC_CMD_OP_RMPOL		= 0x0008,
	WBC_CMD_OP_INODES_LIMIT		= 0x0010,
	WBC_CMD_OP_PAGES_LIMIT		= 0x0020,
	WBC_CMD_OP_READDIR_POL		= 0x0040,
	WBC_CMD_OP_RECLAIM_RATIO	= 0x0080,
	WBC_CMD_OP_FLUSH_POL		= 0x0100,
	WBC_CMD_OP_MAX_BATCH_COUNT	= 0x0200,
	WBC_CMD_OP_MAX_QLEN		= 0x0400,
	WBC_CMD_OP_BATCH_NO_LAYOUT	= 0x0800,
	WBC_CMD_OP_MAX_NRPAGES_PER_FILE	= 0x1000,
	WBC_CMD_OP_MDT_IAVAIL_LOW	= 0x2000,
};

struct wbc_cmd {
	__u32			wbcc_flags;
	enum wbc_cmd_type	wbcc_cmd;
	struct wbc_conf		wbcc_conf;
};

#ifdef FMODE_CREATED /* added in Linux v4.18-rc1-20-g73a09dd */
# define ll_is_opened(o, f)		((f)->f_mode & FMODE_OPENED)
# define ll_finish_open(f, d, o)	finish_open((f), (d), NULL)
# define ll_last_arg
# define ll_set_created(o, f)						\
do {									\
	(f)->f_mode |= FMODE_CREATED;					\
} while (0)

#else
# define ll_is_opened(o, f)		(*(o))
# define ll_finish_open(f, d, o)	finish_open((f), (d), NULL, (o))
# define ll_last_arg			, int *opened
# define ll_set_created(o, f)						\
do {									\
	*(o) |= FILE_CREATED;						\
} while (0)

#endif

static inline bool md_opcode_need_exlock(enum md_item_opcode opc)
{
	return opc == MD_OP_CREATE_EXLOCK || opc == MD_OP_SETATTR_EXLOCK ||
	       opc == MD_OP_EXLOCK_ONLY;
}

static inline bool wbc_cache_mode_mem(struct wbc_inode *wbci)
{
	return wbci->wbci_cache_mode == WBC_MODE_MEMFS;
}

static inline bool wbc_cache_mode_dop(struct wbc_inode *wbci)
{
	return wbci->wbci_cache_mode == WBC_MODE_DATA_PCC;
}

static inline bool wbc_mode_lock_drop(struct wbc_inode *wbci)
{
	return wbci->wbci_flush_mode == WBC_FLUSH_AGING_DROP ||
	       wbci->wbci_flush_mode == WBC_FLUSH_LAZY_DROP;
}

static inline bool wbc_mode_lock_keep(struct wbc_inode *wbci)
{
	return wbci->wbci_flush_mode == WBC_FLUSH_AGING_KEEP ||
	       wbci->wbci_flush_mode == WBC_FLUSH_LAZY_KEEP;
}

static inline bool wbc_flush_mode_lazy(struct wbc_inode *wbci)
{
	return wbci->wbci_flush_mode == WBC_FLUSH_LAZY_DROP ||
	       wbci->wbci_flush_mode == WBC_FLUSH_LAZY_KEEP;
}

static inline bool wbc_flush_mode_aging(struct wbc_inode *wbci)
{
	return wbci->wbci_flush_mode == WBC_FLUSH_AGING_DROP ||
	       wbci->wbci_flush_mode == WBC_FLUSH_AGING_KEEP;
}

static inline bool wbc_inode_has_protected(struct wbc_inode *wbci)
{
  //FL mean flag
	return wbci->wbci_flags & WBC_STATE_FL_PROTECTED;
}

static inline bool wbc_inode_complete(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_COMPLETE;
}

static inline bool wbc_inode_none(struct wbc_inode *wbci)
{
	return wbci->wbci_flags == WBC_STATE_FL_NONE;
}

static inline bool wbc_inode_reserved(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_INODE_RESERVED;
}

static inline bool wbc_inode_data_committed(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_DATA_COMMITTED;
}

static inline bool wbc_inode_assimilated(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_DATA_COMMITTED;
}

static inline bool wbc_inode_dop_assimilated(struct wbc_inode *wbci)
{
	return wbc_cache_mode_dop(wbci) && wbc_inode_assimilated(wbci);
}

static inline bool wbc_inode_data_caching(struct wbc_inode *wbci)
{
	return wbc_inode_has_protected(wbci) && !wbc_inode_data_committed(wbci);
}

static inline bool wbc_inode_root(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_ROOT;
}

static inline bool wbc_inode_was_flushed(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_SYNC;
}

/* The file metadata was written out to the server. */
static inline bool wbc_inode_written_out(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_SYNC ||
	       wbci->wbci_flags == WBC_STATE_FL_NONE;
}

static inline bool wbc_inode_error(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_ERROR;
}

static inline bool wbc_inode_evicted(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_EVICTED;
}

static inline bool wbc_inode_attr_dirty(struct wbc_inode *wbci)
{
	return wbci->wbci_dirty_flags == WBC_DIRTY_FL_ATTR;
}

static inline bool wbc_decomplete_lock_keep(struct wbc_inode *wbci,
					    struct writeback_control_ext *wbcx)
{
	return wbcx->for_decomplete && wbc_mode_lock_keep(wbci);
}

static inline enum mds_op_bias wbc_md_op_bias(struct wbc_inode *wbci)
{
	return wbc_inode_has_protected(wbci) ? MDS_WBC_LOCKLESS : 0;
}

static inline __u64 wbc_intent_lock_flags(struct wbc_inode *wbci,
					  struct lookup_intent *it)
{
	if (wbc_inode_has_protected(wbci)) {
		LASSERT((it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR) &&
			!wbc_inode_complete(wbci));
		return LDLM_FL_INTENT_PARENT_LOCKED;
	}
	return 0;
}

static inline const char *wbc_rmpol2string(enum wbc_remove_policy pol)
{
	switch (pol) {
	case WBC_RMPOL_SYNC:
		return "sync";
	default:
		return "unknow";
	}
}

static inline const char *wbc_readdir_pol2string(enum wbc_readdir_policy pol)
{
	switch (pol) {
	case WBC_READDIR_DCACHE_COMPAT:
		return "dcache_compat";
	case WBC_READDIR_DCACHE_DECOMPLETE:
		return "dcache_decomp";
	default:
		return "unknow";
	}
}

static inline const char *wbc_flushpol2string(enum wbc_flush_policy pol)
{
	switch (pol) {
	case WBC_FLUSH_POL_RQSET:
		return "rqset";
	case WBC_FLUSH_POL_BATCH:
		return "batch";
	case WBC_FLUSH_POL_PTLRPCD:
		return "ptlrpcd";
	default:
		return "unknow";
	}
}

static inline bool wbc_cache_too_much_inodes(struct wbc_conf *conf)
{
	if (conf->wbcc_hiwm_ratio)
		return conf->wbcc_max_inodes - conf->wbcc_free_inodes >
		       conf->wbcc_hiwm_inodes_count;
	return false;
}

static inline bool wbc_cache_too_much_pages(struct wbc_conf *conf)
{
	if (conf->wbcc_hiwm_ratio)
		return percpu_counter_compare(&conf->wbcc_used_pages,
					      conf->wbcc_hiwm_pages_count) > 0;
	return false;
}

/* wbc.c */
void wbc_super_root_add(struct inode *inode);
void wbc_super_root_del(struct inode *inode);
int wbc_reserve_inode(struct wbc_super *super);
void wbc_unreserve_inode(struct inode *inode);
void wbc_reserved_inode_lru_add(struct inode *inode);
void wbc_reserved_inode_lru_del(struct inode *inode);
void wbc_inode_data_lru_add(struct inode *inode, struct file *file);
void wbc_inode_data_lru_del(struct inode *inode);
void wbc_free_inode(struct inode *inode);
void wbc_inode_unreserve_dput(struct inode *inode, struct dentry *dentry);
void wbc_sync_io_init(struct wbc_sync_io *anchor, int nr);
int wbc_sync_io_wait(struct wbc_sync_io *anchor, long timeout);
void wbc_sync_io_note(struct wbc_sync_io *anchor, int ioret);
long wbc_flush_opcode_get(struct inode *inode, struct dentry *dchild,
			  struct writeback_control_ext *wbcx,
			  unsigned int *valid, __u32 *dirty_flags);
void wbc_inode_writeback_complete(struct inode *inode);
int wbc_make_inode_sync(struct dentry *dentry);
int wbc_make_inode_deroot(struct inode *inode, struct ldlm_lock *lock,
			  struct writeback_control_ext *wbcx);
int wbc_make_subtree_deroot(struct dentry *dentry);
int wbc_make_inode_decomplete(struct inode *inode, unsigned int unrsv_children);
int wbc_make_dir_decomplete(struct inode *dir, struct dentry *parent,
			    unsigned int unrsv_children);
int wbc_make_data_commit(struct dentry *dentry);
int wbc_make_inode_assimilated(struct inode *inode);
int wbc_super_init(struct wbc_super *super);
void wbc_super_fini(struct wbc_super *super);
void wbc_inode_init(struct wbc_inode *wbci);
void wbc_dentry_init(struct dentry *dentry);
int wbc_cmd_handle(struct wbc_super *super, struct wbc_cmd *cmd);
int wbc_cmd_parse_and_handle(char *buffer, unsigned long count,
			     struct wbc_super *super);
int wbc_rule_parse_and_handle(char *buffer, unsigned long count,
			      struct wbc_super *super);

/* memfs.c */
void wbc_inode_operations_set(struct inode *inode, umode_t mode, dev_t dev);
bool wbc_inode_acct_page(struct inode *inode, long nr_pages);
void wbc_inode_unacct_pages(struct inode *inode, long nr_pages);

/* llite_wbc.c */
void wbcfs_inode_operations_switch(struct inode *inode);
int wbcfs_d_init(struct dentry *de);
int wbc_do_setattr(struct inode *inode, unsigned int valid);
int wbc_flush_default_lsm_md(struct inode *inode);
int wbc_do_remove(struct inode *dir, struct dentry *dchild, bool rmdir);
int wbcfs_commit_cache_pages(struct inode *inode);
int wbcfs_inode_flush_lockless(struct inode *inode,
			       struct writeback_control_ext *wbcx);
int wbcfs_context_init(struct super_block *sb, struct wbc_context *ctx,
		       bool lazy_init);
int wbcfs_context_fini(struct super_block *sb, struct wbc_context *ctx);
int wbcfs_context_prepare(struct super_block *sb, struct wbc_context *ctx);
int wbcfs_context_commit(struct super_block *sb, struct wbc_context *ctx);
int wbcfs_flush_dir_child(struct wbc_context *ctx, struct inode *dir,
			  struct dentry *dchild, struct ldlm_lock *lock,
			  struct writeback_control_ext *wbcx, bool no_layout);
int wbcfs_file_open_local(struct inode *inode, struct file *file);
void wbcfs_file_release_local(struct inode *inode, struct file *file);
int wbcfs_dcache_dir_open(struct inode *inode, struct file *file);
int wbcfs_dcache_dir_close(struct inode *inode, struct file *file);
int wbcfs_setattr_data_object(struct inode *inode, struct iattr *attr);
void wbc_free_inode_pages_final(struct inode *inode,
				struct address_space *mapping);
bool wbc_file_fail_evicted(struct file *file);

void wbc_tunables_init(struct super_block *sb);
void wbc_tunables_fini(struct super_block *sb);
long wbc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
void wbc_inode_lock_callback(struct inode *inode, struct ldlm_lock *lock,
			     bool *cached);
int wbc_root_init(struct inode *dir, struct inode *inode,
		  struct dentry *dentry);

int wbc_write_inode(struct inode *inode, struct writeback_control *wbc);
int wbc_super_shrink_roots(struct wbc_super *super);
int wbc_super_sync_fs(struct wbc_super *super, int wait);
void wbc_free_inode(struct inode *inode);
void wbc_free_inode_pages_final(struct inode *inode,
				struct address_space *mapping);
void wbc_intent_inode_init(struct inode *dir, struct inode *inode,
			   struct lookup_intent *it);

int ll_new_inode_init(struct inode *dir, struct dentry *dchild,
		      struct inode *inode);
void ll_intent_inode_init(struct inode *dir, struct inode *inode,
			  struct lookup_intent *it);

enum lu_mkdir_policy
ll_mkdir_policy_get(struct ll_sb_info *sbi, struct inode *dir,
		    struct dentry *dchild, umode_t mode,
		    __u64 *extra_lock_flags);

#endif /* LLITE_WBC_H */
