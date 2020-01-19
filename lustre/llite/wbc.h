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

enum lu_mkdir_policy {
	MKDIR_POL_REINT,
	MKDIR_POL_INTENT,
	MKDIR_POL_EXCL,
};

#define LPROCFS_WR_WBC_MAX_CMD 4096

#define WBC_MAX_RPCS		100
#define WBC_DEFAULT_MAX_RPCS	0

enum wbc_remove_policy {
	WBC_RMPOL_NONE,
	WBC_RMPOL_SYNC,
	WBC_RMPOL_DEFAULT = WBC_RMPOL_SYNC,
};

struct wbc_conf {
	enum lu_wbc_cache_mode	wbcc_cache_mode;
	enum lu_wbc_flush_mode	wbcc_flush_mode;
	enum wbc_remove_policy	wbcc_rmpol;
	__u32			wbcc_max_rpcs;
	__u32			wbcc_background_async_rpc:1,
				wbcc_batch_update;
	/* How many inodes are allowed. */
	unsigned long		wbcc_max_inodes;
	/* How many inodes are left for allocation. */
	unsigned long		wbcc_free_inodes;
	/* How many blocks are allowed. */
	unsigned long		wbcc_max_blocks;
	/* How many blocks are allocated. */
	struct percpu_counter	wbcc_used_blocks;
};

struct wbc_super {
	spinlock_t		 wbcs_lock;
	__u64			 wbcs_generation;
	struct wbc_conf		 wbcs_conf;
	struct dentry		*wbcs_debugfs_dir;
	struct list_head	 wbcs_roots;
	struct list_head	wbcs_lazy_roots;
};

/* Extend for the data structure writeback_control */
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
	unsigned unused_bit0:1,
		 unused_bit1:1,
		 unused_bit2:1,
		 unused_bit3:1,
		 unused_bit4:1,
		 unused_bit5:1,
		 unused_bit6:1,
		 unused_bit7:1;
};

struct wbc_inode {
	__u32			wbci_flags;
	/*
	 * Cache mode and flush mode should be a command information shared
	 * by the whole subtree under the root WBC directory.
	 */
	enum lu_wbc_cache_mode	wbci_cache_mode;
	enum lu_wbc_flush_mode	wbci_flush_mode;
	enum lu_wbc_dirty_flags	wbci_dirty_flags;
	unsigned int		wbci_dirty_attr;
	struct list_head	wbci_root_list;
	struct lustre_handle	wbci_lock_handle;
	struct rw_semaphore	wbci_rw_sem;
};

struct wbc_dentry {
	struct list_head	wbcd_flush_item;
	struct list_head	wbcd_fsync_item;
};

enum wbc_cmd_type {
	WBC_CMD_DISABLE = 0,
	WBC_CMD_ENABLE,
	WBC_CMD_CONFIG,
	WBC_CMD_CHANGE,
	WBC_CMD_CLEAR,
};

enum wbc_cmd_op {
	WBC_CMD_OP_CACHE_MODE	= 0x01,
	WBC_CMD_OP_FLUSH_MODE	= 0x02,
	WBC_CMD_OP_MAX_RPCS	= 0x04,
	WBC_CMD_OP_RMPOL	= 0x08,
	WBC_CMD_OP_INODES_LIMIT	= 0x10,
	WBC_CMD_OP_BLOCKS_LIMIT	= 0x20,
	WBC_CMD_OP_DECOMPLETE	= 0x40,
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

static inline bool wbc_inode_attr_dirty(struct wbc_inode *wbci)
{
	return wbci->wbci_dirty_flags & WBC_DIRTY_FL_ATTR;
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

/* wbc.c */
void wbc_super_root_add(struct inode *inode);
void wbc_super_root_del(struct inode *inode);
int wbc_reserve_inode(struct wbc_super *super);
void wbc_unreserve_inode(struct inode *inode);
void wbc_free_inode(struct inode *inode);
void wbc_inode_unreserve_dput(struct inode *inode, struct dentry *dentry);
long wbc_flush_opcode_get(struct inode *inode, struct dentry *dchild,
			  struct writeback_control_ext *wbcx,
			  unsigned int *valid);
long wbc_flush_opcode_data_lockless(struct inode *inode, unsigned int *valid,
				    struct writeback_control_ext *wbcx);
void wbc_inode_writeback_complete(struct inode *inode);
int wbc_make_inode_sync(struct dentry *dentry);
int wbc_make_inode_deroot(struct inode *inode, struct ldlm_lock *lock,
			  struct writeback_control_ext *wbcx);
int wbc_make_inode_decomplete(struct inode *inode);
int wbc_super_init(struct wbc_super *super);
void wbc_super_fini(struct wbc_super *super);
void wbc_inode_init(struct wbc_inode *wbci);
void wbc_dentry_init(struct dentry *dentry);
int wbc_cmd_handle(struct wbc_super *super, struct wbc_cmd *cmd);
int wbc_cmd_parse_and_handle(char *buffer, unsigned long count,
			     struct wbc_super *super);

/* memfs.c */
void wbc_inode_operations_set(struct inode *inode, umode_t mode, dev_t dev);

/* llite_wbc.c */
void wbcfs_inode_operations_switch(struct inode *inode);
int wbcfs_d_init(struct dentry *de);
int wbc_do_setattr(struct inode *inode, unsigned int valid);
int wbc_do_remove(struct inode *dir, struct dentry *dchild, bool rmdir);
int wbcfs_commit_cache_pages(struct inode *inode);
int wbcfs_inode_flush_lockless(struct inode *inode,
			       struct writeback_control_ext *wbcx);
int wbcfs_flush_dir_children(struct inode *dir,
			     struct list_head *childlist,
			     struct ldlm_lock *lock,
			     struct writeback_control_ext *wbcx);

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
