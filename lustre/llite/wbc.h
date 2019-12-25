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

#define WBC_MAX_ASYNC_RPCS	100

struct wbc_conf {
	enum lu_wbc_cache_mode	wbcc_cache_mode;
	enum lu_wbc_flush_mode	wbcc_flush_mode;
	__u32			wbcc_max_rpcs;
};

struct wbc_super {
	spinlock_t	 wbcs_lock;
	__u64		 wbcs_generation;
	struct wbc_conf	 wbcs_conf;
	struct dentry	*wbcs_debugfs_dir;
};

struct wbc_inode {
	__u32			wbci_flags;
	/*
	 * Cache mode and flush mode should be a command information shared
	 * by the whole subtree under the root WBC directory.
	 */
	enum lu_wbc_cache_mode	wbci_cache_mode;
	enum lu_wbc_flush_mode	wbci_flush_mode;
	struct lustre_handle	wbci_lock_handle;
};

struct wbc_dentry {
	struct list_head	wbcd_flush_item;
};

enum wbc_cmd_type {
	WBC_CMD_DISABLE = 0,
	WBC_CMD_ENABLE,
	WBC_CMD_CONFIG,
};

enum wbc_cmd_op {
	WBC_CMD_OP_CACHE_MODE	= 0x1,
	WBC_CMD_OP_FLUSH_MODE	= 0x2,
	WBC_CMD_OP_MAX_RPCS	= 0x4,
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

static inline bool wbc_inode_has_protected(struct wbc_inode *wbci)
{
	return wbci->wbci_flags & WBC_STATE_FL_PROTECTED;
}

/* wbc.c */
void wbc_super_init(struct wbc_super *super);
void wbc_inode_init(struct wbc_inode *wbci);
void wbc_dentry_init(struct dentry *dentry);
int wbc_cmd_handle(struct wbc_super *super, struct wbc_cmd *cmd);
int wbc_cmd_parse_and_handle(char *buffer, unsigned long count,
			     struct wbc_super *super);
int wbc_inode_flush(struct inode *inode, struct ldlm_lock *lock);

/* memfs.c */
void wbc_inode_operations_set(struct inode *inode, umode_t mode, dev_t dev);

/* llite_wbc.c */
void wbcfs_inode_operations_switch(struct inode *inode);
int wbcfs_d_init(struct dentry *de);
int wbcfs_commit_cache_pages(struct inode *inode);
int wbcfs_flush_dir_children(struct inode *dir,
			     struct list_head *childlist,
			     struct ldlm_lock *lock);
void wbc_tunables_init(struct super_block *sb);
void wbc_tunables_fini(struct super_block *sb);
long wbc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
void wbc_inode_lock_callback(struct inode *inode, struct ldlm_lock *lock,
			     bool *cached);
int wbc_root_init(struct inode *dir, struct inode *inode,
		  struct dentry *dentry);

int wbc_write_inode(struct inode *inode, struct writeback_control *wbc);
enum lu_mkdir_policy
ll_mkdir_policy_get(struct ll_sb_info *sbi, struct inode *dir,
		    struct dentry *dchild, umode_t mode,
		    __u64 *extra_lock_flags);
#endif /* LLITE_WBC_H */
