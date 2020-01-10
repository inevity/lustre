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
 * Copyright (c) 2019-2021, DDN Storage Corporation.
 */
/*
 * lustre/llite/wbc.c
 *
 * Lustre Metadata Writeback Caching (WBC)
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/namei.h>
#include <linux/file.h>
#include <lustre_compat.h>
#include <linux/security.h>
#include <linux/swap.h>
#include "llite_internal.h"

void wbc_super_root_add(struct inode *inode)
{
	struct wbc_super *super = ll_i2wbcs(inode);
	struct wbc_inode *wbci = ll_i2wbci(inode);

	LASSERT(wbci->wbci_flags & WBC_STATE_FL_ROOT);
	spin_lock(&super->wbcs_lock);
	if (wbci->wbci_flush_mode == WBC_FLUSH_LAZY_KEEP ||
	    wbci->wbci_flush_mode == WBC_FLUSH_LAZY_DROP)
		list_add(&wbci->wbci_root_list, &super->wbcs_lazy_roots);
	else
		list_add(&wbci->wbci_root_list, &super->wbcs_roots);
	spin_unlock(&super->wbcs_lock);
}

void wbc_super_root_del(struct inode *inode)
{
	struct wbc_super *super = ll_i2wbcs(inode);
	struct wbc_inode *wbci = ll_i2wbci(inode);

	LASSERT(wbci->wbci_flags & WBC_STATE_FL_ROOT);
	spin_lock(&super->wbcs_lock);
	if (!list_empty(&wbci->wbci_root_list))
		list_del_init(&wbci->wbci_root_list);
	spin_unlock(&super->wbcs_lock);
}

/*
 * Wait for writeback on an inode to complete. Called with i_lock held.
 * Caller must make sure inode cannot go away when we drop i_lock.
 * linux/fs/fs-writeback.c
 */
static void __inode_wait_for_writeback(struct inode *inode)
	__releases(inode->i_lock)
	__acquires(inode->i_lock)
{
	DEFINE_WAIT_BIT(wq, &inode->i_state, __I_SYNC);
	wait_queue_head_t *wqh;

	wqh = bit_waitqueue(&inode->i_state, __I_SYNC);
	while (inode->i_state & I_SYNC) {
		spin_unlock(&inode->i_lock);
		__wait_on_bit(wqh, &wq, bit_wait,
			      TASK_UNINTERRUPTIBLE);
		spin_lock(&inode->i_lock);
	}
}

/*
 * Wait for writeback on an inode to complete. Caller must have inode pinned.
 * linux/fs/fs-writeback.c
 */
void inode_wait_for_writeback(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	__inode_wait_for_writeback(inode);
	spin_unlock(&inode->i_lock);
}

static void __wbc_inode_wait_for_writeback(struct inode *inode)
	__releases(inode->i_lock)
	__acquires(inode->i_lock)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	DEFINE_WAIT_BIT(wq, &wbci->wbci_flags, __WBC_STATE_FL_WRITEBACK);
	wait_queue_head_t *wqh;

	wqh = bit_waitqueue(&wbci->wbci_flags, __WBC_STATE_FL_WRITEBACK);
	while (wbci->wbci_flags & WBC_STATE_FL_WRITEBACK) {
		spin_unlock(&inode->i_lock);
		__wait_on_bit(wqh, &wq, bit_wait, TASK_UNINTERRUPTIBLE);
		spin_lock(&inode->i_lock);
	}
}

void wbc_inode_writeback_complete(struct inode *inode)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);

	wbci->wbci_flags &= ~WBC_STATE_FL_WRITEBACK;
	/*
	 * Waiters must see WBC_STATE_FL_WRITEBACK cleared before
	 * being woken up.
	 */
	smp_mb();
	wake_up_bit(&wbci->wbci_flags, __WBC_STATE_FL_WRITEBACK);
}

long wbc_flush_opcode_get(struct inode *dir, struct dentry *dchild,
			  struct ldlm_lock *lock, unsigned int *valid,
			  struct writeback_control_ext *wbcx)
{
	struct inode *inode = dchild->d_inode;
	struct wbc_inode *wbci = ll_i2wbci(inode);
	long opc = MD_OP_NONE;

	ENTRY;

	spin_lock(&inode->i_lock);
	switch (wbci->wbci_flush_mode) {
	case WBC_FLUSH_LAZY_KEEP:
		break;
	case WBC_FLUSH_AGING_DROP:
		LASSERT(!(inode->i_state & I_SYNC));
		break;
	case WBC_FLUSH_AGING_KEEP:
		if (inode->i_state & I_SYNC)
			__inode_wait_for_writeback(inode);

		LASSERT(!(inode->i_state & I_SYNC) && !wbcx->for_fsync);
		if (wbci->wbci_flags & WBC_STATE_FL_WRITEBACK)
			__wbc_inode_wait_for_writeback(inode);
		break;
	default:
		break;
	}

	/* The root WBC EX lock was revoked. */
	if (wbci->wbci_flags == WBC_STATE_FL_NONE)
		GOTO(out_unlock, opc);

	if (wbc_inode_was_flushed(wbci)) {
		if (wbci->wbci_dirty_flags & WBC_DIRTY_ATTR) {
			opc = MD_OP_SETATTR_EXLOCK;
			*valid = wbci->wbci_dirty_attr;
			wbci->wbci_dirty_attr = 0;
			wbci->wbci_dirty_flags = WBC_DIRTY_NONE;
		} else if (!(wbci->wbci_flags & WBC_STATE_FL_ROOT)) {
			opc = MD_OP_EXLOCK_ONLY;
		}
	} else {
		/*
		 * TODO: Update the metadata attributes on MDT together with
		 * the file creation.
		 */
		*valid = wbci->wbci_dirty_attr;
		wbci->wbci_dirty_attr = 0;
		wbci->wbci_dirty_flags = WBC_DIRTY_NONE;
		opc = MD_OP_CREATE_EXLOCK;
	}

	if (opc != MD_OP_NONE)
		wbci->wbci_flags |= WBC_STATE_FL_WRITEBACK;
out_unlock:
	spin_unlock(&inode->i_lock);

	RETURN(opc);
}

long wbc_flush_opcode_data_lockless(struct inode *inode, unsigned int *valid,
				    struct writeback_control_ext *wbcx)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	long opc = MD_OP_NONE;

	spin_lock(&inode->i_lock);
	LASSERT(inode->i_state & I_SYNC && !wbcx->for_callback);

	if (wbcx->for_fsync)
		LASSERT(wbci->wbci_flags & WBC_STATE_FL_WRITEBACK);
	else if (wbci->wbci_flags & WBC_STATE_FL_WRITEBACK)
		__wbc_inode_wait_for_writeback(inode);

	/*
	 * The inode was redirtied.
	 * TODO: handle more dirty flags: I_DIRTY_TIME | I_DIRTY_TIME_EXPIRED
	 * in the latest Linux kernel.
	 */
	if (inode->i_state & I_DIRTY) {
		inode->i_state &= ~I_DIRTY;
		/* Paired with smp_mb() in __mark_inode_dirty(). */
		smp_mb();
	}

	if (wbc_inode_was_flushed(wbci)) {
		if (wbci->wbci_dirty_flags & WBC_DIRTY_ATTR) {
			opc = MD_OP_SETATTR_LOCKLESS;
			*valid = wbci->wbci_dirty_attr;
			wbci->wbci_dirty_attr = 0;
			wbci->wbci_dirty_flags = WBC_DIRTY_NONE;
		}
		/* TODO: Hardlink. */
	} else {
		opc = MD_OP_CREATE_LOCKLESS;
	}
	spin_unlock(&inode->i_lock);

	return opc;
}

static int wbc_flush_ancestors_topdown(struct list_head *fsync_list)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0, /* metadata-only */
	};
	struct writeback_control_ext *wbcx =
			(struct writeback_control_ext *)&wbc;
	struct wbc_dentry *wbcd, *tmp;
	int rc = 0;

	ENTRY;

	wbcx->for_fsync = 1;
	list_for_each_entry_safe(wbcd, tmp, fsync_list, wbcd_fsync_item) {
		struct ll_dentry_data *lld;
		struct dentry *dentry;
		struct inode *inode;

		lld = container_of(wbcd, struct ll_dentry_data, lld_wbc_dentry);
		dentry = lld->lld_dentry;
		inode = dentry->d_inode;

		list_del_init(&wbcd->wbcd_fsync_item);

		/* TODO: batched metadata flushing */
		if (rc == 0)
			rc = sync_inode(inode, &wbc);

		spin_lock(&inode->i_lock);
		ll_i2wbci(inode)->wbci_flags &= ~WBC_STATE_FL_WRITEBACK;
		spin_unlock(&inode->i_lock);
		wbc_inode_writeback_complete(inode);
	}

	RETURN(rc);
}

int wbc_make_inode_sync(struct dentry *dentry)
{
	LIST_HEAD(fsync_list);

	for (;;) {
		struct inode *inode = dentry->d_inode;
		struct wbc_inode *wbci = ll_i2wbci(inode);
		struct wbc_dentry *wbcd = ll_d2wbcd(dentry);

		spin_lock(&inode->i_lock);
		if (wbci->wbci_flags & WBC_STATE_FL_WRITEBACK) {
			__wbc_inode_wait_for_writeback(inode);
			LASSERT(wbc_inode_was_flushed(wbci));
		}

		if (wbc_inode_was_flushed(wbci)) {
			spin_unlock(&inode->i_lock);
			break;
		}

		if (inode->i_state & I_SYNC)
			__inode_wait_for_writeback(inode);

		LASSERT(!(inode->i_state & I_SYNC));

		if (wbc_inode_was_flushed(wbci)) {
			spin_unlock(&inode->i_lock);
			break;
		}

		wbci->wbci_flags |= WBC_STATE_FL_WRITEBACK;
		list_add(&wbcd->wbcd_fsync_item, &fsync_list);
		spin_unlock(&inode->i_lock);
		dentry = dentry->d_parent;
	}

	return wbc_flush_ancestors_topdown(&fsync_list);
}

static int wbc_flush_regular_file(struct inode *inode, struct ldlm_lock *lock,
				  struct writeback_control_ext *wbcx)
{
	int rc;

	rc = wbcfs_commit_cache_pages(inode);
	wbcfs_inode_operations_switch(inode);

	return rc;
}

static int wbc_flush_dir(struct inode *dir, struct ldlm_lock *lock,
			 struct writeback_control_ext *wbcx)
{
	struct dentry *dentry, *tmp_subdir;
	LIST_HEAD(dirty_children_list);
	int rc;

	ENTRY;

	spin_lock(&dir->i_lock);
	/*
	 * Usually there is only one dentry in this alias dentry list.
	 * Even if not, It cannot have hardlinks for directories,
	 * so only one will actually have any children entries anyway.
	 */
	hlist_for_each_entry(dentry, &dir->i_dentry, d_alias) {
		struct dentry *child;

		spin_lock(&dentry->d_lock);
		if (list_empty(&dentry->d_subdirs)) {
			spin_unlock(&dentry->d_lock);
			continue;
		}

		list_for_each_entry_safe(child, tmp_subdir, &dentry->d_subdirs,
					 d_child) {
			struct wbc_inode *wbci;

			/* Negative entry? Drop it right away */
			if (child->d_inode == NULL) {
				d_lustre_invalidate(child);
				continue;
			}

			wbci = ll_i2wbci(child->d_inode);
			LASSERT(wbc_inode_has_protected(
				ll_i2wbci(child->d_inode)) && ll_d2d(child));
			/*
			 * The inode will be flushed. Pin it first to avoid
			 * be deleted? dget(child)
			 */
			list_add_tail(&ll_d2wbcd(child)->wbcd_flush_item,
				      &dirty_children_list);
		}
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&dir->i_lock);

	rc = wbcfs_flush_dir_children(dir, &dirty_children_list, lock, wbcx);
	mapping_clear_unevictable(dir->i_mapping);
	wbcfs_inode_operations_switch(dir);
	/* TODO: error handling when @dirty_children_list is not empty. */
	LASSERT(list_empty(&dirty_children_list));

	RETURN(rc);
}

static int wbc_inode_flush(struct inode *inode, struct ldlm_lock *lock,
			   struct writeback_control_ext *wbcx)
{
	if (S_ISDIR(inode->i_mode))
		return wbc_flush_dir(inode, lock, wbcx);
	else if (S_ISREG(inode->i_mode))
		return wbc_flush_regular_file(inode, lock, wbcx);

	return -ENOTSUPP;
}

static inline int wbc_inode_flush_lockless(struct inode *inode,
					   struct writeback_control_ext *wbcx)
{
	return wbcfs_inode_flush_lockless(inode, wbcx);
}

static inline void wbc_mark_inode_deroot(struct inode *inode)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);

	wbc_super_root_del(inode);
	wbci->wbci_flags = WBC_STATE_FL_NONE;
	wbcfs_inode_operations_switch(inode);
}

int wbc_make_inode_deroot(struct inode *inode, struct ldlm_lock *lock,
			  struct writeback_control_ext *wbcx)
{
	int rc;

	LASSERT(wbc_inode_root(ll_i2wbci(inode)));

	rc = wbc_inode_flush(inode, lock, wbcx);
	spin_lock(&inode->i_lock);
	wbc_mark_inode_deroot(inode);
	spin_unlock(&inode->i_lock);
	return rc;
}

static int wbc_inode_flush_lockdrop(struct inode *inode,
				    struct writeback_control_ext *wbcx)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct ldlm_lock *lock;
	int rc = 0;

	lock = ldlm_handle2lock(&wbci->wbci_lock_handle);
	if (lock == NULL) {
		LASSERT(!wbc_inode_has_protected(wbci));
		RETURN(0);
	}

	if (wbc_inode_has_protected(wbci))
		rc = wbc_inode_flush(inode, lock, wbcx);

	LDLM_LOCK_PUT(lock);

	return rc;
}

void wbc_inode_init(struct wbc_inode *wbci)
{
	wbci->wbci_flags = WBC_STATE_FL_NONE;
	wbci->wbci_dirty_flags = WBC_DIRTY_NONE;
	INIT_LIST_HEAD(&wbci->wbci_root_list);
}

void wbc_dentry_init(struct dentry *dentry)
{
	struct ll_dentry_data *lld;

	lld = ll_d2d(dentry);
	LASSERT(lld);
	lld->lld_dentry = dentry;
	INIT_LIST_HEAD(&lld->lld_wbc_dentry.wbcd_flush_item);
	INIT_LIST_HEAD(&lld->lld_wbc_dentry.wbcd_fsync_item);
}

static inline struct wbc_inode *wbc_inode(struct list_head *head)
{
	return list_entry(head, struct wbc_inode, wbci_root_list);
}

static int __wbc_super_shrink_roots(struct wbc_super *super,
				     struct list_head *shrink_list)
{
	struct writeback_control_ext wbcx = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0, /* metadata-only */
		.for_sync = 1,
		.for_callback = 1,
	};
	int rc = 0;

	LASSERT(shrink_list == &super->wbcs_lazy_roots ||
		shrink_list == &super->wbcs_roots);

	spin_lock(&super->wbcs_lock);
	while (!list_empty(shrink_list)) {
		struct wbc_inode *wbci = wbc_inode(shrink_list->prev);
		struct inode *inode = ll_wbci2i(wbci);

		LASSERT(wbci->wbci_flags & WBC_STATE_FL_ROOT);
		list_del_init(&wbci->wbci_root_list);
		spin_unlock(&super->wbcs_lock);
		rc = wbc_inode_flush_lockdrop(inode, &wbcx);
		if (rc) {
			CERROR("Failed to flush file: "DFID"\n",
			       PFID(&ll_i2info(inode)->lli_fid));
			return rc;
		}
		spin_lock(&super->wbcs_lock);
	}
	spin_unlock(&super->wbcs_lock);

	return rc;
}

int wbc_super_shrink_roots(struct wbc_super *super)
{
	int rc;
	int rc2;

	rc = __wbc_super_shrink_roots(super, &super->wbcs_lazy_roots);
	rc2 = __wbc_super_shrink_roots(super, &super->wbcs_roots);
	if (rc)
		rc = rc2;

	return rc;
}

int wbc_super_sync_fs(struct wbc_super *super, int wait)
{
	if (!wait)
		return 0;

	return __wbc_super_shrink_roots(super, &super->wbcs_lazy_roots);
}

int wbc_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct writeback_control_ext *wbcx =
		(struct writeback_control_ext *)wbc;
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc = 0;

	ENTRY;

	/* The inode was flush to MDT due to LRU lock shrinking. */
	if (!wbc_inode_has_protected(wbci))
		RETURN(0);

	/* TODO: Handle WB_SYNC_ALL WB_SYNC_NONE properly. */
	switch (wbci->wbci_flush_mode) {
	case WBC_FLUSH_AGING_DROP:

		rc = wbc_inode_flush_lockdrop(inode, wbcx);
		/* TODO: Convert the EX WBC lock to PR or CR lock. */
		break;
	case WBC_FLUSH_AGING_KEEP:
		rc = wbc_inode_flush_lockless(inode, wbcx);
		break;
	case WBC_FLUSH_LAZY_DROP:
	default:
		break;
	}

	RETURN(rc);
}

static void wbc_super_conf_disable(struct wbc_conf *conf)
{
	memset(conf, 0, sizeof(*conf));
	conf->wbcc_cache_mode = WBC_MODE_NONE;
	conf->wbcc_flush_mode = WBC_FLUSH_NONE;
}

static void wbc_super_conf_default(struct wbc_conf *conf)
{
	conf->wbcc_cache_mode = WBC_MODE_MEMFS;
	conf->wbcc_flush_mode = WBC_FLUSH_DEFAULT_MODE;
	conf->wbcc_max_rpcs = 0;
}

static void wbc_super_conf_update(struct wbc_conf *conf, struct wbc_cmd *cmd)
{
	if (conf->wbcc_cache_mode == WBC_MODE_NONE)
		conf->wbcc_cache_mode = WBC_MODE_DEFAULT;
	if (cmd->wbcc_flags & WBC_CMD_OP_CACHE_MODE)
		conf->wbcc_cache_mode = cmd->wbcc_conf.wbcc_cache_mode;
	if (cmd->wbcc_flags & WBC_CMD_OP_FLUSH_MODE)
		conf->wbcc_flush_mode = cmd->wbcc_conf.wbcc_flush_mode;
	if (cmd->wbcc_flags & WBC_CMD_OP_MAX_RPCS)
		conf->wbcc_max_rpcs = cmd->wbcc_conf.wbcc_max_rpcs;
	if (cmd->wbcc_flags & WBC_CMD_OP_RMPOL)
		conf->wbcc_rmpol = cmd->wbcc_conf.wbcc_rmpol;
}

void wbc_super_init(struct wbc_super *super)
{
	spin_lock_init(&super->wbcs_lock);
	wbc_super_conf_disable(&super->wbcs_conf);
	INIT_LIST_HEAD(&super->wbcs_roots);
	INIT_LIST_HEAD(&super->wbcs_lazy_roots);
}

static int wbc_parse_value_pair(struct wbc_cmd *cmd, char *buffer)
{
	struct wbc_conf *conf = &cmd->wbcc_conf;
	char *key, *val;
	unsigned long num;
	int rc;

	val = buffer;
	key = strsep(&val, "=");
	if (val == NULL || strlen(val) == 0)
		return -EINVAL;

	/* Key of the value pair */
	if (strcmp(key, "cache_mode") == 0) {
		if (strcmp(val, "memfs") == 0)
			conf->wbcc_cache_mode = WBC_MODE_MEMFS;
		else
			return -EINVAL;

		cmd->wbcc_flags |= WBC_CMD_OP_CACHE_MODE;
	} else if (strcmp(key, "flush_mode") == 0) {
		if (strcmp(val, "lazy_drop") == 0)
			conf->wbcc_flush_mode = WBC_FLUSH_LAZY_DROP;
		else if (strcmp(val, "aging_drop") == 0)
			conf->wbcc_flush_mode = WBC_FLUSH_AGING_DROP;
		else if (strcmp(val, "aging_keep") == 0)
			conf->wbcc_flush_mode = WBC_FLUSH_AGING_KEEP;
		else
			return -EINVAL;

		cmd->wbcc_flags |= WBC_CMD_OP_FLUSH_MODE;
	} else if (strcmp(key, "max_rpcs") == 0) {
		rc = kstrtoul(val, 10, &num);
		if (rc)
			return rc;

		conf->wbcc_max_rpcs = num;
		cmd->wbcc_flags |= WBC_CMD_OP_MAX_RPCS;
	} else if (strcmp(key, "rmpol") == 0) {
		if (strcmp(val, "sync") == 0)
			conf->wbcc_rmpol = WBC_RMPOL_SYNC;
		else
			return -EINVAL;

		cmd->wbcc_flags |= WBC_CMD_OP_RMPOL;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int wbc_parse_value_pairs(struct wbc_cmd *cmd, char *buffer)
{
	char *val;
	char *token;
	int rc;

	val = buffer;
	while (val != NULL && strlen(val) != 0) {
		token = strsep(&val, " ");
		rc = wbc_parse_value_pair(cmd, token);
		if (rc)
			return rc;
	}

	/* TODO: General valid check for the WBC commands. */
	return 0;
}

static struct wbc_cmd *wbc_cmd_parse(char *buffer, unsigned long count)
{
	static struct wbc_cmd *cmd;
	char *token;
	char *val;
	int rc = 0;

	ENTRY;

	OBD_ALLOC_PTR(cmd);
	if (cmd == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* Disable WBC on the client, and clear all setting */
	if (strncmp(buffer, "disable", 7) == 0) {
		cmd->wbcc_cmd = WBC_CMD_DISABLE;
		RETURN(cmd);
	}

	if (strncmp(buffer, "enable", 6) == 0) {
		cmd->wbcc_cmd = WBC_CMD_ENABLE;
		RETURN(cmd);
	}

	val = buffer;
	token = strsep(&val, " ");
	if (val == NULL || strlen(val) == 0)
		GOTO(out_free_cmd, rc = -EINVAL);

	/* Type of the command */
	if (strcmp(token, "conf") == 0)
		cmd->wbcc_cmd = WBC_CMD_CONFIG;
	else
		GOTO(out_free_cmd, rc = -EINVAL);

	rc = wbc_parse_value_pairs(cmd, val);
	if (rc == 0)
		RETURN(cmd);

out_free_cmd:
	OBD_FREE_PTR(cmd);
	RETURN(ERR_PTR(rc));
}

int wbc_cmd_handle(struct wbc_super *super, struct wbc_cmd *cmd)
{
	struct wbc_conf *conf = &super->wbcs_conf;
	int rc = 0;

	spin_lock(&super->wbcs_lock);
	switch (cmd->wbcc_cmd) {
	case WBC_CMD_DISABLE:
		wbc_super_conf_disable(conf);
		super->wbcs_generation++;
		break;
	case WBC_CMD_ENABLE:
		if (conf->wbcc_cache_mode == WBC_MODE_NONE) {
			wbc_super_conf_default(conf);
			super->wbcs_generation++;
		} else {
			rc = -EALREADY;
		}
		break;
	case WBC_CMD_CONFIG:
		wbc_super_conf_update(conf, cmd);
		super->wbcs_generation++;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	spin_unlock(&super->wbcs_lock);
	return rc;
}

int wbc_cmd_parse_and_handle(char *buffer, unsigned long count,
			     struct wbc_super *super)
{
	int rc = 0;
	struct wbc_cmd *cmd;

	ENTRY;

	cmd = wbc_cmd_parse(buffer, count);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	rc = wbc_cmd_handle(super, cmd);
	OBD_FREE_PTR(cmd);
	return rc;
}
