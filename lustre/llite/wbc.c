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

long wbc_flush_opcode_get(struct dentry *dchild)
{
	struct inode *inode = dchild->d_inode;
	struct wbc_inode *wbci = ll_i2wbci(inode);

	if (wbci->wbci_flags & WBC_STATE_FL_SYNC) {
		if (wbci->wbci_dirty_flags & WBC_DIRTY_ATTR)
			return MD_OP_SETATTR_EXLOCK;

		return MD_OP_EXLOCK_ONLY;
	}

	return MD_OP_CREATE_EXLOCK;
}

static int wbc_flush_regular_file(struct inode *inode, struct ldlm_lock *lock)
{
	/*
	 * TODO: Update the metadata object on MDT if the file attributs of
	 * this regular file was modified after flushed to MDT.
	 */
	return wbcfs_commit_cache_pages(inode);
}

static int wbc_flush_dir(struct inode *dir, struct ldlm_lock *lock)
{
	struct dentry *dentry, *tmp_subdir;
	LIST_HEAD(dirty_children_list);
	int rc;

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

	rc = wbcfs_flush_dir_children(dir, &dirty_children_list, lock);
	mapping_clear_unevictable(dir->i_mapping);
	wbcfs_inode_operations_switch(dir);
	/* TODO: error handling when @dirty_children_list is not empty. */
	LASSERT(list_empty(&dirty_children_list));

	RETURN(rc);
}

int wbc_inode_flush(struct inode *inode, struct ldlm_lock *lock)
{
	if (S_ISDIR(inode->i_mode))
		return wbc_flush_dir(inode, lock);
	else if (S_ISREG(inode->i_mode))
		return wbc_flush_regular_file(inode, lock);

	return -ENOTSUPP;
}

static inline void wbc_inode_flush_lockless(struct inode *inode)
{
	wbcfs_inode_flush_lockless(inode);
}

void wbc_inode_init(struct wbc_inode *wbci)
{
	wbci->wbci_flags = WBC_STATE_FL_NONE;
	wbci->wbci_dirty_flags = WBC_DIRTY_NONE;
}

void wbc_dentry_init(struct dentry *dentry)
{
	struct ll_dentry_data *lld;

	lld = ll_d2d(dentry);
	LASSERT(lld);
	lld->lld_dentry = dentry;
	INIT_LIST_HEAD(&lld->lld_wbc_dentry.wbcd_flush_item);
}

int wbc_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct ldlm_lock *lock;
	bool cached;

	ENTRY;

	/* The inode was flush to MDT due to LRU lock shrinking. */
	cached = wbc_inode_has_protected(wbci);
	if (!cached)
		RETURN(0);

	/* TODO: Handle WB_SYNC_ALL. */
	switch (wbci->wbci_flush_mode) {
	case WBC_FLUSH_AGING_DROP:
		lock = ldlm_handle2lock(&wbci->wbci_lock_handle);
		if (lock == NULL) {
			LASSERT(!wbc_inode_has_protected(wbci));
			RETURN(0);
		}

		wbc_inode_lock_callback(inode, lock, &cached);
		LDLM_LOCK_PUT(lock);
		/* TODO: Convert the EX WBC lock to PR or CR lock. */
		break;
	case WBC_FLUSH_AGING_KEEP:
		wbc_inode_flush_lockless(inode);
		break;
	case WBC_FLUSH_LAZY_DROP:
	default:
		break;
	}

	RETURN(0);
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
