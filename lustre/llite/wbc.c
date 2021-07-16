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
	if (wbc_flush_mode_lazy(wbci))
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

int wbc_reserve_inode(struct wbc_super *super)
{
	struct wbc_conf *conf = &super->wbcs_conf;
	int rc = 0;

	if (conf->wbcc_max_inodes) {
		spin_lock(&super->wbcs_lock);
		if (!conf->wbcc_free_inodes)
			rc = -ENOSPC;
		else
			conf->wbcc_free_inodes--;
		spin_unlock(&super->wbcs_lock);
		if (wbc_cache_too_much_inodes(conf))
			wake_up_process(super->wbcs_reclaim_task);
	}
	return rc;
}

void wbc_unreserve_inode(struct inode *inode)
{
	struct wbc_super *super = ll_i2wbcs(inode);
	struct wbc_inode *wbci = ll_i2wbci(inode);

	wbci->wbci_flags &= ~WBC_STATE_FL_INODE_RESERVED;
	if (super->wbcs_conf.wbcc_max_inodes) {
		spin_lock(&super->wbcs_lock);
		if (!list_empty(&wbci->wbci_rsvd_lru))
			list_del_init(&wbci->wbci_rsvd_lru);
		super->wbcs_conf.wbcc_free_inodes++;
		spin_unlock(&super->wbcs_lock);
	}
}

void wbc_reserved_inode_lru_add(struct inode *inode)
{
	struct wbc_super *super = ll_i2wbcs(inode);

	if (super->wbcs_conf.wbcc_max_inodes) {
		spin_lock(&super->wbcs_lock);
		list_add_tail(&ll_i2wbci(inode)->wbci_rsvd_lru,
			      &super->wbcs_rsvd_inode_lru);
		spin_unlock(&super->wbcs_lock);
	}
}

void wbc_reserved_inode_lru_del(struct inode *inode)
{
	struct wbc_super *super = ll_i2wbcs(inode);

	if (super->wbcs_conf.wbcc_max_inodes) {
		spin_lock(&super->wbcs_lock);
		list_del_init(&ll_i2wbci(inode)->wbci_rsvd_lru);
		super->wbcs_conf.wbcc_free_inodes++;
		spin_unlock(&super->wbcs_lock);
	}
}

void wbc_free_inode(struct inode *inode)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);

	if (wbc_inode_root(wbci))
		wbc_super_root_del(inode);
	if (wbc_inode_reserved(wbci))
		wbc_unreserve_inode(inode);
}

void wbc_inode_unreserve_dput(struct inode *inode,
					    struct dentry *dentry)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);

	if (wbc_inode_reserved(wbci)) {
		wbci->wbci_flags &= ~WBC_STATE_FL_INODE_RESERVED;
		wbc_unreserve_inode(inode);
		/* Unpin the dentry now as it is stable. */
		dput(dentry);
	}
}

void wbc_inode_data_lru_add(struct inode *inode, struct file *file)
{
	struct wbc_super *super = ll_i2wbcs(inode);
	struct ll_file_data *fd = file->private_data;

	/*
	 * FIXME: It whould better to add @inode into cache shrinking list
	 * when the file is actual modified, i.e. at close() time with data
	 * modified, but not at file open time.
	 */
	if (super->wbcs_conf.wbcc_max_pages && fd->fd_omode & FMODE_WRITE) {
		struct wbc_inode *wbci = ll_i2wbci(inode);

		spin_lock(&super->wbcs_data_lru_lock);
		if (list_empty(&wbci->wbci_data_lru))
			list_add_tail(&wbci->wbci_data_lru,
				      &super->wbcs_data_inode_lru);
		spin_unlock(&super->wbcs_data_lru_lock);
	}
}

void wbc_inode_data_lru_del(struct inode *inode)
{
	struct wbc_super *super = ll_i2wbcs(inode);

	if (super->wbcs_conf.wbcc_max_pages) {
		struct wbc_inode *wbci = ll_i2wbci(inode);

		spin_lock(&super->wbcs_data_lru_lock);
		if (!list_empty(&wbci->wbci_data_lru))
			list_del_init(&wbci->wbci_data_lru);
		spin_unlock(&super->wbcs_data_lru_lock);
	}
}

static inline void wbc_clear_dirty_for_flush(struct wbc_inode *wbci,
					     unsigned int *valid)
{
	*valid = wbci->wbci_dirty_attr;
	wbci->wbci_dirty_attr = 0;
	wbci->wbci_dirty_flags = WBC_DIRTY_FL_FLUSHING;
}

static inline bool wbc_flush_need_exlock(struct wbc_inode *wbci,
					 struct writeback_control_ext *wbcx)
{
	return wbc_mode_lock_drop(wbci) || wbcx->for_callback;
}

/**
 * Initialize synchronous io wait \a anchor for \a nr updates.
 * \param anchor owned by caller, initialized here.
 * \param nr number of updates initially pending in sync.
 */
void wbc_sync_io_init(struct wbc_sync_io *anchor, int nr)
{
	ENTRY;
	memset(anchor, 0, sizeof(*anchor));
	init_waitqueue_head(&anchor->wsi_waitq);
	atomic_set(&anchor->wsi_sync_nr, nr);
}

/**
 * Wait until all IO completes. Transfer completion routine has to call
 * wbc_sync_io_note() for every entity.
 */
int wbc_sync_io_wait(struct wbc_sync_io *anchor, long timeout)
{
	int rc = 0;

	ENTRY;

	LASSERT(timeout >= 0);
	if (timeout > 0 &&
	    wait_event_idle_timeout(anchor->wsi_waitq,
				    atomic_read(&anchor->wsi_sync_nr) == 0,
				    cfs_time_seconds(timeout)) == 0) {
		rc = -ETIMEDOUT;
		CERROR("IO failed: %d, still wait for %d remaining entries\n",
		       rc, atomic_read(&anchor->wsi_sync_nr));
	}

	wait_event_idle(anchor->wsi_waitq,
			atomic_read(&anchor->wsi_sync_nr) == 0);
	if (!rc)
		rc = anchor->wsi_sync_rc;

	/* We take the lock to ensure that cl_sync_io_note() has finished */
	spin_lock(&anchor->wsi_waitq.lock);
	LASSERT(atomic_read(&anchor->wsi_sync_nr) == 0);
	spin_unlock(&anchor->wsi_waitq.lock);

	RETURN(rc);
}

/**
 * Indicate that transfer of a single update completed.
 */
void wbc_sync_io_note(struct wbc_sync_io *anchor, int ioret)
{
	ENTRY;
	if (anchor->wsi_sync_rc == 0 && ioret < 0)
		anchor->wsi_sync_rc = ioret;

	/* Completion is used to signal the end of IO. */
	LASSERT(atomic_read(&anchor->wsi_sync_nr) > 0);
	if (atomic_dec_and_lock(&anchor->wsi_sync_nr,
				&anchor->wsi_waitq.lock)) {
		wake_up_locked(&anchor->wsi_waitq);
		spin_unlock(&anchor->wsi_waitq.lock);
	}
	EXIT;
}

long wbc_flush_opcode_get(struct inode *inode, struct dentry *dchild,
			  struct writeback_control_ext *wbcx,
			  unsigned int *valid)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	long opc = MD_OP_NONE;
	bool decomp_keep;

	ENTRY;

	decomp_keep = wbc_decomplete_lock_keep(wbci, wbcx);
	spin_lock(&inode->i_lock);
	if (wbc_mode_lock_keep(wbci)) {
		if (wbcx->for_callback && inode->i_state & I_SYNC)
			__inode_wait_for_writeback(inode);

		if (!wbcx->for_fsync &&
		    wbci->wbci_flags & WBC_STATE_FL_WRITEBACK)
			__wbc_inode_wait_for_writeback(inode);
	} else if (wbc_mode_lock_drop(wbci)) {
		LASSERT(!(inode->i_state & I_SYNC));
	}

	/*
	 * The inode was redirtied.
	 * TODO: handle more dirty flags: I_DIRTY_TIME | I_DIRTY_TIME_EXPIRED
	 * in the latest Linux kernel.
	 */

	if (wbc_inode_none(wbci)) {
		opc = MD_OP_NONE;
	} else if (wbc_inode_was_flushed(wbci)) {
		if (decomp_keep) {
			LASSERT(dchild != NULL);
			opc = MD_OP_NONE;
			if (wbcx->unrsv_children_decomp)
				wbc_inode_unreserve_dput(inode, dchild);
		} else if (wbc_inode_attr_dirty(wbci)) {
			wbc_clear_dirty_for_flush(wbci, valid);
			opc = wbc_flush_need_exlock(wbci, wbcx) ?
			      MD_OP_SETATTR_EXLOCK : MD_OP_SETATTR_LOCKLESS;
		} else if (wbc_flush_need_exlock(wbci, wbcx)) {
			opc = MD_OP_EXLOCK_ONLY;
		}
	} else {
		/*
		 * TODO: Update the metadata attributes on MDT together with
		 * the file creation.
		 */
		wbc_clear_dirty_for_flush(wbci, valid);
		opc = wbc_flush_need_exlock(wbci, wbcx) ?
		      MD_OP_CREATE_EXLOCK : MD_OP_CREATE_LOCKLESS;
	}

	if (opc != MD_OP_NONE)
		wbci->wbci_flags |= WBC_STATE_FL_WRITEBACK;
	spin_unlock(&inode->i_lock);

	RETURN(opc);
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
		struct wbc_inode *wbci;

		lld = container_of(wbcd, struct ll_dentry_data, lld_wbc_dentry);
		dentry = lld->lld_dentry;
		inode = dentry->d_inode;
		wbci = ll_i2wbci(inode);

		list_del_init(&wbcd->wbcd_fsync_item);

		/* Add @inode into the dirty list, otherwise sync_inode() will
		 * skip to write out the inode as the inode is not marked as
		 * I_DIRTY.
		 */
		if (wbc_flush_mode_lazy(wbci))
			mark_inode_dirty(inode);

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

static inline void wbc_sync_addroot_lockdrop(struct wbc_inode *wbci,
					     struct wbc_dentry *wbcd,
					     struct list_head *fsync_list)
{
	if (wbc_mode_lock_drop(wbci) && wbc_inode_root(wbci)) {
		LASSERT(wbc_inode_has_protected(wbci));
		wbci->wbci_flags |= WBC_STATE_FL_WRITEBACK;
		list_add(&wbcd->wbcd_fsync_item, fsync_list);
	}
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

		if (wbc_inode_written_out(wbci)) {
			wbc_sync_addroot_lockdrop(wbci, wbcd, &fsync_list);
			spin_unlock(&inode->i_lock);
			break;
		}

		if (inode->i_state & I_SYNC)
			__inode_wait_for_writeback(inode);

		LASSERT(!(inode->i_state & I_SYNC));

		if (wbc_inode_written_out(wbci)) {
			wbc_sync_addroot_lockdrop(wbci, wbcd, &fsync_list);
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

static int wbc_inode_update_metadata(struct inode *inode,
				     struct ldlm_lock *lock,
				     struct writeback_control_ext *wbcx)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	long opc = MD_OP_NONE;
	unsigned int valid;
	int rc = 0;

	ENTRY;

	LASSERT(wbc_inode_was_flushed(wbci));

	spin_lock(&inode->i_lock);
	if (wbc_inode_attr_dirty(wbci)) {
		valid = wbci->wbci_dirty_attr;
		wbci->wbci_dirty_flags = WBC_DIRTY_FL_FLUSHING;
		wbci->wbci_dirty_attr = 0;
		opc = MD_OP_SETATTR_LOCKLESS;
	}
	/* TODO: hardlink. */
	spin_unlock(&inode->i_lock);

	/*
	 * FIXME: if @inode is a directory, it should handle the order of the
	 * metadata attribute updating such as chmod()/chown() and newly file
	 * creation under this directory carefully. Or MDT should ignore the
	 * permission check for newly file creation under the protection of an
	 * WBC EX lock.
	 */
	if (opc == MD_OP_SETATTR_LOCKLESS)
		rc = wbc_do_setattr(inode, valid);

	RETURN(rc);
}

static int wbc_reopen_file_handler(struct inode *inode,
				   struct ldlm_lock *lock,
				   struct writeback_control_ext *wbcx)
{
	struct dentry *dentry;
	int rc = 0;

	ENTRY;

	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		struct wbc_dentry *wbcd = ll_d2wbcd(dentry);
		struct ll_file_data *fd, *tmp;

		dget(dentry);
		spin_unlock(&inode->i_lock);

		/*
		 * Do not need to acquire @wbcd_open_lock spinlock as it is
		 * under the protection of the lock @wbci_rw_sem.
		 */
		list_for_each_entry_safe(fd, tmp, &wbcd->wbcd_open_files,
					 fd_wbc_file.wbcf_open_item) {
			struct file *file = fd->fd_file;

			list_del_init(&fd->fd_wbc_file.wbcf_open_item);
			/* FIXME: Is it safe to switch file operatoins here? */
			if (S_ISDIR(inode->i_mode))
				file->f_op = &ll_dir_operations;
			else if (S_ISREG(inode->i_mode))
				file->f_op = ll_i2sbi(inode)->ll_fop;

			rc = file->f_op->open(inode, file);
			if (rc)
				GOTO(out_dput, rc);

			wbcfs_dcache_dir_close(inode, file);
			dput(dentry); /* Unpin from open in MemFS. */
		}
out_dput:
		dput(dentry);
		if (rc)
			RETURN(rc);
		spin_lock(&inode->i_lock);
	}
	spin_unlock(&inode->i_lock);

	RETURN(rc);
}

static int wbc_flush_regular_file(struct inode *inode, struct ldlm_lock *lock,
				  struct writeback_control_ext *wbcx)
{
	int rc;

	ENTRY;

	rc = wbc_inode_update_metadata(inode, lock, wbcx);
	if (rc)
		RETURN(rc);

	rc = wbcfs_commit_cache_pages(inode);
	if (rc < 0)
		RETURN(rc);

	rc = wbc_reopen_file_handler(inode, lock, wbcx);
	RETURN(rc);
}

static int wbc_flush_dir_children(struct wbc_context *ctx,
				  struct inode *dir,
				  struct list_head *childlist,
				  struct ldlm_lock *lock,
				  struct writeback_control_ext *wbcx)
{
	struct wbc_dentry *wbcd, *tmp;
	int rc = 0;

	ENTRY;

	rc = wbcfs_context_prepare(dir->i_sb, ctx);
	if (rc)
		RETURN(rc);

	list_for_each_entry_safe(wbcd, tmp, childlist, wbcd_flush_item) {
		struct ll_dentry_data *lld;
		struct dentry *dchild;

		lld = container_of(wbcd, struct ll_dentry_data, lld_wbc_dentry);
		dchild = lld->lld_dentry;
		list_del_init(&wbcd->wbcd_flush_item);

		rc = wbcfs_flush_dir_child(ctx, dir, dchild, lock, wbcx);
		/*
		 * Unpin the dentry.
		 * FIXME: race between dirty inode flush and unlink/rmdir().
		 */
		dput(dchild);
		if (rc)
			RETURN(rc);
	}

	rc = wbcfs_context_commit(dir->i_sb, ctx);
	RETURN(rc);
}

static inline bool wbc_dirty_queue_need_unplug(struct wbc_conf *conf,
					       __u32 count)
{
	return conf->wbcc_max_qlen > 0 && count > conf->wbcc_max_qlen;
}

static int wbc_flush_dir(struct inode *dir, struct ldlm_lock *lock,
			 struct writeback_control_ext *wbcx)
{
	struct dentry *dentry, *child, *tmp_subdir;
	LIST_HEAD(dirty_children_list);
	struct wbc_context ctx;
	__u32 count = 0;
	int rc, rc2;

	ENTRY;

	rc = wbc_inode_update_metadata(dir, lock, wbcx);
	if (rc)
		RETURN(rc);

	LASSERT(S_ISDIR(dir->i_mode));

	/*
	 * Usually there is only one dentry in this alias dentry list.
	 * Even if not, It cannot have hardlinks for directories,
	 * so only one will actually have any children entries anyway.
	 */
	dentry = d_find_any_alias(dir);
	if (!dentry)
		RETURN(0);

	rc = wbcfs_context_init(dir->i_sb, &ctx, true);
	if (rc)
		RETURN(rc);

	spin_lock(&dentry->d_lock);
	list_for_each_entry_safe(child, tmp_subdir,
				 &dentry->d_subdirs, d_child) {
		struct wbc_inode *wbci;

		/* Negative entry? or being unlinked? Drop it right away */
		if (child->d_inode == NULL || d_unhashed(child))
			continue;

		spin_lock_nested(&child->d_lock, DENTRY_D_LOCK_NESTED);
		if (child->d_inode == NULL || d_unhashed(child)) {
			spin_unlock(&child->d_lock);
			continue;
		}

		/*
		 * The inode will be flushed. Pin it first to avoid be deleted.
		 */
		dget_dlock(child);
		spin_unlock(&child->d_lock);
		count++;

		wbci = ll_i2wbci(child->d_inode);
		LASSERT(wbc_inode_has_protected(ll_i2wbci(child->d_inode)) &&
			ll_d2d(child));
		list_add_tail(&ll_d2wbcd(child)->wbcd_flush_item,
			      &dirty_children_list);

		if (wbc_dirty_queue_need_unplug(ll_i2wbcc(dir), count)) {
			spin_unlock(&dentry->d_lock);
			rc = wbc_flush_dir_children(&ctx, dir,
						    &dirty_children_list,
						    lock, wbcx);
			/* FIXME: error handling... */
			LASSERT(list_empty(&dirty_children_list));
			count = 0;
			cond_resched();
			spin_lock(&dentry->d_lock);
		}
	}
	spin_unlock(&dentry->d_lock);

	rc = wbc_flush_dir_children(&ctx, dir, &dirty_children_list,
				    lock, wbcx);
	mapping_clear_unevictable(dir->i_mapping);
	/* FIXME: error handling when @dirty_children_list is not empty. */
	LASSERT(list_empty(&dirty_children_list));

	if (rc == 0 && !(wbcx->for_decomplete &&
			 wbc_mode_lock_keep(ll_i2wbci(dir))))
		rc = wbc_reopen_file_handler(dir, lock, wbcx);

	rc2 = wbcfs_context_fini(dir->i_sb, &ctx);
	if (rc2 && rc == 0)
		rc = rc2;
	dput(dentry);
	RETURN(rc);
}

static int wbc_inode_flush(struct inode *inode, struct ldlm_lock *lock,
			   struct writeback_control_ext *wbcx)
{
	if (S_ISDIR(inode->i_mode))
		return wbc_flush_dir(inode, lock, wbcx);
	if (S_ISREG(inode->i_mode))
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
	if (wbc_inode_reserved(wbci))
		wbc_unreserve_inode(inode);

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

int wbc_make_inode_decomplete(struct inode *inode,
			      unsigned int unrsv_children)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct writeback_control_ext wbcx = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0, /* metadata-only */
		.for_decomplete = 1,
		.unrsv_children_decomp = unrsv_children,
	};
	struct ldlm_lock *lock = NULL;
	int rc;

	ENTRY;

	LASSERT(S_ISDIR(inode->i_mode));
	if (wbc_mode_lock_drop(wbci)) {
		lock = ldlm_handle2lock(&wbci->wbci_lock_handle);
		if (lock == NULL) {
			LASSERTF(!wbc_inode_has_protected(wbci),
				 "WBC flags %d\n", wbci->wbci_flags);
			RETURN(0);
		}
	}

	down_write(&wbci->wbci_rw_sem);
	if (wbc_inode_none(wbci) || !wbc_inode_complete(wbci))
		GOTO(up_rwsem, rc = 0);

	rc = wbc_inode_flush(inode, lock, &wbcx);
	/* FIXME: error handling. */

	spin_lock(&inode->i_lock);
	if (wbc_mode_lock_drop(wbci))
		wbc_mark_inode_deroot(inode);
	else if (wbc_mode_lock_keep(wbci))
		wbci->wbci_flags &= ~WBC_STATE_FL_COMPLETE;
	spin_unlock(&inode->i_lock);

up_rwsem:
	up_write(&wbci->wbci_rw_sem);
	if (lock)
		LDLM_LOCK_PUT(lock);

	RETURN(rc);
}

int wbc_make_dir_decomplete(struct inode *dir, struct dentry *parent,
			    unsigned int unrsv_children)
{
	int rc;

	ENTRY;

	LASSERT(parent != NULL && parent->d_inode == dir);

	if (!d_mountpoint(parent)) {
		if (wbc_mode_lock_drop(ll_i2wbci(dir)))
			rc = wbc_make_inode_sync(parent->d_parent);
		else /* lock keep flush mode */
			rc = wbc_make_inode_sync(parent);
		if (rc)
			RETURN(rc);
	}

	rc = wbc_make_inode_decomplete(dir, unrsv_children);
	RETURN(rc);
}

int wbc_make_data_commit(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	/*
	 * TODO: Reopen the file to support lock drop flush mode.
	 */
	if (!d_mountpoint(dentry->d_parent)) {
		if (wbc_mode_lock_drop(ll_i2wbci(inode)))
			rc = wbc_make_inode_sync(dentry->d_parent);
		else /* lock keep flush mode */
			rc = wbc_make_inode_sync(dentry);
		if (rc)
			RETURN(rc);
	}

	down_write(&wbci->wbci_rw_sem);
	rc = wbcfs_commit_cache_pages(inode);
	up_write(&wbci->wbci_rw_sem);

	RETURN(rc);
}

static int wbc_inode_flush_lockdrop(struct inode *inode,
				    struct writeback_control_ext *wbcx)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct ldlm_lock *lock;
	int rc = 0;

	lock = ldlm_handle2lock(&wbci->wbci_lock_handle);
	if (lock == NULL) {
		LASSERTF(!wbc_inode_has_protected(wbci),
			 "WBC flags: %d inode %p\n", wbci->wbci_flags, inode);
		RETURN(0);
	}

	down_write(&wbci->wbci_rw_sem);
	if (wbc_inode_has_protected(wbci))
		rc = wbc_make_inode_deroot(inode, lock, wbcx);
	up_write(&wbci->wbci_rw_sem);

	LDLM_LOCK_PUT(lock);

	return rc;
}

void wbc_inode_init(struct wbc_inode *wbci)
{
	wbci->wbci_flags = WBC_STATE_FL_NONE;
	wbci->wbci_dirty_flags = WBC_DIRTY_FL_NONE;
	INIT_LIST_HEAD(&wbci->wbci_root_list);
	INIT_LIST_HEAD(&wbci->wbci_rsvd_lru);
	INIT_LIST_HEAD(&wbci->wbci_data_lru);
	init_rwsem(&wbci->wbci_rw_sem);
}

void wbc_dentry_init(struct dentry *dentry)
{
	struct ll_dentry_data *lld;

	lld = ll_d2d(dentry);
	LASSERT(lld);
	lld->lld_dentry = dentry;
	INIT_LIST_HEAD(&lld->lld_wbc_dentry.wbcd_flush_item);
	INIT_LIST_HEAD(&lld->lld_wbc_dentry.wbcd_fsync_item);
	INIT_LIST_HEAD(&lld->lld_wbc_dentry.wbcd_open_files);
	spin_lock_init(&lld->lld_wbc_dentry.wbcd_open_lock);
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

	super->wbcs_conf.wbcc_cache_mode = WBC_MODE_NONE;
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
	case WBC_FLUSH_LAZY_KEEP:
		if (wbcx->for_fsync) {
			if (wbc_mode_lock_drop(wbci))
				rc = wbc_inode_flush_lockdrop(inode, wbcx);
			else if (wbc_mode_lock_keep(wbci))
				rc = wbc_inode_flush_lockless(inode, wbcx);
		}
		break;
	default:
		break;
	}

	RETURN(rc);
}

static int wbc_reclaim_inodes_below(struct wbc_super *super, __u32 low)
{
	struct wbc_conf *conf = &super->wbcs_conf;
	int rc = 0;

	ENTRY;

	spin_lock(&super->wbcs_lock);
	while (conf->wbcc_free_inodes < low) {
		struct inode *inode;
		struct wbc_inode *wbci;
		struct ll_inode_info *lli;
		struct dentry *dchild;

		if (list_empty(&super->wbcs_rsvd_inode_lru))
			break;

		wbci = list_entry(super->wbcs_rsvd_inode_lru.next,
				  struct wbc_inode, wbci_rsvd_lru);

		list_del_init(&wbci->wbci_rsvd_lru);
		lli = container_of(wbci, struct ll_inode_info, lli_wbc_inode);
		inode = ll_info2i(lli);
		dchild = d_find_any_alias(inode);
		if (!dchild)
			continue;

		spin_unlock(&super->wbcs_lock);

		rc = wbc_make_dir_decomplete(dchild->d_parent->d_inode,
					     dchild->d_parent, 1);
		dput(dchild);
		if (rc) {
			CERROR("Reclaim inodes failed: rc = %d\n", rc);
			RETURN(rc);
		}

		cond_resched();
		spin_lock(&super->wbcs_lock);
	}
	spin_unlock(&super->wbcs_lock);

	RETURN(rc);
}

static int wbc_reclaim_inodes(struct wbc_super *super)
{
	__u32 low = super->wbcs_conf.wbcc_max_inodes >> 1;

	return wbc_reclaim_inodes_below(super, low);
}

static int wbc_reclaim_pages_count(struct wbc_super *super, __u32 count)
{
	__u32 shrank_count = 0;
	int rc = 0;

	ENTRY;

	spin_lock(&super->wbcs_data_lru_lock);
	while (shrank_count < count) {
		struct inode *inode;
		struct wbc_inode *wbci;
		struct ll_inode_info *lli;
		struct dentry *dentry;

		if (list_empty(&super->wbcs_data_inode_lru))
			break;

		wbci = list_entry(super->wbcs_data_inode_lru.next,
				  struct wbc_inode, wbci_data_lru);

		list_del_init(&wbci->wbci_data_lru);
		lli = container_of(wbci, struct ll_inode_info, lli_wbc_inode);
		inode = ll_info2i(lli);
		dentry = d_find_any_alias(inode);
		if (!dentry)
			continue;

		spin_unlock(&super->wbcs_data_lru_lock);

		rc = wbc_make_data_commit(dentry);
		dput(dentry);
		if (rc < 0) {
			CERROR("Reclaim pages failed: rc = %d\n", rc);
			RETURN(rc);
		}

		shrank_count += rc;
		cond_resched();
		spin_lock(&super->wbcs_data_lru_lock);
	}
	spin_unlock(&super->wbcs_data_lru_lock);

	RETURN(rc);
}

static int wbc_reclaim_pages(struct wbc_super *super)
{
	__u32 count = super->wbcs_conf.wbcc_max_pages >> 1;

	return wbc_reclaim_pages_count(super, count);
}

#ifndef TASK_IDLE
#define TASK_IDLE TASK_INTERRUPTIBLE
#endif

static int ll_wbc_reclaim_main(void *arg)
{
	struct wbc_super *super = arg;

	ENTRY;

	while (({set_current_state(TASK_IDLE);
		 !kthread_should_stop(); })) {
		if (wbc_cache_too_much_inodes(&super->wbcs_conf)) {
			__set_current_state(TASK_RUNNING);
			(void) wbc_reclaim_inodes(super);
			cond_resched();
		} else if (wbc_cache_too_much_pages(&super->wbcs_conf)) {
			__set_current_state(TASK_RUNNING);
			(void) wbc_reclaim_pages(super);
		} else {
			schedule();
		}
	}
	__set_current_state(TASK_RUNNING);

	RETURN(0);
}

static void wbc_super_reset_common_conf(struct wbc_conf *conf)
{
	conf->wbcc_rmpol = WBC_RMPOL_DEFAULT;
	conf->wbcc_readdir_pol = WBC_READDIR_POL_DEFAULT;
	conf->wbcc_flush_pol = WBC_FLUSH_POL_DEFAULT;
	conf->wbcc_max_batch_count = 0;
	conf->wbcc_max_rpcs = WBC_DEFAULT_MAX_RPCS;
	conf->wbcc_max_qlen = WBC_DEFAULT_MAX_QLEN;
	conf->wbcc_background_async_rpc = 0;
	conf->wbcc_max_inodes = 0;
	conf->wbcc_free_inodes = 0;
	conf->wbcc_max_pages = 0;
	conf->wbcc_hiwm_ratio = WBC_DEFAULT_HIWM_RATIO;
	conf->wbcc_hiwm_inodes_count = 0;
	conf->wbcc_hiwm_pages_count = 0;
}

/* called with @wbcs_lock hold. */
static void wbc_super_disable_cache(struct wbc_super *super)
{
	struct wbc_conf *conf = &super->wbcs_conf;

repeat:
	conf->wbcc_cache_mode = WBC_MODE_NONE;
	conf->wbcc_flush_mode = WBC_FLUSH_NONE;

	spin_unlock(&super->wbcs_lock);
	wbc_super_shrink_roots(super);
	spin_lock(&super->wbcs_lock);
	/* The cache mode was changed when shrinking the WBC roots. */
	if (conf->wbcc_cache_mode != WBC_MODE_NONE)
		goto repeat;

	LASSERTF(conf->wbcc_max_inodes == conf->wbcc_free_inodes &&
		 percpu_counter_sum(&conf->wbcc_used_pages) == 0,
		 "max_inodes: %lu free_inodes:%lu\n",
		 conf->wbcc_max_inodes, conf->wbcc_free_inodes);
	wbc_super_reset_common_conf(conf);
}

static void wbc_super_conf_default(struct wbc_conf *conf)
{
	conf->wbcc_cache_mode = WBC_MODE_MEMFS;
	conf->wbcc_flush_mode = WBC_FLUSH_DEFAULT_MODE;
	conf->wbcc_rmpol = WBC_RMPOL_DEFAULT;
	conf->wbcc_max_rpcs = WBC_DEFAULT_MAX_RPCS;
	conf->wbcc_max_qlen = WBC_DEFAULT_MAX_QLEN;
}

static int wbc_super_conf_update(struct wbc_conf *conf, struct wbc_cmd *cmd)
{
	/*
	 * Memery limits for inodes/pages are not allowed to be decreased
	 * less then used value in the runtime.
	 */
	if (cmd->wbcc_flags & WBC_CMD_OP_INODES_LIMIT &&
	    (conf->wbcc_max_inodes - conf->wbcc_free_inodes) >
	    cmd->wbcc_conf.wbcc_max_inodes)
		return -EINVAL;

	if (cmd->wbcc_flags & WBC_CMD_OP_PAGES_LIMIT &&
	    percpu_counter_compare(&conf->wbcc_used_pages,
				   cmd->wbcc_conf.wbcc_max_pages) > 0)
		return -EINVAL;

	if (cmd->wbcc_flags & WBC_CMD_OP_INODES_LIMIT) {
		conf->wbcc_free_inodes += (cmd->wbcc_conf.wbcc_max_inodes -
					   conf->wbcc_max_inodes);
		conf->wbcc_max_inodes = cmd->wbcc_conf.wbcc_max_inodes;
	}

	if (cmd->wbcc_flags & WBC_CMD_OP_PAGES_LIMIT)
		conf->wbcc_max_pages = cmd->wbcc_conf.wbcc_max_pages;

	if (cmd->wbcc_flags & WBC_CMD_OP_RECLAIM_RATIO) {
		conf->wbcc_hiwm_ratio = cmd->wbcc_conf.wbcc_hiwm_ratio;
		conf->wbcc_hiwm_inodes_count = conf->wbcc_max_inodes *
					       conf->wbcc_hiwm_ratio / 100;
		conf->wbcc_hiwm_pages_count = conf->wbcc_max_pages *
					      conf->wbcc_hiwm_ratio / 100;
	}

	if (conf->wbcc_cache_mode == WBC_MODE_NONE)
		conf->wbcc_cache_mode = WBC_MODE_DEFAULT;
	if (cmd->wbcc_flags & WBC_CMD_OP_CACHE_MODE)
		conf->wbcc_cache_mode = cmd->wbcc_conf.wbcc_cache_mode;
	if (cmd->wbcc_flags & WBC_CMD_OP_FLUSH_MODE)
		conf->wbcc_flush_mode = cmd->wbcc_conf.wbcc_flush_mode;
	if (cmd->wbcc_flags & WBC_CMD_OP_MAX_RPCS)
		conf->wbcc_max_rpcs = cmd->wbcc_conf.wbcc_max_rpcs;
	if (cmd->wbcc_flags & WBC_CMD_OP_MAX_QLEN)
		conf->wbcc_max_qlen = cmd->wbcc_conf.wbcc_max_qlen;
	if (cmd->wbcc_flags & WBC_CMD_OP_RMPOL)
		conf->wbcc_rmpol = cmd->wbcc_conf.wbcc_rmpol;
	if (cmd->wbcc_flags & WBC_CMD_OP_READDIR_POL)
		conf->wbcc_readdir_pol = cmd->wbcc_conf.wbcc_readdir_pol;
	if (cmd->wbcc_flags & WBC_CMD_OP_FLUSH_POL)
		conf->wbcc_flush_pol = cmd->wbcc_conf.wbcc_flush_pol;
	if (cmd->wbcc_flags & WBC_CMD_OP_MAX_BATCH_COUNT)
		conf->wbcc_max_batch_count =
				cmd->wbcc_conf.wbcc_max_batch_count;

	return 0;
}

void wbc_super_fini(struct wbc_super *super)
{
	LASSERT(list_empty(&super->wbcs_rsvd_inode_lru));
	LASSERT(list_empty(&super->wbcs_data_inode_lru));

	if (super->wbcs_reclaim_task) {
		kthread_stop(super->wbcs_reclaim_task);
		super->wbcs_reclaim_task = NULL;
	}

	percpu_counter_destroy(&super->wbcs_conf.wbcc_used_pages);
}

int wbc_super_init(struct wbc_super *super)
{
	struct wbc_conf *conf = &super->wbcs_conf;
	int rc;

	ENTRY;

#ifdef HAVE_PERCPU_COUNTER_INIT_GFP_FLAG
	rc = percpu_counter_init(&conf->wbcc_used_pages, 0, GFP_KERNEL);
#else
	rc = percpu_counter_init(&conf->wbcc_used_pages, 0);
#endif
	if (rc)
		RETURN(-ENOMEM);

	conf->wbcc_cache_mode = WBC_MODE_NONE;
	conf->wbcc_flush_mode = WBC_FLUSH_NONE;
	wbc_super_reset_common_conf(conf);
	spin_lock_init(&super->wbcs_lock);
	INIT_LIST_HEAD(&super->wbcs_roots);
	INIT_LIST_HEAD(&super->wbcs_lazy_roots);
	INIT_LIST_HEAD(&super->wbcs_rsvd_inode_lru);
	INIT_LIST_HEAD(&super->wbcs_data_inode_lru);
	spin_lock_init(&super->wbcs_data_lru_lock);

	super->wbcs_reclaim_task = kthread_run(ll_wbc_reclaim_main, super,
					       "ll_wbc_reclaimer");
	if (IS_ERR(super->wbcs_reclaim_task)) {
		rc = PTR_ERR(super->wbcs_reclaim_task);
		super->wbcs_reclaim_task = NULL;
		CERROR("Cannot start WBC reclaim thread: rc = %d\n", rc);
		GOTO(out_err, rc);
	}

	RETURN(0);
out_err:
	wbc_super_fini(super);
	RETURN(rc);
}

static int wbc_parse_value_pair(struct wbc_cmd *cmd, char *buffer)
{
	struct wbc_conf *conf = &cmd->wbcc_conf;
	char *key, *val, *rest;
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
		if (strcmp(val, "lazy") == 0)
			conf->wbcc_flush_mode = WBC_FLUSH_LAZY_DEFAULT;
		else if (strcmp(val, "lazy_drop") == 0)
			conf->wbcc_flush_mode = WBC_FLUSH_LAZY_DROP;
		else if (strcmp(val, "lazy_keep") == 0)
			conf->wbcc_flush_mode = WBC_FLUSH_LAZY_KEEP;
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
	} else if (strcmp(key, "max_qlen") == 0) {
		rc = kstrtoul(val, 10, &num);
		if (rc)
			return rc;

		conf->wbcc_max_qlen = num;
		cmd->wbcc_flags |= WBC_CMD_OP_MAX_QLEN;
	} else if (strcmp(key, "rmpol") == 0) {
		if (strcmp(val, "sync") == 0)
			conf->wbcc_rmpol = WBC_RMPOL_SYNC;
		else
			return -EINVAL;

		cmd->wbcc_flags |= WBC_CMD_OP_RMPOL;
	} else if (strcmp(key, "readdir_pol") == 0) {
		if (strcmp(val, "dcache_compat") == 0)
			conf->wbcc_readdir_pol = WBC_READDIR_DCACHE_COMPAT;
		else if (strcmp(val, "dcache_decomp") == 0)
			conf->wbcc_readdir_pol = WBC_READDIR_DCACHE_DECOMPLETE;
		else
			return -EINVAL;

		cmd->wbcc_flags |= WBC_CMD_OP_READDIR_POL;
	} else if (strcmp(key, "hiwm_ratio") == 0) {
		rc = kstrtoul(val, 10, &num);
		if (rc)
			return rc;

		if (num >= 100)
			return -ERANGE;

		conf->wbcc_hiwm_ratio = num;
		cmd->wbcc_flags |= WBC_CMD_OP_RECLAIM_RATIO;
	} else if (strcmp(key, "max_inodes") == 0) {
		conf->wbcc_max_inodes = memparse(val, &rest);
		if (*rest)
			return -EINVAL;

		cmd->wbcc_flags |= WBC_CMD_OP_INODES_LIMIT;
	} else if (strcmp(key, "max_pages") == 0) {
		conf->wbcc_max_pages = memparse(val, &rest);
		if (*rest)
			return -EINVAL;

		cmd->wbcc_flags |= WBC_CMD_OP_PAGES_LIMIT;
	} else if (strcmp(key, "size") == 0) {
		unsigned long long size;

		size = memparse(val, &rest);
		if (*rest == '%') {
			size <<= PAGE_SHIFT;
			size *= cfs_totalram_pages();
			do_div(size, 100);
			rest++;
		}
		if (*rest)
			return -EINVAL;

		conf->wbcc_max_pages = DIV_ROUND_UP(size, PAGE_SIZE);
		cmd->wbcc_flags |= WBC_CMD_OP_PAGES_LIMIT;
	} else if (strcmp(key, "flush_pol") == 0) {
		if (strcmp(val, "batch") == 0)
			conf->wbcc_flush_pol = WBC_FLUSH_POL_BATCH;
		else if (strcmp(val, "rqset") == 0)
			conf->wbcc_flush_pol = WBC_FLUSH_POL_RQSET;
		else
			return -EINVAL;

		cmd->wbcc_flags |= WBC_CMD_OP_FLUSH_POL;
	} else if (strcmp(key, "max_batch_count") == 0) {
		rc = kstrtoul(val, 10, &num);
		if (rc)
			return rc;

		conf->wbcc_max_batch_count = num;
		cmd->wbcc_flags |= WBC_CMD_OP_MAX_BATCH_COUNT;
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

	if (strncmp(buffer, "clear", 5) == 0) {
		cmd->wbcc_cmd = WBC_CMD_CLEAR;
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
		wbc_super_disable_cache(super);
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
	case WBC_CMD_CHANGE:
		rc = wbc_super_conf_update(conf, cmd);
		if (rc == 0)
			super->wbcs_generation++;
		break;
	case WBC_CMD_CLEAR:
		spin_unlock(&super->wbcs_lock);
		rc = wbc_super_shrink_roots(super);
		spin_lock(&super->wbcs_lock);
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
