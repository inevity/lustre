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
 * Copyright (c) 2021, Whamcloud/DDN Storage Corporation.
 */
/*
 * lustre/llite/memfs.c
 *
 * Embeded MemFS for Lustre Metadata Writeback Caching (WBC)
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/namei.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <lustre_compat.h>
#include <linux/security.h>
#include <linux/swap.h>
#include <linux/dirent.h>
#include "llite_internal.h"

#define DIRENT64_SIZE(len)	\
	ALIGN(offsetof(struct linux_dirent64, d_name) + (len) + 1, sizeof(u64))

static int wbc_cache_enter(struct inode *dir, struct dentry *dchild)
{
	struct wbc_inode *wbci = ll_i2wbci(dir);
	struct dentry *parent = dchild->d_parent;
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);

	if (!wbc_inode_has_protected(wbci) || !wbc_inode_complete(wbci))
		RETURN(0);

	rc = wbc_reserve_inode(ll_i2wbcs(dir));
	if (rc == 0)
		RETURN(1);
	if (rc != -ENOSPC)
		RETURN(rc);

	up_read(&wbci->wbci_rw_sem);
	LASSERT(parent != NULL && parent->d_inode == dir);

	if (!d_mountpoint(parent)) {
		if (wbc_mode_lock_drop(wbci))
			rc = wbc_make_inode_sync(parent->d_parent);
		else if (wbc_mode_lock_keep(wbci))
			rc = wbc_make_inode_sync(parent);
		if (rc)
			GOTO(down_rwsem, rc);
	}

	rc = wbc_make_inode_decomplete(dir);
down_rwsem:
	down_read(&wbci->wbci_rw_sem);
	RETURN(rc);
}

static void wbc_cache_leave(struct inode *dir, enum md_op_code opc)
{
	up_read(&ll_i2wbci(dir)->wbci_rw_sem);
}

/*
 * These are the methods to create virtual entries for MD WBC.
 * Borrowing heavily from ramfs code.
 */
static struct inode *wbc_get_inode(struct inode *dir, int mode, dev_t dev,
				   struct md_op_data *op_data)
{
	struct inode *inode = new_inode(dir->i_sb);
	struct ll_sb_info *sbi = ll_s2sbi(dir->i_sb);
	struct ll_inode_info *lli;
	struct wbc_inode *dwbci;
	struct wbc_inode *wbci;
	int rc;

	ENTRY;

	if (!inode)
		RETURN(inode);

	inode_init_owner(inode, dir, mode);
	lli = ll_i2info(inode);
	ll_lli_init(lli);
	rc = obd_fid_alloc(NULL, sbi->ll_md_exp, &lli->lli_fid, op_data);
	if (rc) {
		iput(inode);
		RETURN(ERR_PTR(rc));
	}

	inode->i_ino = cl_fid_build_ino(&lli->lli_fid,
					test_bit(LL_SBI_32BIT_API,
						 sbi->ll_flags));
	inode->i_generation = cl_fid_build_gen(&lli->lli_fid);
	insert_inode_hash(inode);

#ifdef HAVE_BACKING_DEV_INFO
	inode->i_mapping->backing_dev_info = &s2lsi(inode->i_sb)->lsi_bdi;
#endif
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	/*
	 * For a directory, clear unevictable flag for mapping once it loses
	 * the root EX WBC lock;
	 * For a regular file, clear this once it has acquired the all extent
	 * locks for data contents so the client can flush the data if needed.
	 */
	mapping_set_unevictable(inode->i_mapping);
	/* TODO: set the creation time (btime). */
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

	/*
	 * Inherit cache information of the root WBC dirtectory.
	 * TODO: This should be a common data structure shared by all files or
	 * directories under the protection of the root WBC EX lock.
	 */
	dwbci = ll_i2wbci(dir);
	wbci = &lli->lli_wbc_inode;
	wbci->wbci_cache_mode = dwbci->wbci_cache_mode;
	wbci->wbci_flush_mode = dwbci->wbci_flush_mode;
	wbci->wbci_flags = WBC_STATE_FL_PROTECTED | WBC_STATE_FL_COMPLETE |
			   WBC_STATE_FL_INODE_RESERVED;
	wbci->wbci_dirty_flags = WBC_DIRTY_FL_CREAT;
	wbc_inode_operations_set(inode, mode, dev);

	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	if (S_ISDIR(inode->i_mode))
		inc_nlink(inode);

	/*
	 * Add the inode to some list to ensure it is flushed to the server
	 * after some reasonable timeout, or perhaps if we just make it dirty
	 * here, then the 5s flush will happen all by itself?
	 */
	RETURN(inode);
}

static int wbc_new_node(struct inode *dir, struct dentry *dchild,
			const char *tgt, umode_t mode, int rdev, __u32 opc)
{
	struct inode *inode;
	struct qstr *name = &dchild->d_name;
	struct md_op_data *op_data;
	int tgt_len = 0;
	int rc;

	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(dir)));

	if (unlikely(tgt != NULL))
		tgt_len = strlen(tgt) + 1;

	op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name,
				     name->len, 0, opc, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	inode = wbc_get_inode(dir, mode, old_decode_dev(rdev), op_data);
	if (IS_ERR(inode))
		GOTO(out_exit, rc = PTR_ERR(inode));

	rc = wbcfs_d_init(dchild);
	if (rc)
		GOTO(out_iput, rc);

	d_instantiate(dchild, inode);
	dget(dchild); /* Extra count - pin the dentry in core. */
	/* Mark @dir as dirty to update the mtime/ctime for @dir on MDT? */
	dir->i_mtime = dir->i_ctime = current_time(dir);

	if (opc == LUSTRE_OPC_SYMLINK) {
		struct ll_inode_info *lli;
		int tgt_len = strlen(tgt) + 1;

		/*
		 * Create local cache for symlink name - it is easier like this
		 * for now than using many different kernel APIs to readlink
		 * as async create time where we would need to get the name
		 * somehow. But we might need to get rid of this and convert
		 * finally.
		 */
		lli = ll_i2info(inode);
		OBD_ALLOC(lli->lli_symlink_name, tgt_len);
		if (lli->lli_symlink_name == NULL)
			GOTO(out_iput, rc = -ENOMEM);

		memcpy(lli->lli_symlink_name, tgt, tgt_len);
		inode->i_size = tgt_len;
	}

	switch (ll_i2wbci(inode)->wbci_flush_mode) {
	case WBC_FLUSH_AGING_DROP:
		mark_inode_dirty(dir);
		mark_inode_dirty(inode);
		break;
	case WBC_FLUSH_AGING_KEEP:
		mark_inode_dirty(inode);
		break;
	case WBC_FLUSH_LAZY_DROP:
	default:
		break;
	}

out_iput:
	if (rc)
		iput(inode);
out_exit:
	ll_finish_md_op_data(op_data);

	RETURN(rc);
}

bool wbc_inode_acct_page(struct inode *inode, long nr_pages)
{
	struct wbc_conf *conf = &ll_i2wbcs(inode)->wbcs_conf;

	if (conf->wbcc_max_pages) {
		if (percpu_counter_compare(&conf->wbcc_used_pages,
					   conf->wbcc_max_pages - nr_pages) > 0)
			return false;

		percpu_counter_add(&conf->wbcc_used_pages, nr_pages);
	}

	return true;
}

void wbc_inode_unacct_pages(struct inode *inode, long nr_pages)
{
	struct wbc_conf *conf = &ll_i2wbcs(inode)->wbcs_conf;

	ENTRY;

	if (conf->wbcc_max_pages)
		percpu_counter_sub(&conf->wbcc_used_pages, nr_pages);
	EXIT;
}

static struct dentry *memfs_lookup_nd(struct inode *parent,
				      struct dentry *dentry, unsigned int flags)
{
	struct wbc_inode *wbci = ll_i2wbci(parent);
	struct dentry *de;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_complete(wbci)) {
		/*
		 * XXX Check d_name.len and if it's too big, bail out right away
		 * Probably no point to cache negative dentries, so
		 * just reuse existing kernel mechanism to delete them
		 * on release. Revisit this if it ever becomes an issue.
		 * In fact note that this disables atomic open semantics
		 * and we will fall through into the create path if this was
		 * open|create kind of lookup, but that's likely ok too.
		 */
		de = simple_lookup(parent, dentry, flags);
	} else {
		/*
		 * If @parent is in the state WBC_STATE_FL_NONE, or not
		 * Complete(C) but Protected(C) state, perform the lookup()
		 * on MDT.
		 */
		de = ll_dir_inode_operations.lookup(parent, dentry, flags);
	}

	up_read(&wbci->wbci_rw_sem);
	RETURN(de);
}

int memfs_mkdir(struct inode *dir, struct dentry *dchild, umode_t mode)
{
	int rc;

	ENTRY;

	if (!IS_POSIXACL(dir) || !exp_connect_umask(ll_i2mdexp(dir)))
		mode &= ~current_umask();

	mode = (mode & (S_IRWXUGO | S_ISVTX)) | S_IFDIR;
	rc = wbc_cache_enter(dir, dchild);
	if (rc > 0) { /* inode is reserved in MemFS. */
		rc = wbc_new_node(dir, dchild, NULL, mode, 0, LUSTRE_OPC_MKDIR);
		if (!rc)
			inc_nlink(dir);
	} else if (rc == 0) {
		rc = ll_dir_inode_operations.mkdir(dir, dchild, mode);
	}

	wbc_cache_leave(dir, LUSTRE_OPC_MKDIR);

	RETURN(rc);
}

static int memfs_link(struct dentry *old_dentry, struct inode *dir,
		      struct dentry *new_dentry)
{
	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(dir)));

	/* XXX Need to ensure we are in the same dir. */
	RETURN(simple_link(old_dentry, dir, new_dentry));
}

static int memfs_remove_policy(struct inode *dir, struct dentry *dchild,
			       bool rmdir)
{
	struct inode *inode = dchild->d_inode;
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct wbc_conf *conf = &ll_i2wbcs(dir)->wbcs_conf;

	ENTRY;

	if (!wbc_mode_lock_keep(wbci) || !wbc_inode_was_flushed(wbci))
		RETURN(0);

	switch (conf->wbcc_rmpol) {
	case WBC_RMPOL_SYNC:
		RETURN(rmdir ? ll_dir_inode_operations.rmdir(dir, dchild) :
			       ll_dir_inode_operations.unlink(dir, dchild));
	default:
		RETURN(0);
	}
}

static int memfs_rmdir(struct inode *dir, struct dentry *dchild)
{
	struct wbc_inode *wbci = ll_i2wbci(dir);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_complete(wbci)) {
		rc = memfs_remove_policy(dir, dchild, true);
		if (rc)
			GOTO(up_rwsem, rc);

		rc = simple_rmdir(dir, dchild);
	} else {
		LASSERT(wbc_inode_written_out(wbci));
		rc = ll_dir_inode_operations.rmdir(dir, dchild);
		if (rc)
			GOTO(up_rwsem, rc);

		if (wbc_inode_reserved(ll_i2wbci(dchild->d_inode)))
			rc = simple_rmdir(dir, dchild);
	}

up_rwsem:
	up_read(&wbci->wbci_rw_sem);
	RETURN(rc);
}

static int memfs_unlink(struct inode *dir, struct dentry *dchild)
{
	struct wbc_inode *wbci = ll_i2wbci(dir);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_complete(wbci)) {
		rc = memfs_remove_policy(dir, dchild, false);
		if (rc)
			GOTO(up_rwsem, rc);

		rc = simple_unlink(dir, dchild);
	} else {
		rc = ll_dir_inode_operations.unlink(dir, dchild);
		if (rc)
			GOTO(up_rwsem, rc);

		if (wbc_inode_reserved(ll_i2wbci(dchild->d_inode)))
			rc = simple_unlink(dir, dchild);
	}

up_rwsem:
	up_read(&wbci->wbci_rw_sem);
	RETURN(rc);
}

static int memfs_rename(struct inode *src, struct dentry *src_dchild,
			struct inode *tgt, struct dentry *tgt_dchild
#ifdef HAVE_IOPS_RENAME_WITH_FLAGS
			, unsigned int flags
#endif
			)
{
	int rc;

	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(src)));

	if (!wbc_inode_complete(ll_i2wbci(src)) ||
	    !wbc_inode_complete(ll_i2wbci(tgt)))
		RETURN(-EXDEV);

	rc = simple_rename(src, src_dchild, tgt, tgt_dchild
#ifdef HAVE_IOPS_RENAME_WITH_FLAGS
			   , flags
#endif
			  );
	if (rc)
		RETURN(rc);

	d_move(src_dchild, tgt_dchild);
	RETURN(wbcfs_d_init(tgt_dchild));
}

/*
 * Find page in cache, or allocate.
 */
static int memfs_write_getpage(struct inode *inode, pgoff_t index,
			       struct page **pagep)
{
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfp_mask = mapping_gfp_mask(mapping);
	struct page *page;
	int rc;

	ENTRY;

repeat:
	page = find_lock_page(mapping, index);
	if (page)
		GOTO(found, rc = 0);

	/*
	 * Fast cache lookup did not find it: allocate it.
	 */
	if (!wbc_inode_acct_page(inode, 1))
		RETURN(-ENOSPC);

	page = __page_cache_alloc(gfp_mask);
	if (!page)
		GOTO(unacct_page, rc = -ENOMEM);

	rc = add_to_page_cache_lru(page, mapping, index, gfp_mask);
	if (unlikely(rc)) {
		put_page(page);
		GOTO(unacct_page, rc);
	}
found:
	wait_for_stable_page(page);
	*pagep = page;
	RETURN(0);

unacct_page:
	wbc_inode_unacct_pages(inode, 1);
	if (rc == -EEXIST)
		GOTO(repeat, rc);

	RETURN(rc);
}

static int memfs_write_begin(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned flags,
			     struct page **pagep, void **fsdata)
{
	struct inode *inode = file_inode(file);
	struct wbc_inode *wbci = ll_i2wbci(inode);
	pgoff_t index = pos >> PAGE_SHIFT;
	int rc;

	ENTRY;

	LASSERT(wbc_inode_data_caching(wbci));

	rc = memfs_write_getpage(inode, index, pagep);
	if (rc == -ENOSPC) {
		int rc2;

		up_read(&wbci->wbci_rw_sem);
		rc2 = wbc_make_data_commit(file->f_path.dentry);
		down_read(&wbci->wbci_rw_sem);
		if (rc2)
			rc = rc2;
	}

	RETURN(rc);
}

static int memfs_write_end(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned len, unsigned copied,
			   struct page *page, void *fsdata)
{
	struct inode *inode = file_inode(file);

	ENTRY;

	LASSERT(wbc_inode_data_caching(ll_i2wbci(inode)));

	if (pos + copied > inode->i_size)
		i_size_write(inode, pos + copied);

	if (!PageUptodate(page)) {
		if (copied < PAGE_SIZE) {
			unsigned from = pos & (PAGE_SIZE - 1);

			zero_user_segments(page, 0, from,
					from + copied, PAGE_SIZE);
		}
		SetPageUptodate(page);
	}
	set_page_dirty(page);
	unlock_page(page);
	put_page(page);

	return copied;
}

static loff_t memfs_file_seek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file_inode(file);

	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(inode)));

	RETURN(generic_file_llseek(file, offset, origin));
}

static int memfs_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);

	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(inode)));
	/* Not support now */
	RETURN(0);
}

/*
 * TODO: Add fsync(2) support for the WBC_FLUSH_LAZY and WBC_FLUSH_AGING_KEEP
 * flush mode. It needs to reopen the file from MDT when the root WBC EX lock
 * is revoking.
 */
static int memfs_fsync(struct file *file, loff_t start,
		       loff_t end, int datasync)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc = 0;

	ENTRY;

	if (!(wbc_inode_was_flushed(wbci)))
		rc = wbc_make_inode_sync(dentry);

	if (S_ISREG(inode->i_mode)) {
		down_write(&wbci->wbci_rw_sem);
		rc = wbcfs_commit_cache_pages(inode);
		up_write(&wbci->wbci_rw_sem);
	}

	if (rc)
		RETURN(rc);

	LASSERT(wbc_inode_written_out(wbci));
	RETURN(ll_fsync(file, start, end, datasync));
}

static ssize_t memfs_file_splice_read(struct file *in_file, loff_t *ppos,
				      struct pipe_inode_info *pipe,
				      size_t count, unsigned int flags)
{
	struct inode *inode = file_inode(in_file);

	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(inode)));
	/* XXX Clearly we cannot leave it like this for production! */
	RETURN(0);
}

#ifdef HAVE_INODEOPS_ENHANCED_GETATTR
static int memfs_getattr(const struct path *path, struct kstat *stat,
			 u32 request_mask, unsigned int flags)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = dentry->d_inode;
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_has_protected(wbci))
		rc = simple_getattr(path, stat, request_mask, flags);
	else
		rc = inode->i_op->getattr(path, stat, request_mask, flags);
	up_read(&wbci->wbci_rw_sem);

	RETURN(rc);
}
#else
static int memfs_getattr(struct vfsmount *mnt, struct dentry *de,
			 struct kstat *stat)
{
	struct inode *inode = de->d_inode;
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_has_protected(wbci))
		rc = simple_getattr(mnt, de, stat);
	else
		rc = inode->i_op->getattr(mnt, de, stat);
	up_read(&wbci->wbci_rw_sem);

	RETURN(rc);
}
#endif

static int memfs_file_open(struct inode *inode, struct file *file)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_has_protected(wbci)) {
		struct ll_file_data *fd;
		struct dentry *dentry = file_dentry(file);
		struct wbc_dentry *wbcd = ll_d2wbcd(dentry);
		__u64 flags = file->f_flags;

		fd = ll_file_data_get();
		if (fd == NULL)
			GOTO(up_rwsem, rc = -ENOMEM);

		fd->fd_file = file;
		file->private_data = fd;
		ll_readahead_init(inode, &fd->fd_ras);

		if ((flags + 1)  & O_ACCMODE)
			flags++;
		if (file->f_flags & O_TRUNC)
			flags |= FMODE_WRITE;
		fd->fd_omode = flags & (FMODE_READ | FMODE_WRITE | FMODE_EXEC);

		/* ll_cl_context intiialize */
		INIT_LIST_HEAD(&fd->fd_wbc_open_item);

		/* Pin dentry, thus it will keep in MemFS until unlink. */
		dget(dentry);
		spin_lock(&wbcd->wbcd_open_lock);
		list_add(&fd->fd_wbc_open_item, &wbcd->wbcd_open_files);
		spin_unlock(&wbcd->wbcd_open_lock);

		GOTO(up_rwsem, rc = 0);
	} else {
		rc = ll_i2sbi(inode)->ll_fop->open(inode, file);
	}
up_rwsem:
	up_read(&wbci->wbci_rw_sem);
	RETURN(rc);
}

static int memfs_file_release(struct inode *inode, struct file *file)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_has_protected(wbci)) {
		struct ll_file_data *fd;
		struct dentry *dentry = file_dentry(file);
		struct wbc_dentry *wbcd = ll_d2wbcd(dentry);

		fd = file->private_data;
		spin_lock(&wbcd->wbcd_open_lock);
		list_del_init(&fd->fd_wbc_open_item);
		spin_unlock(&wbcd->wbcd_open_lock);
		ll_file_data_put(fd);
		file->private_data = NULL;
		dput(dentry); /* Unpin from open(). */

		GOTO(up_rwsem, rc = 0);
	} else {
		rc = ll_i2sbi(inode)->ll_fop->release(inode, file);
	}
up_rwsem:
	up_read(&wbci->wbci_rw_sem);
	RETURN(rc);
}

#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
static int memfs_getpage(struct inode *inode, pgoff_t index,
			 struct page **pagep)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;

	if (index > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return -EFBIG;

	page = find_lock_entry(mapping, index);
	/* fallocated page? */
	if (page && !PageUptodate(page)) {
		unlock_page(page);
		put_page(page);
		page = NULL;
	}

	*pagep = page;
	return 0;
}

/* linux/mm/shmem.c shmem_file_read_iter() */
static ssize_t __memfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	loff_t *ppos = &iocb->ki_pos;
	unsigned long offset;
	ssize_t retval = 0;
	pgoff_t index;
	int error = 0;

	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(inode)));

	/*
	 * Might this read be for a stacking filesystem?  Then when reading
	 * holes of a sparse file, we actually need to allocate those pages,
	 * and even mark them dirty, so it cannot exceed the max_pages limit.
	 */

	index = *ppos >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page = NULL;
		pgoff_t end_index;
		unsigned long nr, ret;
		loff_t i_size = i_size_read(inode);

		end_index = i_size >> PAGE_SHIFT;
		if (index > end_index)
			break;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset)
				break;
		}

		error = memfs_getpage(inode, index, &page);
		if (error) {
			if (error == -EINVAL)
				error = 0;
			break;
		}
		if (page)
			unlock_page(page);

		/*
		 * We must evaluate after, since reads (unlike writes)
		 * are called without i_mutex protection against truncate
		 */
		nr = PAGE_SIZE;
		i_size = i_size_read(inode);
		end_index = i_size >> PAGE_SHIFT;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset) {
				if (page)
					put_page(page);
				break;
			}
		}
		nr -= offset;

		if (page) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_page(page);
			/*
			 * Mark the page accessed if we read the beginning.
			 */
			if (!offset)
				mark_page_accessed(page);
		} else {
			page = ZERO_PAGE(0);
			get_page(page);
		}

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 */
		ret = copy_page_to_iter(page, offset, nr, to);
		retval += ret;
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;

		put_page(page);
		if (!iov_iter_count(to))
			break;
		if (ret < nr) {
			error = -EFAULT;
			break;
		}
		cond_resched();
	}

	*ppos = ((loff_t) index << PAGE_SHIFT) + offset;
	file_accessed(file);
	return retval ? retval : error;
}

static ssize_t memfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_data_caching(wbci))
		rc = __memfs_file_read_iter(iocb, to);
	else
		rc = ll_i2sbi(inode)->ll_fop->read_iter(iocb, to);
	up_read(&wbci->wbci_rw_sem);

	RETURN(rc);
}

static ssize_t memfs_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
repeat:
	if (wbc_inode_data_caching(wbci)) {
		rc = generic_file_write_iter(iocb, iter);
		if (rc == -ENOSPC)
			GOTO(repeat, rc);
	} else {
		rc = ll_i2sbi(inode)->ll_fop->write_iter(iocb, iter);
	}
	up_read(&wbci->wbci_rw_sem);

	RETURN(rc);
}

#else

/*
 * It can not use simple_readpage() directly in Linux ramfs especially when
 * there are holes in the file which is cached MemFS. It must rewrite the read
 * VFS interface similar to Linux tmpfs.
 */
/* linux/mm/filemap.c */
static int memfs_file_read_actor(read_descriptor_t *desc, struct page *page,
				 unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long left, count = desc->count;

	if (size > count)
		size = count;

	/*
	 * Faults on the destination of a read are common, so do it before
	 * taking the kmap.
	 */
	if (IS_ENABLED(CONFIG_HIGHMEM) &&
	    !fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page);
		left = __copy_to_user_inatomic(desc->arg.buf,
						kaddr + offset, size);
		kunmap_atomic(kaddr);
		if (left == 0)
			goto success;
	}

	/* Do it the slow way */
	kaddr = kmap(page);
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);
	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
success:
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

/*
 * linux/mm/shmem.c
 * TODO: mmap support.
 */
static int memfs_getpage(struct inode *inode, pgoff_t index,
			 struct page **pagep)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;

	if (index > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return -EFBIG;

	page = __find_lock_page(mapping, index);
	/* fallocated page? */
	if (page && !PageUptodate(page)) {
		unlock_page(page);
		put_page(page);
		page = NULL;
	}

	*pagep = page;
	return 0;
}

/* linux/mm/shmem.c do_shmem_file_read() */
static void do_memfs_file_read(struct file *filp,
			       loff_t *ppos, read_descriptor_t *desc,
			       read_actor_t actor)
{
	struct inode *inode = file_inode(filp);
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index;
	unsigned long offset;

	/*
	 * Might this read be for a stacking filesystem?  Then when reading
	 * holes of a sparse file, we actually need to allocate those pages,
	 * and even mark them dirty, so it cannot exceed the max_pages limit.
	 */

	index = *ppos >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page = NULL;
		pgoff_t end_index;
		unsigned long nr, ret;
		loff_t i_size = i_size_read(inode);

		end_index = i_size >> PAGE_SHIFT;
		if (index > end_index)
			break;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset)
				break;
		}

		desc->error = memfs_getpage(inode, index, &page);
		if (desc->error) {
			if (desc->error == -EINVAL)
				desc->error = 0;
			break;
		}
		if (page)
			unlock_page(page);

		/*
		 * We must evaluate after, since reads (unlike writes)
		 * are called without i_mutex protection against truncate
		 */
		nr = PAGE_SIZE;
		i_size = i_size_read(inode);
		end_index = i_size >> PAGE_SHIFT;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset) {
				if (page)
					put_page(page);
				break;
			}
		}
		nr -= offset;

		if (page) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_page(page);
			/*
			 * Mark the page accessed if we read the beginning.
			 */
			if (!offset)
				mark_page_accessed(page);
		} else {
			page = ZERO_PAGE(0);
			get_page(page);
		}

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		ret = actor(desc, page, offset, nr);
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;

		put_page(page);
		if (ret != nr || !desc->count)
			break;

		cond_resched();
	}

	*ppos = ((loff_t) index << PAGE_SHIFT) + offset;
	file_accessed(filp);
}

static ssize_t __memfs_file_aio_read(struct kiocb *iocb,
				     const struct iovec *iov,
				     unsigned long nr_segs, loff_t pos)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct file *filp = iocb->ki_filp;
	ssize_t retval;
	unsigned long seg;
	size_t count;
	loff_t *ppos = &iocb->ki_pos;

	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(inode)));

	retval = generic_segment_checks(iov, &nr_segs, &count, VERIFY_WRITE);
	if (retval)
		return retval;

	for (seg = 0; seg < nr_segs; seg++) {
		read_descriptor_t desc;

		desc.written = 0;
		desc.arg.buf = iov[seg].iov_base;
		desc.count = iov[seg].iov_len;
		if (desc.count == 0)
			continue;
		desc.error = 0;
		do_memfs_file_read(filp, ppos, &desc, memfs_file_read_actor);
		retval += desc.written;
		if (desc.error) {
			retval = retval ?: desc.error;
			break;
		}
		if (desc.count > 0)
			break;
	}
	return retval;
}

static ssize_t memfs_file_aio_read(struct kiocb *iocb,
				   const struct iovec *iov,
				   unsigned long nr_segs, loff_t pos)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct wbc_inode *wbci = ll_i2wbci(inode);

	ENTRY;

	LASSERT(wbc_inode_has_protected(wbci));

	if (wbc_inode_data_committed(wbci))
		RETURN(ll_i2sbi(inode)->ll_fop->aio_read(iocb, iov,
							 nr_segs, pos));
	else
		RETURN(__memfs_file_aio_read(iocb, iov, nr_segs, pos));
}

static ssize_t memfs_file_read(struct file *file, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_data_caching(wbci))
		rc = do_sync_read(file, buf, count, ppos);
	else
		rc = ll_i2sbi(inode)->ll_fop->read(file, buf, count, ppos);
	up_read(&wbci->wbci_rw_sem);

	RETURN(rc);
}

static ssize_t memfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
				    unsigned long nr_segs, loff_t pos)
{
	struct wbc_inode *wbci = ll_i2wbci(file_inode(iocb->ki_filp));

	ENTRY;

	LASSERT(wbc_inode_data_caching(wbci));

	RETURN(generic_file_aio_write(iocb, iov, nr_segs, pos));
}

static ssize_t memfs_file_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
repeat:
	if (wbc_inode_data_caching(wbci)) {
		rc = do_sync_write(file, buf, count, ppos);
		if (rc == -ENOSPC)
			GOTO(repeat, rc);
	} else {
		rc = ll_i2sbi(inode)->ll_fop->write(file, buf, count, ppos);
	}
	up_read(&wbci->wbci_rw_sem);

	RETURN(rc);
}
#endif /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */

static int memfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);

	ENTRY;

	LASSERT(wbc_inode_has_protected(ll_i2wbci(inode)));
	RETURN(generic_file_mmap(file, vma));
}

static int memfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	ENTRY;

	down_read(&wbci->wbci_rw_sem);
	if (wbc_inode_has_protected(wbci)) {
		rc = setattr_prepare(&init_user_ns, dentry, attr);
		if (rc)
			GOTO(up_rwsem, rc);

		if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
			struct address_space *mapping = inode->i_mapping;
			unsigned long nr_pages = mapping->nrpages;
			loff_t oldsize = inode->i_size;

			if (wbc_inode_data_committed(wbci)) {
				inode_unlock(inode);
				rc = cl_setattr_ost(ll_i2info(inode)->lli_clob,
						    attr,
						    OP_XVALID_OWNEROVERRIDE, 0);
				inode_lock(inode);
				inode_dio_wait(inode);
				inode_has_no_xattr(inode);
			} else {
				truncate_setsize(inode, attr->ia_size);
				if (attr->ia_size < oldsize)
					wbc_inode_unacct_pages(inode,
						nr_pages - mapping->nrpages);
			}
		}

		if (rc)
			GOTO(up_rwsem, rc);

		setattr_copy(&init_user_ns, inode, attr);
		wbci->wbci_dirty_flags |= WBC_DIRTY_FL_ATTR;
		wbci->wbci_dirty_attr |= attr->ia_valid;
		spin_unlock(&inode->i_lock);
		if (wbc_flush_mode_aging(wbci))
			mark_inode_dirty(inode);
	} else {
		LASSERT(wbc_inode_none(wbci));
		rc = inode->i_op->setattr(dentry, attr);
	}
up_rwsem:
	up_read(&wbci->wbci_rw_sem);
	RETURN(rc);
}

static int memfs_mknod(struct inode *dir, struct dentry *dchild,
		       umode_t mode, dev_t rdev)
{
	int rc;

	ENTRY;

	if (!IS_POSIXACL(dir) || !exp_connect_umask(ll_i2mdexp(dir)))
		mode &= ~current_umask();

	switch (mode & S_IFMT) {
	case 0:
		mode |= S_IFREG;
		/* fallthrough */
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK: {
		struct wbc_inode *wbci = ll_i2wbci(dir);

		rc = wbc_cache_enter(dir, dchild);
		/* The inode was reserved in MemFS successfully. */
		if (rc > 0) {
			rc = wbc_new_node(dir, dchild, NULL, mode,
					  old_encode_dev(rdev),
					  LUSTRE_OPC_MKNOD);
		} else if (rc == 0) {
			LASSERT(wbc_inode_written_out(wbci));
			rc = ll_dir_inode_operations.mknod(dir, dchild,
							   mode, rdev);
		}
		wbc_cache_leave(dir, LUSTRE_OPC_MKNOD);
		break;
	}
	case S_IFDIR:
		rc = -EPERM;
		break;
	default:
		rc = -EINVAL;
	}

	RETURN(rc);
}

static int memfs_create_nd(struct inode *dir, struct dentry *dentry,
			   umode_t mode, bool want_excl)
{
	int rc;

	ENTRY;

	rc = wbc_cache_enter(dir, dentry);
	if (rc > 0)
		rc = wbc_new_node(dir, dentry, NULL, mode, 0,
				  LUSTRE_OPC_CREATE);
	else if (rc == 0)
		rc = ll_dir_inode_operations.create(dir, dentry, mode,
						    want_excl);
	wbc_cache_leave(dir, LUSTRE_OPC_CREATE);
	RETURN(rc);
}

static int memfs_symlink(struct inode *dir, struct dentry *dchild,
			 const char *oldpath)
{
	int rc;

	ENTRY;

	rc = wbc_cache_enter(dir, dchild);
	if (rc > 0)
		rc = wbc_new_node(dir, dchild, oldpath, S_IFLNK | S_IRWXUGO, 0,
				  LUSTRE_OPC_SYMLINK);
	else if (rc == 0)
		rc = ll_dir_inode_operations.symlink(dir, dchild, oldpath);
	wbc_cache_leave(dir, LUSTRE_OPC_SYMLINK);
	RETURN(rc);
}

#ifdef HAVE_IOP_GET_LINK
const char *memfs_get_link(struct dentry *dentry, struct inode *inode,
			   struct delayed_call *done)
{
	return ll_i2info(inode)->lli_symlink_name;
}

#else

static void *memfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, ll_i2info(dentry->d_inode)->lli_symlink_name);
	return NULL;
}
#endif /* HAVE_IOP_GET_LINK */

static const struct file_operations memfs_dir_operations = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.llseek		= dcache_dir_lseek,
	.read		= generic_read_dir,
#ifdef HAVE_DIR_CONTEXT
	.iterate_shared	= dcache_readdir,
#else
	.readdir	= dcache_readdir,
#endif
	.fsync		= memfs_fsync,
	.unlocked_ioctl	= wbc_ioctl,
};

static const struct inode_operations memfs_dir_inode_operations = {
	.mknod		= memfs_mknod,
	.lookup		= memfs_lookup_nd,
	.create		= memfs_create_nd,
	.unlink		= memfs_unlink,
	.mkdir		= memfs_mkdir,
	.rmdir		= memfs_rmdir,
	.symlink	= memfs_symlink,
	.link		= memfs_link,
	.rename		= memfs_rename,
	.setattr	= memfs_setattr,
	.getattr	= memfs_getattr,
};

static const struct inode_operations memfs_file_inode_operations = {
	.setattr	= memfs_setattr,
	.getattr	= memfs_getattr,
};

static const struct file_operations memfs_file_operations = {
#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
# ifdef HAVE_SYNC_READ_WRITE
	.read		= new_sync_read,
	.write		= new_sync_write,
# endif
	.read_iter	= memfs_file_read_iter,
	.write_iter	= memfs_file_write_iter,
#else /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.read		= memfs_file_read,
	.aio_read	= memfs_file_aio_read,
	.write		= memfs_file_write,
	.aio_write	= memfs_file_aio_write,
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.unlocked_ioctl	= wbc_ioctl,
	.open		= memfs_file_open,
	.release	= memfs_file_release,
	.mmap		= memfs_file_mmap,
	.llseek		= memfs_file_seek,
	.splice_read	= memfs_file_splice_read,
	.fsync		= memfs_fsync,
	.flush		= memfs_flush
};

/*
 * TODO: using page_symlink() to store long symlink name.
 */
static const struct inode_operations memfs_fast_symlink_inode_operations = {
#ifdef HAVE_IOP_GENERIC_READLINK
	.readlink	= generic_readlink,
#endif
#ifdef HAVE_IOP_GET_LINK
	.get_link	= memfs_get_link,
#else
	.follow_link	= memfs_follow_link,
#endif
};

static const struct address_space_operations memfs_aops = {
	/*
	 * TODO: reimplemet ->set_page_dirty() interface.
	 * - The call __set_page_dirty_nobuffers will mark the inode diry and
	 *   put the inode into the writeback control list. Instead, it would
	 *   better to call mark_inode_dirty() only one time when close the file
	 *   once the file data was modified.
	 * - Here it can be optimized to use light weight function:
	 *   __set_page_dirty_no_writeback(); The writeback related data
	 *   structure can be delayed to initilize during data assimliation.
	 */
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.write_begin	= memfs_write_begin,
	.write_end	= memfs_write_end,
};

void wbc_inode_operations_set(struct inode *inode, umode_t mode, dev_t dev)
{
	switch (mode & S_IFMT) {
	default:
		init_special_inode(inode, mode, dev);
		break;
	case S_IFREG:
		inode->i_op = &memfs_file_inode_operations;
		inode->i_fop = &memfs_file_operations;
		inode->i_mapping->a_ops = &memfs_aops;
		break;
	case S_IFDIR:
		inode->i_op = &memfs_dir_inode_operations;
		inode->i_fop = &memfs_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &memfs_fast_symlink_inode_operations;
		break;
	}
}
