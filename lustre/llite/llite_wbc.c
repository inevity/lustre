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
 * Copyright (c) 2019, 2021, DDN Storage Corporation.
 */
/*
 * lustre/llite/llite_wbc.c
 *
 * Lustre Metadata Writeback Caching (WBC) Implementation
 *
 * Author: Oleg Drokin <green@whamcloud.com>
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include "llite_internal.h"

long wbc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc = 0;

	ENTRY;

	switch (cmd) {
	case LL_IOC_WBC_STATE: {
		struct lu_wbc_state __user *ustate =
			(struct lu_wbc_state __user *)arg;
		struct lu_wbc_state *state;

		OBD_ALLOC_PTR(state);
		if (state == NULL)
			RETURN(-ENOMEM);

		state->wbcs_fmode = inode->i_mode;
		state->wbcs_flags = wbci->wbci_flags;
		state->wbcs_cache_mode = wbci->wbci_cache_mode;
		state->wbcs_flush_mode = wbci->wbci_flush_mode;

		if (copy_to_user(ustate, state, sizeof(*state)))
			GOTO(out_state, rc = -EFAULT);
out_state:
		OBD_FREE_PTR(state);
		RETURN(rc);
	}
	default:
		RETURN(-ENOTTY);
	}
}

void wbcfs_inode_operations_switch(struct inode *inode)
{
	if (S_ISDIR(inode->i_mode)) {
		inode->i_fop = &ll_dir_operations;
		inode->i_op = &ll_dir_inode_operations;
	} else if (S_ISREG(inode->i_mode)) {
		struct ll_sb_info *sbi = ll_i2sbi(inode);

		inode->i_op = &ll_file_inode_operations;
		inode->i_fop = sbi->ll_fop;
		inode->i_mapping->a_ops = &ll_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &ll_fast_symlink_inode_operations;
	} else {
		inode->i_op = &ll_special_inode_operations;
		init_special_inode(inode, inode->i_mode,
				   inode->i_rdev);
	}
}

/*
 * Same as ll_d_init(), but init with valid flags.
 */
int wbcfs_d_init(struct dentry *de)
{
	struct ll_dentry_data *lld;

	ENTRY;

	LASSERT(de != NULL);

	CDEBUG(D_DENTRY, "ldd on dentry %.*s (%p) parent %p inode %p refc %d\n",
		de->d_name.len, de->d_name.name, de, de->d_parent, de->d_inode,
		ll_d_count(de));

	if (de->d_fsdata == NULL) {
		OBD_ALLOC_PTR(lld);
		if (likely(lld != NULL)) {
			spin_lock(&de->d_lock);
			if (likely(de->d_fsdata == NULL)) {
				de->d_fsdata = lld;
				wbc_dentry_init(de);
			} else {
				OBD_FREE_PTR(lld);
			}
			spin_unlock(&de->d_lock);
		} else {
			RETURN(-ENOMEM);
		}
	} else {
		/* Maybe no necessary, but for check and safety. */
		spin_lock(&de->d_lock);
		lld = ll_d2d(de);
		LASSERT(lld != NULL);
		lld->lld_invalid = 0;
		spin_unlock(&de->d_lock);
	}
	LASSERT(de->d_op == &ll_d_ops);

	RETURN(0);
}

static void wbc_fini_op_item(struct md_op_item *item)
{
	struct md_op_data *op_data = &item->mop_data;

	ll_unlock_md_op_lsm(op_data);
	security_release_secctx(op_data->op_file_secctx,
				op_data->op_file_secctx_size);
	OBD_FREE_PTR(item);
}

static inline void wbc_prep_exlock_common(struct md_op_item *item, int it_op)
{
	struct ldlm_enqueue_info *einfo = &item->mop_einfo;

	item->mop_it.it_op = it_op;
	einfo->ei_type = LDLM_IBITS;
	einfo->ei_mode = it_to_lock_mode(&item->mop_it);
	einfo->ei_cb_bl = ll_md_blocking_ast;
	einfo->ei_cb_cp = ldlm_completion_ast;
	einfo->ei_cb_gl = NULL;
	einfo->ei_cbdata = NULL;
	item->mop_lock_flags = LDLM_FL_INTENT_PARENT_LOCKED |
			       LDLM_FL_INTENT_EXLOCK_UPDATE;
}

static int wbc_create_exlock_cb(struct req_capsule *pill,
			       struct md_op_item *item, int rc)
{
	struct lookup_intent *it = &item->mop_it;
	struct dentry *dentry = item->mop_dentry;
	struct inode *inode = dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct wbc_inode *wbci = &lli->lli_wbc_inode;

	ENTRY;

	/*
	 * TODO: handling for error return.
	 * Discard the cached data, remove the whole subtree?
	 * Or notify the user via console messages.
	 */
	if (rc) {
		CERROR("Failed to async create: rc = %d!\n", rc);
		mapping_clear_unevictable(inode->i_mapping);
		GOTO(out_dput, rc);
	}

	/* Must return with EX lock. */
	if (it->it_lock_mode != LCK_EX)
		GOTO(out_dput, rc = -EPROTO);

	ll_set_lock_data(ll_i2mdexp(inode), inode, it, NULL);

	/*
	 * TODO: Currently the file layout for a regular file Must be
	 * instantiated when create the metadata file object.
	 * However, this can be optimized that instantiate the layout in need
	 * when the file is being written.
	 */
	rc = ll_prep_inode(&inode, pill, dentry->d_sb, it);
	if (rc)
		GOTO(out_dput, rc);

	LASSERT((wbci->wbci_flags & WBC_STATE_FL_PROTECTED) &&
		(wbci->wbci_flags & WBC_STATE_FL_COMPLETE));
	wbci->wbci_flags |= WBC_STATE_FL_ROOT | WBC_STATE_FL_SYNC;
	wbci->wbci_lock_handle.cookie = it->it_lock_handle;

	/*
	 * We got a lock handle from this intent, and potentially
	 * the request that needs extra decrefs, so deal with it.
	 */
	ll_intent_release(it);

out_dput:
	/* Unpin the dentry now as it is stable. */
	dput(dentry);

	wbc_fini_op_item(item);

	RETURN(rc);
}

static int wbc_fill_create_common(struct inode *dir,
				  struct dentry *dchild,
				  struct md_op_data *op_data,
				  struct lookup_intent *it)
{
	struct inode *inode = dchild->d_inode;
	int opc;

	ENTRY;

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		opc = LUSTRE_OPC_MKDIR;
		break;
	case S_IFLNK:
		opc = LUSTRE_OPC_SYMLINK;
		break;
	case S_IFREG:
	default:
		opc = LUSTRE_OPC_CREATE;
	}

	op_data = ll_prep_md_op_data(op_data, dir, inode,
				     dchild->d_name.name, dchild->d_name.len,
				     inode->i_mode, opc, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	/*
	 * TODO: It should set the file attributes such as timestamps, uid/gid,
	 * mode for the file correctly (If the file attributes was modified
	 * after created in MemFS.
	 */
	op_data->op_fsuid = from_kuid(&init_user_ns, inode->i_uid);
	op_data->op_fsgid = from_kgid(&init_user_ns, inode->i_gid);
	op_data->op_cap = current_cap();

	if (S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode))
		op_data->op_rdev = old_encode_dev(inode->i_rdev);

	if (opc == LUSTRE_OPC_SYMLINK) {
		struct ll_inode_info *lli = ll_i2info(inode);

		LASSERT(lli->lli_symlink_name);

		op_data->op_data = lli->lli_symlink_name;
		op_data->op_data_size = strlen(lli->lli_symlink_name) + 1;
	}

	/* Tell lmv we got the child fid under control */
	it->it_flags = MDS_OPEN_BY_FID;

	if (!IS_POSIXACL(dir))
		it->it_create_mode &= ~current_umask();

	/* FIXME: Set create mode correctly. */
	it->it_create_mode = inode->i_mode & S_IALLUGO;
	if (S_ISDIR(inode->i_mode)) {
		it->it_create_mode = (inode->i_mode & (S_IRWXUGO | S_ISVTX)) |
				     S_IFDIR;
	} else if (S_ISREG(inode->i_mode)) {
		it->it_create_mode = (inode->i_mode & S_IALLUGO) | S_IFREG;
		/*
		 * With the create intent flags MDS_FMODE_WRITE, the data
		 * objects for this regular file will be created, and the layout
		 * will be instantiated and return to the client.
		 * TODO:
		 * - Send the current size of the file to MDT, then it can
		 *   determine how to allocate data object more intelligent
		 *   accordingly.
		 * - Delay to allocate data objects and instantiate the layout
		 *   for this regular file unless it is necessary if file size
		 *   is zero.
		 */
		it->it_flags |= MDS_FMODE_WRITE;
	} else if (S_ISLNK(inode->i_mode)) {
		it->it_create_mode = S_IFLNK | S_IRWXUGO;
	}

	RETURN(0);
}

/*
 * Prepare arguments for async create RPC.
 */
static struct md_op_item *
wbc_prep_create_exlock(struct inode *dir, struct dentry *dchild,
		       unsigned int valid)
{
	struct md_op_item *item;
	int rc;

	OBD_ALLOC_PTR(item);
	if (item == NULL)
		return ERR_PTR(-ENOMEM);

	rc = wbc_fill_create_common(dir, dchild,
				    &item->mop_data, &item->mop_it);
	if (rc) {
		OBD_FREE_PTR(item);
		return ERR_PTR(rc);
	}

	wbc_prep_exlock_common(item, IT_CREAT);

	return item;
}

typedef struct md_op_item *(*md_prep_op_item_t)(struct inode *dir,
						struct dentry *dchild,
						unsigned int valid);

md_prep_op_item_t wbc_op_item_preps[MD_OP_MAX] = {
	[MD_OP_CREATE_EXLOCK]	= wbc_prep_create_exlock,
};

md_op_item_cb_t wbc_op_item_cbs[MD_OP_MAX] = {
	[MD_OP_CREATE_EXLOCK]	= wbc_create_exlock_cb,
};

static struct md_op_item *
wbc_prep_op_item(enum md_item_opcode opc, struct inode *dir,
		 struct dentry *dchild, struct ldlm_lock *lock,
		 unsigned int valid)
{
	struct md_op_item *item;

	if (opc >= MD_OP_MAX || wbc_op_item_preps[opc] == NULL ||
	    wbc_op_item_cbs[opc] == NULL)
		return ERR_PTR(-EINVAL);

	item = wbc_op_item_preps[opc](dir, dchild, valid);
	if (IS_ERR(item))
		return item;

	item->mop_opc = opc;
	item->mop_dentry = dchild;
	item->mop_cb = wbc_op_item_cbs[opc];

	if (lock)
		item->mop_data.op_open_handle = lock->l_remote_handle;

	return item;
}

/*
 * Write the cached data in MemFS into Lustre clio for an inode.
 * TODO: It need to ensure that generic IO must be blocked in this phase until
 * finished data assimilation.
 */
int wbcfs_commit_cache_pages(struct inode *inode)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct lu_env *env = NULL;
	struct cl_io *io = NULL;
	struct cl_lock *lock = NULL;
	struct cl_lock_descr *descr;
	struct cl_page_list queue;
	struct cl_page *page = NULL;
	struct pagevec pvec;
	pgoff_t index = 0;
	__u16 refcheck;
	loff_t isize;
	int nr_pages;
	unsigned int to;
	int rc;

	ENTRY;
	/* The file data has already assimilated from MemFS into Lustre. */
	if (wbci->wbci_flags & WBC_STATE_FL_DATA_COMMITTED)
		RETURN(0);

	isize = i_size_read(inode);
	if (isize == 0)
		GOTO(out, rc = 0);

	/* Get IO environment */
	rc = cl_io_get(inode, &env, &io, &refcheck);
	if (rc <= 0)
		GOTO(out, rc);

	/*
	 * It is still under the protection of root WBC EX lock where
	 * the granted cached ibits lock is MDS_INODELOCK_UPDATE |
	 * MDS_INODELOCK_LAYOUT at the time of the lock revocation.
	 */
	io->ci_ignore_layout = 1;
	rc = cl_io_init(env, io, CIT_MISC, io->ci_obj);
	if (rc) {
		/*
		 * If rc > 0, it means that the layout of the file is not yet
		 * instantiated. Nothing to do for this IO, return immediately.
		 */
		rc = io->ci_result;
		GOTO(out_env_put, rc);
	}

	lock = vvp_env_lock(env);
	descr = &lock->cll_descr;
	memset(descr, 0, sizeof(*descr)); /* XXX ??? */
	descr->cld_obj = io->ci_obj;
	descr->cld_mode = CLM_WRITE;
	descr->cld_start = 0;
	descr->cld_end = CL_PAGE_EOF; /* Could be cl_index(io->ci_obj, isize) */
	descr->cld_enq_flags = /*CEF_GLIMPSE parallel|*/ CEF_MUST;

	rc = cl_lock_request(env, io, lock);
	if (rc < 0)
		GOTO(out_io_fini, rc);

	/*
	 * Now the client has acquired all locks for page cache in MemFS.
	 * It is the time to assimilate these pages in MemFS into Lustre
	 * page cache via clio engine.
	 * XXX Eventually we actually want to do it all in parallel as the
	 * individual sub locks complete, but it's too much hassle now.
	 */

	/*
	 * Here it is safe to release WBC EX lock that guards the layout,
	 * since IO has already acquired all the extent locks for data IO.
	 * Or It does not need to acquire any exent locks for data IO, and
	 * could hold WBC EX lock until finished data assimulation, sync
	 * the data to OSTs and discard the cached data.
	 */


	cl_page_list_init(&queue);
	ll_pagevec_init(&pvec, 0);
	do {
		int i;
		struct page *vmpage = NULL;

#ifdef HAVE_PAGEVEC_LOOKUP_THREE_PARAM
		nr_pages = pagevec_lookup(&pvec, inode->i_mapping, &index);
#else
		nr_pages = pagevec_lookup(&pvec, inode->i_mapping, index,
					  PAGEVEC_SIZE);
#endif

		for (i = 0 ; i < nr_pages ; i++) {
			vmpage = pvec.pages[i];
			/* XXX lock the page? */
			lock_page(vmpage);

			/* Cannot have any clean pages here! */
			LASSERT(PageDirty(vmpage));

			/*
			 * We are 100% sure that this page is not in the Lustre
			 * clio lists yet.
			 */
			page = cl_page_alloc(env, io->ci_obj, vmpage->index,
					    vmpage, CPT_CACHEABLE);
			if (IS_ERR(page)) {
				unlock_page(vmpage);
				pagevec_release(&pvec);
				GOTO(out_page_discard, rc = PTR_ERR(page));
			}

			lu_ref_add(&page->cp_reference, "cl_io", io);
			cl_page_assume(env, io, page);
			cl_page_list_add(&queue, page, true);
			/*
			 * TODO: Once accumulated one full RPC, commit it
			 * immediately.
			 */
		}

		/* Update the index for the next search */
		if (nr_pages > 0)
			index = vmpage->index + 1;

		pagevec_release(&pvec);
		cond_resched(); /* because why not? */
	} while (nr_pages > 0);

	to = isize & (PAGE_SIZE - 1);
	if (to == 0)
		to = PAGE_SIZE;
	else if (page)
		/* Update the size accordingly for the last page. */
		cl_page_clip(env, page, 0, to);

	rc = cl_io_commit_async(env, io, &queue, 0, to, write_commit_callback);

	/*
	 * Now the pages in queue were failed to commit, discard them unless
	 * they were dirtied before.
	 */
out_page_discard:
	while (queue.pl_nr > 0) {
		page = cl_page_list_first(&queue);
		cl_page_list_del(env, &queue, page);

		if (!PageDirty(cl_page_vmpage(page)))
			cl_page_discard(env, io, page);

		cl_page_disown(env, io, page);
		lu_ref_del(&page->cp_reference, "cl_io", io);
		cl_page_put(env, page);
	}

	cl_page_list_fini(env, &queue);
	cl_lock_release(env, lock);
out_io_fini:
	cl_io_fini(env, io);
out_env_put:
	cl_env_put(env, &refcheck);

out:
	if (rc < 0)
		CERROR("Failed to WBC data for inode %lu, discard data: %d\n",
		       inode->i_ino, rc);

	/* XXX failure handling. */
	wbci->wbci_flags |= WBC_STATE_FL_DATA_COMMITTED;

	/*
	 * TODO: IO must be blocked during switch.
	 */
	wbcfs_inode_operations_switch(inode);
	mapping_clear_unevictable(inode->i_mapping);

	RETURN(rc);
}

/*
 * TODO: Flush batchly for metadata updates.
 */
int wbcfs_flush_dir_children(struct inode *dir,
			     struct list_head *childlist,
			     struct ldlm_lock *lock)
{
	struct wbc_dentry *wbcd, *tmp;
	struct ptlrpc_request_set *rqset;
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct wbc_conf *conf = &sbi->ll_wbc_super.wbcs_conf;
	int limiter = 0;
	int rc = 0;
	int rc2;

	ENTRY;

	rqset = ptlrpc_prep_set();
	if (rqset == NULL)
		RETURN(-ENOMEM);

	list_for_each_entry_safe(wbcd, tmp, childlist, wbcd_flush_item) {
		struct ll_dentry_data *lld;
		struct dentry *dchild;
		struct md_op_item *item;

		lld = container_of(wbcd, struct ll_dentry_data, lld_wbc_dentry);
		dchild = lld->lld_dentry;
		item = wbc_prep_op_item(MD_OP_CREATE_EXLOCK, dir, dchild,
					lock, 0);
		if (IS_ERR(item))
			GOTO(out_rqset, rc = PTR_ERR(item));

		rc = md_intent_lock_async(sbi->ll_md_exp, item, rqset);
		if (rc) {
			CERROR("md_intent_lock_async error: %d\n", rc);
			wbc_fini_op_item(item);
			GOTO(out_rqset, rc);
		}

		list_del_init(&wbcd->wbcd_flush_item);
		limiter++;
		if (conf->wbcc_max_rpcs > 0 && limiter > conf->wbcc_max_rpcs) {
			rc = ptlrpc_set_wait(NULL, rqset);
			ptlrpc_set_destroy(rqset);
			if (rc)
				RETURN(rc);

			rqset = ptlrpc_prep_set();
			if (rqset == NULL)
				RETURN(-ENOMEM);

			limiter = 0;
		}
	}

	if (limiter) {
		rc2 = ptlrpc_set_wait(NULL, rqset);
		if (rc == 0)
			rc = rc2;
	}
out_rqset:
	ptlrpc_set_destroy(rqset);

	RETURN(rc);
}

void wbc_inode_lock_callback(struct inode *inode, struct ldlm_lock *lock,
			     bool *cached)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);

	ENTRY;

	*cached = wbc_inode_has_protected(wbci);
	if (!*cached)
		return;

	wbci->wbci_flags &= ~WBC_STATE_FL_PROTECTED;
	(void) wbc_inode_flush(inode, lock);
	wbci->wbci_flags = WBC_STATE_FL_NONE;
}

int wbc_root_init(struct inode *dir, struct inode *inode, struct dentry *dchild)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct wbc_super *super = ll_i2wbcs(inode);

	ENTRY;

	/*
	 * TODO: Set cache policy for this root WBC directory according to
	 * the predefined customized caching rules.
	 */
	wbci->wbci_cache_mode = super->wbcs_conf.wbcc_cache_mode;
	wbci->wbci_flush_mode = super->wbcs_conf.wbcc_flush_mode;
	wbc_inode_operations_set(inode, inode->i_mode, inode->i_rdev);

	/*
	 * Set this newly created directory with the state of
	 * Protected(P) | Sync(S) | Root(R) | Complete(C).
	 */
	wbci->wbci_flags = WBC_STATE_FL_ROOT | WBC_STATE_FL_PROTECTED |
			   WBC_STATE_FL_SYNC | WBC_STATE_FL_COMPLETE;

	RETURN(0);
}

/*
 * TODO: Customizable rule based auto WBC.
 * Define various auto caching rule for WBC on a client similar to TBF or PCC.
 * When a newly creating directory meets the rule condition, it can try to
 * obtain EX WBC lock from MDS and keep exclusive access on the directory
 * under the protection of the EX lock on the client.
 * The rule can be combination of uid/gid/projid/fname or jobid.
 * Moerover, it would better to return the customized WBC cache specification
 * here to set the cache mode and flush mode for the newly created directory.
 */
enum lu_mkdir_policy
ll_mkdir_policy_get(struct ll_sb_info *sbi, struct inode *dir,
		    struct dentry *dentry, umode_t mode,
		    __u64 *extra_lock_flags)
{
	struct wbc_conf *conf = &ll_i2wbcs(dir)->wbcs_conf;

	if (conf->wbcc_cache_mode == WBC_MODE_NONE) {
		*extra_lock_flags = 0;
		return sbi->ll_intent_mkdir_enabled ?
		       MKDIR_POL_INTENT : MKDIR_POL_REINT;
	}

	*extra_lock_flags = LDLM_FL_INTENT_EXLOCK_UPDATE;
	return MKDIR_POL_EXCL;
}

static int wbc_conf_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct wbc_conf *conf = ll_s2wbcc(sb);

	seq_printf(m, "cache_mode: %s\n",
		   wbc_cachemode2string(conf->wbcc_cache_mode));
	seq_printf(m, "flush_mode: %s\n",
		   wbc_flushmode2string(conf->wbcc_flush_mode));
	seq_printf(m, "max_rpcs: %u\n", conf->wbcc_max_rpcs);

	return 0;
}

static ssize_t wbc_conf_seq_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	char *kernbuf;
	int rc;

	if (count >= LPROCFS_WR_WBC_MAX_CMD)
		return -EINVAL;

	/*
	 * TODO: Check for the WBC support via the connection flag.
	 */
	OBD_ALLOC(kernbuf, count + 1);
	if (kernbuf == NULL)
		return -ENOMEM;

	if (copy_from_user(kernbuf, buffer, count))
		GOTO(out_free_kernbuff, rc = -EFAULT);

	rc = wbc_cmd_parse_and_handle(kernbuf, count, ll_s2wbcs(sb));
out_free_kernbuff:
	OBD_FREE(kernbuf, count + 1);
	return rc ? rc : count;
}
LDEBUGFS_SEQ_FOPS(wbc_conf);

static int wbc_flush_mode_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct wbc_conf *conf = ll_s2wbcc(sb);

	seq_printf(m, "%s\n", wbc_flushmode2string(conf->wbcc_flush_mode));

	return 0;
}

static ssize_t wbc_flush_mode_seq_write(struct file *file,
					const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct wbc_cmd cmd;
	char kernbuf[128];
	int rc;

	ENTRY;

	if (count >= sizeof(kernbuf))
		RETURN(-EINVAL);

	if (copy_from_user(kernbuf, buffer, count))
		RETURN(-EFAULT);

	kernbuf[count] = 0;
	memset(&cmd, 0, sizeof(cmd));
	if (strncmp(kernbuf, "lazy_drop", 9) == 0)
		cmd.wbcc_conf.wbcc_flush_mode = WBC_FLUSH_LAZY_DROP;
	else if (strncmp(kernbuf, "aging_drop", 10) == 0)
		cmd.wbcc_conf.wbcc_flush_mode = WBC_FLUSH_AGING_DROP;
	else
		RETURN(-EINVAL);

	cmd.wbcc_flags |= WBC_CMD_OP_FLUSH_MODE;
	rc = wbc_cmd_handle(ll_s2wbcs(sb), &cmd);
	RETURN(rc ? rc : count);
}

LDEBUGFS_SEQ_FOPS(wbc_flush_mode);

static int wbc_max_rpcs_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct wbc_conf *conf = ll_s2wbcc(sb);

	seq_printf(m, "%u\n", conf->wbcc_max_rpcs);

	return 0;
}

static ssize_t wbc_max_rpcs_seq_write(struct file *file,
				      const char __user *buffer,
				      size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct wbc_cmd cmd;
	unsigned int val;
	int rc;

	rc = kstrtouint_from_user(buffer, count, 0, &val);
	if (rc)
		return rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.wbcc_conf.wbcc_max_rpcs = val;
	cmd.wbcc_flags |= WBC_CMD_OP_MAX_RPCS;

	rc = wbc_cmd_handle(ll_s2wbcs(sb), &cmd);
	return rc ? rc : count;
}

LDEBUGFS_SEQ_FOPS(wbc_max_rpcs);

struct ldebugfs_vars ldebugfs_llite_wbc_vars[] = {
	{ .name =	"conf",
	  .fops =	&wbc_conf_fops		},
	{ .name =	"flush_mode",
	  .fops =	&wbc_flush_mode_fops	},
	{ .name =	"max_rpcs",
	  .fops =	&wbc_max_rpcs_fops,	},
	{ NULL }
};

/* Create sysfs/debugfs entries for WBC. */
void wbc_tunables_init(struct super_block *sb)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct wbc_super *wbcs = ll_s2wbcs(sb);

	wbcs->wbcs_debugfs_dir = debugfs_create_dir("wbc",
						    sbi->ll_debugfs_entry);
	ldebugfs_add_vars(wbcs->wbcs_debugfs_dir, ldebugfs_llite_wbc_vars, sb);
}

void wbc_tunables_fini(struct super_block *sb)
{
	struct wbc_super *wbcs = ll_s2wbcs(sb);

	debugfs_remove_recursive(wbcs->wbcs_debugfs_dir);
	wbcs->wbcs_debugfs_dir = NULL;
}
