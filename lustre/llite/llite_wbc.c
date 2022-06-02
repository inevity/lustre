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

static inline int wbc_ioctl_unreserve(struct dentry *dchild,
				      unsigned int unrsv_children)
{
	struct dentry *parent = dchild->d_parent;
	int rc;

	rc = wbc_make_dir_decomplete(parent->d_inode, parent, unrsv_children);
	if (rc == 0 && unrsv_children == 0)
		wbc_inode_unreserve_dput(dchild->d_inode, dchild);

	return rc;
}

static int wbc_ioctl_state(struct file *file, struct inode *inode,
			   struct lu_wbc_state *state)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc = 0;

	ENTRY;

	state->wbcs_fmode = inode->i_mode;
	state->wbcs_cache_mode = wbci->wbci_cache_mode;
	state->wbcs_flush_mode = wbci->wbci_flush_mode;
	state->wbcs_dirty_flags = wbci->wbci_dirty_flags;

	down_read(&wbci->wbci_rw_sem);
	state->wbcs_flags = wbci->wbci_flags;
	/* Data on PCC. */
	if (wbc_inode_dop_assimilated(wbci))
		rc = pcc_wbc_state_get(file, inode, state);
	up_read(&wbci->wbci_rw_sem);

	RETURN(rc);
}

static int wbc_ioctl_lmv_getstripe(struct file *file, struct inode *inode,
				   unsigned long arg)
{
	struct lmv_user_md __user *ulmv = (struct lmv_user_md __user *)arg;
	struct lmv_user_md lum;
	struct lmv_user_md *lump = NULL;
	struct lmv_stripe_md *lsm;
	int max_stripe_count;
	int stripe_count;
	int lum_size;
	int rc = 0;
	int i;

	ENTRY;

	if (copy_from_user(&lum, ulmv, sizeof(*ulmv)))
		RETURN(-EFAULT);

	max_stripe_count = lum.lum_stripe_count;
	/*
	 * @magic indicates which LMV stripe the ioctl will like to get.
	 * LMV_MAGIC_V1 is for normal LMV stripe, LMV_USER_MAGIC is for
	 * default LMV stripe.
	 */
	/* Get default LMV EA. */
	if (lum.lum_magic == LMV_USER_MAGIC) {
		lsm = ll_i2info(inode)->lli_default_lsm_md;
		/* TODO: If the directory does not have its own default layout,
		 * then it will request the default layout from root FID.
		 */
		if (lsm == NULL)
			RETURN(-ENODATA);

		lum.lum_stripe_count = lsm->lsm_md_stripe_count;
		lum.lum_stripe_offset = lsm->lsm_md_master_mdt_index;
		lum.lum_hash_type = lsm->lsm_md_hash_type;
		lum.lum_max_inherit = lsm->lsm_md_max_inherit;
		lum.lum_max_inherit_rr = lsm->lsm_md_max_inherit_rr;
		lum.lum_pool_name[LOV_MAXPOOLNAME] = 0;

		if (copy_to_user(ulmv, &lum, sizeof(lum)))
			RETURN(-EFAULT);

		RETURN(0);
	}

	if (lum.lum_magic != LMV_MAGIC_V1)
		RETURN(-EINVAL);

	lsm = ll_i2info(inode)->lli_lsm_md;
	if (lsm == NULL)
		RETURN(-ENODATA);

	stripe_count = lsm->lsm_md_stripe_count;
	if (max_stripe_count < stripe_count) {
		lum.lum_stripe_count = stripe_count;
		if (copy_to_user(ulmv, &lum, sizeof(lum)))
			RETURN(-EFAULT);
		RETURN(-E2BIG);
	}

	lum_size = lmv_user_md_size(stripe_count, LMV_USER_MAGIC_SPECIFIC);
	OBD_ALLOC(lump, lum_size);
	if (lump == NULL)
		RETURN(-ENOMEM);

	lump->lum_magic = LMV_MAGIC_V1;
	lump->lum_stripe_count = 0;
	lump->lum_stripe_offset = lsm->lsm_md_master_mdt_index;
	lump->lum_hash_type = lsm->lsm_md_hash_type;
	for (i = 0; i < stripe_count; i++) {
		lump->lum_objects[i].lum_mds = lsm->lsm_md_oinfo[i].lmo_mds;
		lump->lum_objects[i].lum_fid = lsm->lsm_md_oinfo[i].lmo_fid;
		lump->lum_stripe_count++;
	}

	if (copy_to_user(ulmv, lump, lum_size))
		GOTO(out_free, rc = -EFAULT);
out_free:
	OBD_FREE(lump, lum_size);
	RETURN(rc);
}

int wbc_dir_setstripe(struct inode *inode, struct lmv_user_md *lump)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct lustre_md md = { NULL };
	int rc;

	ENTRY;

	LASSERT(S_ISDIR(inode->i_mode));
	if (lump == NULL)
		RETURN(0);

	/* @lump has already swabed for wire in @ll_dir_setstripe(). */
	if (lump->lum_magic != cpu_to_le32(LMV_USER_MAGIC))
		RETURN(0);

	if (!wbc_inode_has_protected(wbci))
		RETURN(0);

	if (!LMVEA_DELETE_VALUES(le32_to_cpu(lump->lum_stripe_count),
				 le32_to_cpu(lump->lum_stripe_offset))) {
		rc = md_unpackmd(sbi->ll_md_exp, &md.default_lmv,
				 (union lmv_mds_md *)lump, sizeof(*lump));
		if (rc < 0)
			RETURN(rc);
	}

	ll_update_default_lsm_md(inode, &md);
	md_free_lustre_md(sbi->ll_md_exp, &md);
	RETURN(0);
}

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

		rc = wbc_ioctl_state(file, inode, state);
		if (copy_to_user(ustate, state, sizeof(*state)))
			GOTO(out_state, rc = -EFAULT);
out_state:
		OBD_FREE_PTR(state);
		RETURN(rc);
	}
	case LL_IOC_WBC_UNRESERVE: {
		struct lu_wbc_unreserve *unrsv;

		if (wbc_inode_none(ll_i2wbci(inode)))
			RETURN(0);

		OBD_ALLOC_PTR(unrsv);
		if (unrsv == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(unrsv,
				   (const struct lu_wbc_unreserve __user *)arg,
				   sizeof(*unrsv)))
			GOTO(out_unrsv_free, rc = -EFAULT);

		if (!inode_owner_or_capable(&init_user_ns, inode))
			GOTO(out_unrsv_free, rc = -EPERM);

		rc = wbc_ioctl_unreserve(file->f_path.dentry,
					 unrsv->wbcu_unrsv_siblings);
out_unrsv_free:
		OBD_FREE_PTR(unrsv);
		RETURN(rc);
	}
	case LL_IOC_WBC_UNCACHE: {
		if (wbc_inode_none(ll_i2wbci(inode)))
			RETURN(0);

		rc = wbc_make_subtree_deroot(file_dentry(file));
		RETURN(rc);
	}
	case LL_IOC_PCC_STATE:
	case LL_IOC_PCC_DETACH:
		RETURN(ll_i2sbi(inode)->ll_fop->unlocked_ioctl(file, cmd, arg));
	case LL_IOC_GET_MDTIDX:
		RETURN(ll_dir_operations.unlocked_ioctl(file, cmd, arg));
	case LL_IOC_LMV_GETSTRIPE: {
		if (!S_ISDIR(inode->i_mode))
			RETURN(-EINVAL);

		down_read(&wbci->wbci_rw_sem);
		if (wbc_inode_has_protected(wbci))
			rc = wbc_ioctl_lmv_getstripe(file, inode, arg);
		else
			rc = ll_dir_operations.unlocked_ioctl(file, cmd, arg);
		up_read(&wbci->wbci_rw_sem);
		RETURN(rc);
	}
	case LL_IOC_LMV_SET_DEFAULT_STRIPE: {
		if (!S_ISDIR(inode->i_mode))
			RETURN(-EINVAL);

		down_read(&wbci->wbci_rw_sem);
		if (wbc_inode_written_out(wbci))
			rc = ll_dir_operations.unlocked_ioctl(file, cmd, arg);
		else
			/*
			 * TODO: Add support for set default LMV EA for a
			 * directory that does not flush back to the server. It
			 * can save the setting of the defulat LMV EA locally
			 * into @lli_default_lsm_md and delay to update it to
			 * the server until the WBC flush time.
			 */
			rc = -EINVAL;
		up_read(&wbci->wbci_rw_sem);
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

static inline void wbc_context_note(struct wbc_context *ctx, int ioret)
{
	if (ctx && ctx->ioc_anchor_used)
		wbc_sync_io_note(&ctx->ioc_anchor, ioret);
}

static int wbc_lsm_packmd(struct inode *inode, struct md_op_data *op_data)
{
	struct ll_inode_info *lli;
	struct lmv_stripe_md *lsm;
	struct lmv_mds_md_v1 *lmm;
	ssize_t lmm_size;
	int rc;

	ENTRY;

	lli = ll_i2info(inode);
	lsm = lli->lli_lsm_md;
	lmm_size = lmv_mds_md_size(lsm->lsm_md_stripe_count, lsm->lsm_md_magic);
	if (lmm_size < 0)
		RETURN(lmm_size);

	OBD_ALLOC(lmm, lmm_size);
	if (lmm == NULL)
		RETURN(-ENOMEM);

	rc = lmv_lsm_packmd(lsm, lmm, lmm_size);
	if (rc < 0) {
		OBD_FREE(lmm, lmm_size);
		RETURN(rc);
	}

	op_data->op_data = lmm;
	op_data->op_data_size = lmm_size;
	RETURN(0);
}

static inline bool wbc_inode_should_pccrw(struct inode *inode)
{
	return S_ISREG(inode->i_mode) && wbc_cache_mode_dop(ll_i2wbci(inode));
}

static int wbc_pccrw_md_set(struct inode *inode, struct md_op_data *op_data,
			    __u64 *cr_flags)
{
	struct pcc_dataset *dataset;
	struct lov_user_md *lum;
	int rc = 0;

	ENTRY;

	/* @rwid = 0 means that select the first available PCC dataset. */
	dataset = pcc_dataset_get(ll_i2pccs(inode), LU_PCC_READWRITE, 0);
	if (dataset == NULL)
		/* TODO: fallback WBC_MODE_MEMFS cache mode. */
		RETURN(-ENOENT);

	OBD_ALLOC_PTR(lum);
	if (lum == NULL)
		GOTO(out, rc = -ENOMEM);

	lum->lmm_magic = LOV_USER_MAGIC_V1;
	lum->lmm_pattern = LOV_PATTERN_F_RELEASED | LOV_PATTERN_RAID0;
	op_data->op_data = lum;
	op_data->op_data_size = sizeof(*lum);
	op_data->op_archive_id = dataset->pccd_rwid;
	ll_i2wbci(inode)->wbci_archive_id = dataset->pccd_rwid;
	*cr_flags |= MDS_OPEN_PCC;
out:
	pcc_dataset_put(dataset);
	RETURN(rc);
}

static void wbc_fini_op_item(struct md_op_item *item, int ioret)
{
	struct md_op_data *op_data = &item->mop_data;

	ll_unlock_md_op_lsm(op_data);
	security_release_secctx(op_data->op_file_secctx,
				op_data->op_file_secctx_size);

	if (item->mop_it.it_flags & MDS_OPEN_PCC) {
		struct lov_user_md *lum = op_data->op_data;

		LASSERT(op_data->op_data_size == sizeof(*lum));
		OBD_FREE_PTR(lum);
	} else if (op_data->op_code == LUSTRE_OPC_MKDIR &&
		   op_data->op_data_size) {
		/* Free allocated @lmm for striped dir. */
		OBD_FREE(op_data->op_data, op_data->op_data_size);
	}

	wbc_context_note(item->mop_owner, ioret);
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
	struct writeback_control_ext *wbcx = item->mop_cbdata;
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
		CERROR("Failed to async create (%pd): rc = %d!\n", dentry, rc);
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
		GOTO(out_it, rc);

	LASSERT(!wbc_decomplete_lock_keep(wbci, wbcx) &&
		wbc_inode_has_protected(wbci) && wbc_inode_complete(wbci));
	spin_lock(&inode->i_lock);
	wbci->wbci_flags |= WBC_STATE_FL_ROOT | WBC_STATE_FL_SYNC;
	wbc_super_root_add(inode);
	wbci->wbci_dirty_flags &= ~WBC_DIRTY_FL_FLUSHING;
	spin_unlock(&inode->i_lock);

	wbci->wbci_lock_handle.cookie = it->it_lock_handle;
out_it:
	ll_intent_release(it);

out_dput:
	wbc_inode_unreserve_dput(inode, dentry);
	wbc_inode_writeback_complete(inode);
	wbc_fini_op_item(item, rc);

	RETURN(rc);
}

static int wbc_fill_create_common(struct inode *dir,
				  struct dentry *dchild,
				  struct md_op_item *item, bool no_layout)
{
	struct md_op_data *op_data = &item->mop_data;
	struct lookup_intent *it = &item->mop_it;
	struct inode *inode = dchild->d_inode;
	int opc;
	int rc;

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
	 * TODO: Set the file attributes such as timestamps, uid/gid, mode for
	 * the file correctly (If the file attributes was modified after
	 * created in MemFS).
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
	} else if (wbc_inode_should_pccrw(inode)) {
		rc = wbc_pccrw_md_set(inode, op_data, &it->it_flags);
		if (rc)
			RETURN(rc);
	} else if (ll_dir_striped(inode)) {
		rc = wbc_lsm_packmd(inode, op_data);
		if (rc)
			RETURN(rc);
	}

	/* Tell lmv we got the child fid under control */
	it->it_flags |= MDS_OPEN_BY_FID;

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
		if (!(no_layout || it->it_flags & MDS_OPEN_PCC))
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
		       unsigned int valid, bool no_layout)
{
	struct md_op_item *item;
	int rc;

	OBD_ALLOC_PTR(item);
	if (item == NULL)
		return ERR_PTR(-ENOMEM);

	rc = wbc_fill_create_common(dir, dchild, item, no_layout);
	if (rc) {
		wbc_fini_op_item(item, rc);
		return ERR_PTR(rc);
	}

	wbc_prep_exlock_common(item, IT_CREAT);

	return item;
}

static int wbc_setattr_exlock_cb(struct req_capsule *pill,
				struct md_op_item *item, int rc)
{
	struct writeback_control_ext *wbcx = item->mop_cbdata;
	struct lookup_intent *it = &item->mop_it;
	struct dentry *dentry = item->mop_dentry;
	struct inode *inode = dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct wbc_inode *wbci = &lli->lli_wbc_inode;
	__u64 bits;

	ENTRY;

	if (rc) {
		CERROR("Failed to setattr (%pd) async: rc = %d!\n", dentry, rc);
		GOTO(out_dput, rc);
	}

	/* Must return with EX lock. */
	if (it->it_lock_mode != LCK_EX)
		GOTO(out_dput, rc = -EPROTO);

	ll_set_lock_data(ll_i2mdexp(inode), inode, it, &bits);
	LASSERT(bits & (MDS_INODELOCK_UPDATE | MDS_INODELOCK_LOOKUP));
	LASSERT(wbci->wbci_flags & WBC_STATE_FL_PROTECTED &&
		wbci->wbci_flags & WBC_STATE_FL_SYNC);
	LASSERT(!wbc_decomplete_lock_keep(wbci, wbcx));
	spin_lock(&inode->i_lock);
	wbci->wbci_flags |= WBC_STATE_FL_ROOT;
	wbci->wbci_dirty_flags &= ~WBC_DIRTY_FL_FLUSHING;
	wbc_super_root_add(inode);
	spin_unlock(&inode->i_lock);

	wbci->wbci_lock_handle.cookie = it->it_lock_handle;
	ll_intent_release(it);

out_dput:
	wbc_inode_unreserve_dput(inode, dentry);
	wbc_inode_writeback_complete(inode);
	wbc_fini_op_item(item, rc);

	RETURN(rc);
}

static inline void wbc_generic_fillattr(struct inode *inode, struct iattr *attr)
{
	attr->ia_uid = inode->i_uid;
	attr->ia_gid = inode->i_gid;
	attr->ia_size = inode->i_size;
	attr->ia_atime = inode->i_atime;
	attr->ia_mtime = inode->i_mtime;
	attr->ia_ctime = inode->i_ctime;
	attr->ia_mode = inode->i_mode;
}

static void memfs_iattr_from_inode(struct inode *inode, unsigned int valid,
				   struct iattr *attr, enum op_xvalid *xvalid)
{
	attr->ia_valid = valid;
	wbc_generic_fillattr(inode, attr);

	if (valid & ATTR_SIZE)
		*xvalid |= OP_XVALID_OWNEROVERRIDE;
	if (valid & ATTR_CTIME)
		*xvalid |= OP_XVALID_CTIME_SET;
}

static void wbc_iattr_from_inode(struct inode *inode, unsigned int valid,
				 struct iattr *attr, enum op_xvalid *xvalid)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);

	switch (wbci->wbci_cache_mode) {
	case WBC_MODE_MEMFS:
		memfs_iattr_from_inode(inode, valid, attr, xvalid);
		break;
	default:
		break;
	}
}

/*
 * Prepare data for async setattr RPC.
 */
static struct md_op_item *
wbc_prep_setattr_exlock(struct inode *dir, struct dentry *dchild,
			unsigned int valid, bool no_layout)
{
	struct md_op_item *item;
	struct inode *inode = dchild->d_inode;
	struct md_op_data *op_data;

	ENTRY;

	OBD_ALLOC_PTR(item);
	if (item == NULL)
		return ERR_PTR(-ENOMEM);

	op_data = ll_prep_md_op_data(&item->mop_data, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data)) {
		OBD_FREE_PTR(item);
		return (struct md_op_item *)op_data;
	}

	wbc_iattr_from_inode(inode, valid, &op_data->op_attr,
			     &op_data->op_xvalid);
	wbc_prep_exlock_common(item, IT_SETATTR);

	return item;
}

static int wbc_exlock_only_cb(struct req_capsule *pill,
			       struct md_op_item *item, int rc)
{
	struct writeback_control_ext *wbcx = item->mop_cbdata;
	struct lookup_intent *it = &item->mop_it;
	struct dentry *dentry = item->mop_dentry;
	struct inode *inode = dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct wbc_inode *wbci = &lli->lli_wbc_inode;
	__u64 bits;

	ENTRY;

	if (rc) {
		CERROR("Failed to acquire EX lock: rc = %d!\n", rc);
		GOTO(out_dput, rc);
	}

	/* Must return with EX lock. */
	if (it->it_lock_mode != LCK_EX)
		GOTO(out_dput, rc = -EPROTO);

	LASSERT(!wbc_decomplete_lock_keep(wbci, wbcx));

	ll_set_lock_data(ll_i2mdexp(inode), inode, it, &bits);
	LASSERT(bits & (MDS_INODELOCK_UPDATE | MDS_INODELOCK_LOOKUP));
	LASSERT(wbci->wbci_flags & WBC_STATE_FL_PROTECTED &&
		wbci->wbci_flags & WBC_STATE_FL_SYNC);

	spin_lock(&inode->i_lock);
	wbci->wbci_flags |= WBC_STATE_FL_ROOT;
	wbc_super_root_add(inode);
	spin_unlock(&inode->i_lock);

	wbci->wbci_lock_handle.cookie = it->it_lock_handle;
	ll_intent_release(it);

out_dput:
	wbc_inode_unreserve_dput(inode, dentry);
	wbc_inode_writeback_complete(inode);
	wbc_fini_op_item(item, rc);

	RETURN(rc);
}

/*
 * Prepare data for WBC EX lock.
 * If the @inode is flushed to MDT in the state SYNC(S), during the time of
 * dropping the root WBC lock of the parent directory @dir level by level, the
 * client needs to acquire the WBC EX locks back on the children file @inode.
 */
static struct md_op_item *
wbc_prep_exlock_only(struct inode *dir, struct dentry *dchild,
		     unsigned int valid, bool no_layout)
{
	struct md_op_item *item;
	struct inode *inode = dchild->d_inode;
	struct md_op_data *op_data;

	OBD_ALLOC_PTR(item);
	if (item == NULL)
		return ERR_PTR(-ENOMEM);

	op_data = ll_prep_md_op_data(&item->mop_data, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data)) {
		OBD_FREE_PTR(item);
		return (struct md_op_item *)op_data;
	}

	wbc_prep_exlock_common(item, IT_WBC_EXLOCK);
	return item;
}

static inline void wbc_prep_lockless_common(struct md_op_item *item, int it_op)
{
	item->mop_it.it_op = it_op;
	item->mop_data.op_bias |= MDS_WBC_LOCKLESS;
}

static int wbc_create_lockless_cb(struct req_capsule *pill,
			       struct md_op_item *item, int rc)
{
	struct writeback_control_ext *wbcx = item->mop_cbdata;
	struct dentry *dchild = item->mop_dentry;
	struct dentry *parent = dchild->d_parent;
	struct inode *inode = dchild->d_inode;
	struct wbc_inode *wbci = ll_i2wbci(inode);

	ENTRY;

	LASSERT(wbcx->for_decomplete && wbc_inode_has_protected(wbci) &&
		wbc_inode_reserved(wbci) &&
		wbc_inode_complete(ll_i2wbci(parent->d_inode)));
	rc = ll_prep_inode(&inode, pill, dchild->d_sb, NULL);
	if (rc)
		GOTO(out_fini, rc);

	spin_lock(&inode->i_lock);
	wbci->wbci_flags |= WBC_STATE_FL_SYNC;
	wbci->wbci_dirty_flags &= ~WBC_DIRTY_FL_FLUSHING;
	spin_unlock(&inode->i_lock);
out_fini:
	if (wbcx->unrsv_children_decomp)
		wbc_inode_unreserve_dput(inode, dchild);

	wbc_inode_writeback_complete(inode);
	wbc_fini_op_item(item, rc);
	RETURN(rc);
}

static struct md_op_item *
wbc_prep_create_lockless(struct inode *dir, struct dentry *dchild,
			 unsigned int valid, bool no_layout)
{
	struct md_op_item *item;
	int rc;

	OBD_ALLOC_PTR(item);
	if (item == NULL)
		return ERR_PTR(-ENOMEM);

	rc = wbc_fill_create_common(dir, dchild, item, no_layout);
	if (rc) {
		OBD_FREE_PTR(item);
		return ERR_PTR(rc);
	}

	wbc_prep_lockless_common(item, IT_CREAT);
	return item;
}

static int wbc_setattr_lockless_cb(struct req_capsule *pill,
				   struct md_op_item *item, int rc)
{
	struct writeback_control_ext *wbcx = item->mop_cbdata;
	struct dentry *dentry = item->mop_dentry;
	struct inode *inode = dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct wbc_inode *wbci = &lli->lli_wbc_inode;

	ENTRY;

	if (rc) {
		CERROR("Failed to async setattr (%pd): rc = %d!\n", dentry, rc);
		GOTO(out_dput, rc);
	}

	LASSERT(wbci->wbci_flags & WBC_STATE_FL_PROTECTED &&
		wbci->wbci_flags & WBC_STATE_FL_SYNC);
	LASSERT(!wbc_decomplete_lock_keep(wbci, wbcx));
	spin_lock(&inode->i_lock);
	wbci->wbci_dirty_flags &= ~WBC_DIRTY_FL_FLUSHING;
	spin_unlock(&inode->i_lock);

out_dput:
	wbc_inode_writeback_complete(inode);
	wbc_fini_op_item(item, rc);

	RETURN(rc);
}

static struct md_op_item *
wbc_prep_setattr_lockless(struct inode *dir, struct dentry *dchild,
			  unsigned int valid, bool no_layout)
{
	struct md_op_item *item;
	struct inode *inode = dchild->d_inode;
	struct md_op_data *op_data;

	OBD_ALLOC_PTR(item);
	if (item == NULL)
		return ERR_PTR(-ENOMEM);

	op_data = ll_prep_md_op_data(&item->mop_data, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data)) {
		OBD_FREE_PTR(item);
		return (struct md_op_item *)op_data;
	}

	wbc_iattr_from_inode(inode, valid, &op_data->op_attr,
			     &op_data->op_xvalid);
	wbc_prep_lockless_common(item, IT_SETATTR);

	return item;
}

typedef struct md_op_item *(*md_prep_op_item_t)(struct inode *dir,
						struct dentry *dchild,
						unsigned int valid,
						bool no_layout);

md_prep_op_item_t wbc_op_item_preps[MD_OP_MAX] = {
	[MD_OP_CREATE_LOCKLESS]		= wbc_prep_create_lockless,
	[MD_OP_CREATE_EXLOCK]		= wbc_prep_create_exlock,
	[MD_OP_SETATTR_LOCKLESS]	= wbc_prep_setattr_lockless,
	[MD_OP_SETATTR_EXLOCK]		= wbc_prep_setattr_exlock,
	[MD_OP_EXLOCK_ONLY]		= wbc_prep_exlock_only,
};

md_op_item_cb_t wbc_op_item_cbs[MD_OP_MAX] = {
	[MD_OP_CREATE_LOCKLESS]		= wbc_create_lockless_cb,
	[MD_OP_CREATE_EXLOCK]		= wbc_create_exlock_cb,
	[MD_OP_SETATTR_LOCKLESS]	= wbc_setattr_lockless_cb,
	[MD_OP_SETATTR_EXLOCK]		= wbc_setattr_exlock_cb,
	[MD_OP_EXLOCK_ONLY]		= wbc_exlock_only_cb,
};

static struct md_op_item *
wbc_prep_op_item(enum md_item_opcode opc, struct inode *dir,
		 struct dentry *dchild, struct ldlm_lock *lock,
		 struct writeback_control_ext *wbcx,
		 unsigned int valid, bool no_layout)
{
	struct md_op_item *item;

	if (opc >= MD_OP_MAX || wbc_op_item_preps[opc] == NULL ||
	    wbc_op_item_cbs[opc] == NULL)
		return ERR_PTR(-EINVAL);

	item = wbc_op_item_preps[opc](dir, dchild, valid, no_layout);
	if (IS_ERR(item))
		return item;

	item->mop_opc = opc;
	item->mop_dentry = dchild;
	item->mop_cb = wbc_op_item_cbs[opc];
	item->mop_cbdata = wbcx;

	if (lock)
		item->mop_data.op_open_handle = lock->l_remote_handle;

	return item;
}

int wbc_do_setattr(struct inode *inode, unsigned int valid)
{
	struct ptlrpc_request *request = NULL;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	int mode = inode->i_mode;
	struct iattr *attr;
	int rc;

	ENTRY;

	OBD_ALLOC_PTR(op_data);
	if (op_data == NULL)
		RETURN(-ENOMEM);

	attr = &op_data->op_attr;
	wbc_iattr_from_inode(inode, valid, attr, &op_data->op_xvalid);
	if ((valid & (ATTR_CTIME | ATTR_SIZE | ATTR_MODE)) ==
	    (ATTR_CTIME | ATTR_SIZE | ATTR_MODE))
		op_data->op_xvalid |= OP_XVALID_OWNEROVERRIDE;

	if (((valid & (ATTR_MODE|ATTR_FORCE|ATTR_SIZE)) ==
	     (ATTR_SIZE|ATTR_MODE)) &&
	    ((mode & (S_ISGID|S_IXGRP)) == (S_ISGID|S_IXGRP)))
		attr->ia_valid |= ATTR_FORCE;

	if (valid & ATTR_SIZE)
		attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;

	/* POSIX: check before ATTR_*TIME_SET set (from inode_change_ok) */
	if (attr->ia_valid & TIMES_SET_FLAGS) {
		if ((!uid_eq(current_fsuid(), inode->i_uid)) &&
		    !capable(CAP_FOWNER))
			RETURN(-EPERM);
	}

	/* We mark all of the fields "set" so MDS/OST does not re-set them */
	if (valid & ATTR_CTIME)
		op_data->op_xvalid |= OP_XVALID_CTIME_SET;

	if (valid & (ATTR_MTIME | ATTR_CTIME))
		CDEBUG(D_INODE, "setting mtime %lld, ctime %lld, now = %lld\n",
		       (s64)attr->ia_mtime.tv_sec, (s64)attr->ia_ctime.tv_sec,
		       ktime_get_real_seconds());

	attr->ia_valid &= ~ATTR_FILE;
	ll_prep_md_op_data(op_data, inode, NULL, NULL, 0, 0,
			   LUSTRE_OPC_ANY, NULL);
	op_data->op_bias |= MDS_WBC_LOCKLESS;

	rc = md_setattr(sbi->ll_md_exp, op_data, NULL, 0, &request);
	if (rc) {
		if (rc == -ENOENT)
			clear_nlink(inode);
		else if (rc != -EPERM && rc != -EACCES && rc != -ETXTBSY)
			CERROR("md_setattr fails: rc = %d\n", rc);
	}

	ptlrpc_req_finished(request);
	if (rc)
		GOTO(out, rc);

	if ((attr->ia_valid & (ATTR_SIZE | ATTR_ATIME | ATTR_ATIME_SET |
			       ATTR_MTIME | ATTR_MTIME_SET | ATTR_CTIME) ||
	     op_data->op_xvalid & OP_XVALID_CTIME_SET) &&
	     wbc_inode_data_committed(ll_i2wbci(inode))) {
		struct ll_inode_info *lli = ll_i2info(inode);

		LASSERT(lli->lli_clob);
		rc = cl_setattr_ost(lli->lli_clob, attr, op_data->op_xvalid, 0);
	}

out:
	ll_finish_md_op_data(op_data);

	RETURN(rc);
}

static int wbc_sync_create(struct inode *inode, struct dentry *dchild)
{
	struct inode *dir = dchild->d_parent->d_inode;
	struct ptlrpc_request *request = NULL;
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct md_op_data *op_data;
	void *data = NULL;
	size_t datalen = 0;
	umode_t mode = 0;
	__u64 cr_flags = 0;
	int rdev = 0;
	int opc;
	int rc;

	ENTRY;

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		opc = LUSTRE_OPC_MKDIR;
		mode = (inode->i_mode & (S_IRWXUGO | S_ISVTX)) | S_IFDIR;
		break;
	case S_IFLNK:
		opc = LUSTRE_OPC_SYMLINK;
		mode = S_IFLNK | S_IRWXUGO;
		data = ll_i2info(inode)->lli_symlink_name;
		datalen = strlen(ll_i2info(inode)->lli_symlink_name) + 1;
		break;
	case S_IFREG:
		mode = (inode->i_mode & S_IALLUGO) | S_IFREG;
		cr_flags |= MDS_FMODE_WRITE;
		/* fallthrough */
	default:
		rdev = old_encode_dev(inode->i_rdev);
		opc = LUSTRE_OPC_CREATE;
		break;
	}

	op_data = ll_prep_md_op_data(NULL, dir, inode,
				     dchild->d_name.name, dchild->d_name.len,
				     0, opc, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	if (wbc_inode_should_pccrw(inode)) {
		rc = wbc_pccrw_md_set(inode, op_data, &cr_flags);
		if (rc)
			GOTO(out, rc);

		data = op_data->op_data;
		datalen = op_data->op_data_size;
	} else if (ll_dir_striped(inode)) {
		rc = wbc_lsm_packmd(inode, op_data);
		if (rc)
			GOTO(out, rc);

		data = op_data->op_data;
		datalen = op_data->op_data_size;
	}

	/* TODO: Set the timstamps for the inode correctly. */
	op_data->op_bias |= MDS_WBC_LOCKLESS;
	rc = md_create(sbi->ll_md_exp, op_data, data, datalen, mode,
			from_kuid(&init_user_ns, inode->i_uid),
			from_kgid(&init_user_ns, inode->i_gid),
			current_cap(), rdev, cr_flags, &request);
	if (rc)
		GOTO(out, rc);

	ll_update_times(request, dir);

	rc = ll_prep_inode(&inode, &request->rq_pill, dchild->d_sb, NULL);
	ptlrpc_req_finished(request);
out:
	if (data != NULL)
		OBD_FREE(data, datalen);
	ll_finish_md_op_data(op_data);
	RETURN(rc);
}

static int wbc_do_create(struct inode *inode)
{
	struct dentry *dentry;
	int rc;

	ENTRY;

	/* TODO: Hardlink for a non-directory file. */
	dentry = d_find_any_alias(inode);
	if (!dentry)
		RETURN(0);

	rc = wbc_sync_create(inode, dentry);
	/*
	 * TODO: for WB_SYNC_NONE mode, do async create and data flush on
	 * background.
	 */
	if (rc == 0 && S_ISREG(inode->i_mode))
		wbcfs_commit_cache_pages(inode);

	dput(dentry);
	RETURN(rc);
}

static int wbc_inode_layout_create(struct inode *inode)
{
	struct layout_intent intent = {
		.li_opc = LAYOUT_INTENT_WRITE,
		.li_extent.e_start = 0,
		.li_extent.e_end = OBD_OBJECT_EOF,
	};
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	struct lustre_md md = { NULL };
	struct md_op_data *op_data;
	int rc;

	ENTRY;

	op_data = ll_prep_md_op_data(NULL, inode, inode, NULL,
				     0, 0, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_data = &intent;
	op_data->op_data_size = sizeof(intent);

	CDEBUG(D_INODE, "%s: layout create for file "DFID"(%p)\n",
	       sbi->ll_fsname, PFID(ll_inode2fid(inode)), inode);

	rc = md_layout_create(sbi->ll_md_exp, op_data, &req);
	if (rc < 0)
		GOTO(out, rc);

	rc = md_get_lustre_md(sbi->ll_md_exp, &req->rq_pill, sbi->ll_dt_exp,
			      sbi->ll_md_exp, &md);
	if (rc != 0)
		GOTO(out, rc);

	if (!(md.body->mbo_valid & OBD_MD_FLEASIZE))
		GOTO(out, rc = -EPROTO);

	LASSERT(md.body->mbo_valid & OBD_MD_FLEASIZE);
	rc = cl_file_inode_init(inode, &md);
	md_free_lustre_md(sbi->ll_md_exp, &md);
out:
	if (req != NULL)
		ptlrpc_req_finished(req);

	if (!IS_ERR_OR_NULL(op_data))
		ll_finish_md_op_data(op_data);

	RETURN(rc);
}

/*
 * Write the cached data in MemFS into Lustre clio for an inode.
 * TODO: It need to ensure that generic IO must be blocked in this phase until
 * finished data assimilation.
 */
static int wbc_commit_data_lustre(struct inode *inode)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct address_space *mapping = inode->i_mapping;
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
	if (wbc_inode_data_committed(wbci) || wbc_inode_none(wbci))
		RETURN(0);

	if (ll_i2info(inode)->lli_clob == NULL) {
		rc = wbc_inode_layout_create(inode);
		if (rc) {
			CERROR("%s: failed to create layout for "DFID"\n",
			       ll_i2sbi(inode)->ll_fsname,
			       PFID(ll_inode2fid(inode)));
			RETURN(rc);
		}
	}

	isize = i_size_read(inode);
	LASSERT(ll_i2info(inode)->lli_clob);

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
		nr_pages = pagevec_lookup(&pvec, mapping, &index);
#else
		nr_pages = pagevec_lookup(&pvec, mapping, index, PAGEVEC_SIZE);
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

	if (queue.pl_nr == 0)
		GOTO(out_page_discard, rc);

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
	wbc_inode_data_lru_del(inode);
	spin_lock(&inode->i_lock);
	wbci->wbci_flags |= WBC_STATE_FL_DATA_COMMITTED;
	wbc_inode_unacct_pages(inode, mapping->nrpages);
	mapping->a_ops = &ll_aops;
	spin_unlock(&inode->i_lock);

	if (rc == 0)
		rc = mapping->nrpages;
	mapping_clear_unevictable(mapping);

	RETURN(rc);
}

int wbcfs_setattr_data_object(struct inode *inode, struct iattr *attr)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	bool cached;
	int rc;

	ENTRY;

	inode_unlock(inode);
	if (wbc_cache_mode_dop(wbci)) {
		rc = pcc_inode_setattr(inode, attr, &cached);
		if (cached) {
			if (rc)
				CERROR("%s: PCC inode "DFID" setattr failed: "
				       "rc = %d\n", ll_i2sbi(inode)->ll_fsname,
				       PFID(ll_inode2fid(inode)), rc);
			GOTO(out, rc);
		}
	}

	rc = cl_setattr_ost(ll_i2info(inode)->lli_clob, attr,
			    OP_XVALID_OWNEROVERRIDE, 0);
out:
	inode_lock(inode);
	inode_dio_wait(inode);
	inode_has_no_xattr(inode);

	RETURN(rc);
}

static int wbc_reopen_pcc_file(struct inode *inode)
{
	struct dentry *dentry;
	struct ll_file_data *fd;
	struct wbc_dentry *wbcd;
	int rc = 0;

	ENTRY;

	/* FIXME: hardlink. */
	dentry = d_find_any_alias(inode);
	if (!dentry)
		RETURN(0);

	wbcd = ll_d2wbcd(dentry);
	/*
	 * It does not need to take @wbcd_open_lock as it is under the
	 * protection of the lock @wbci_rw_sem.
	 */
	list_for_each_entry(fd, &wbcd->wbcd_open_files,
			    fd_wbc_file.wbcf_open_item) {
		rc = pcc_file_open(inode, fd->fd_file);
		if (rc)
			break;
	}

	dput(dentry);
	RETURN(rc);
}

static int wbc_commit_data_pcc(struct inode *inode)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct address_space *mapping = inode->i_mapping;
	int nr_pages = mapping->nrpages;
	int rc;

	ENTRY;

	/* The file data has already assimilated from MemFS into Lustre. */
	if (wbc_inode_data_committed(wbci) || wbc_inode_none(wbci))
		RETURN(0);

	rc = pcc_wbc_commit_data(inode, wbci->wbci_archive_id);
	if (rc < 0)
		RETURN(rc);

	rc = wbc_reopen_pcc_file(inode);
	/* XXX failure handling. */
	wbc_inode_data_lru_del(inode);
	spin_lock(&inode->i_lock);
	wbci->wbci_flags |= WBC_STATE_FL_DATA_COMMITTED;
	wbc_inode_unacct_pages(inode, mapping->nrpages);
	mapping->a_ops = &ll_aops;
	spin_unlock(&inode->i_lock);

	if (rc == 0)
		rc = nr_pages;
	mapping_clear_unevictable(mapping);

	/* XXX call @truncate_inode_pages() to release the whole pages. */
	RETURN(rc);
}

int wbcfs_commit_cache_pages(struct inode *inode)
{
	switch (ll_i2wbci(inode)->wbci_cache_mode) {
	case WBC_MODE_MEMFS:
		return wbc_commit_data_lustre(inode);
	case WBC_MODE_DATA_PCC:
		return wbc_commit_data_pcc(inode);
	default:
		return -EOPNOTSUPP;
	}
}

int wbc_make_inode_assimilated(struct inode *inode)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	int rc;

	if (!S_ISREG(inode->i_mode))
		return 0;

	if (wbc_inode_assimilated(wbci) || wbc_inode_none(wbci))
		return 0;

	down_write(&wbci->wbci_rw_sem);
	rc = wbcfs_commit_cache_pages(inode);
	up_write(&wbci->wbci_rw_sem);

	return rc > 0 ? 0 : rc;
}

void wbc_free_inode_pages_final(struct inode *inode,
				struct address_space *mapping)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);

	if (wbc_inode_has_protected(wbci)) {
		if (wbc_inode_dop_assimilated(wbci))
			return;

		if (inode->i_nlink) {
			(void) wbcfs_commit_cache_pages(inode);
			cl_sync_file_range(inode, 0, OBD_OBJECT_EOF,
					   CL_FSYNC_LOCAL, 1);
		} else {
			wbc_inode_unacct_pages(inode, mapping->nrpages);
		}
	}
}

int wbcfs_inode_flush_lockless(struct inode *inode,
			       struct writeback_control_ext *wbcx)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	unsigned int valid = 0;
	int rc = 0;
	long opc;

	ENTRY;

	opc = wbc_flush_opcode_get(inode, NULL, wbcx, &valid);
	switch (opc) {
	case MD_OP_NONE:
		break;
	case MD_OP_CREATE_LOCKLESS:
		rc = wbc_do_create(inode);
		spin_lock(&inode->i_lock);
		LASSERT(wbci->wbci_flags & WBC_STATE_FL_WRITEBACK &&
			wbci->wbci_dirty_flags & WBC_DIRTY_FL_FLUSHING);
		wbci->wbci_dirty_flags &= ~WBC_DIRTY_FL_FLUSHING;
		if (rc == 0)
			wbci->wbci_flags |= WBC_STATE_FL_SYNC;
		spin_unlock(&inode->i_lock);
		wbc_inode_writeback_complete(inode);

		/*
		 * For background writeout, assimilate the cache page to free
		 * up pinnned memory in MemFS and make them reclaimable
		 * immediately.
		 */
		if (wbcx->for_background)
			rc =  wbc_make_inode_assimilated(inode);
		break;
	case MD_OP_SETATTR_LOCKLESS: {
		rc = wbc_do_setattr(inode, valid);
		spin_lock(&inode->i_lock);
		LASSERT(wbci->wbci_flags & WBC_STATE_FL_WRITEBACK &&
			wbci->wbci_dirty_flags & WBC_DIRTY_FL_FLUSHING);
		wbci->wbci_dirty_flags &= ~WBC_DIRTY_FL_FLUSHING;
		spin_unlock(&inode->i_lock);
		wbc_inode_writeback_complete(inode);
		break;
	}
	default:
		LBUG();
	}

	/* TODO: error handling - redirty and requeue the inode? */

	RETURN(rc);
}

int wbcfs_context_init(struct super_block *sb, struct wbc_context *ctx,
		       bool lazy_init)
{
	struct wbc_super *super = ll_s2wbcs(sb);
	struct wbc_conf *conf = &super->wbcs_conf;

	ENTRY;

	if (lazy_init) {
		memset(ctx, 0, sizeof(*ctx));
		ctx->ioc_pol = conf->wbcc_flush_pol;
		RETURN(0);
	} else {
		ctx->ioc_pol = conf->wbcc_flush_pol;
	}

	switch (ctx->ioc_pol) {
	case WBC_FLUSH_POL_RQSET:
		ctx->ioc_rqset = ptlrpc_prep_set();
		if (ctx->ioc_rqset == NULL)
			RETURN(-ENOMEM);
		break;
	case WBC_FLUSH_POL_BATCH:
		ctx->ioc_batch = md_batch_create(ll_s2sbi(sb)->ll_md_exp, 0,
						 conf->wbcc_max_batch_count);
		if (IS_ERR(ctx->ioc_batch))
			RETURN(PTR_ERR(ctx->ioc_batch));
		/* fall through */
	case WBC_FLUSH_POL_PTLRPCD:
		/*
		 * Hold one ref so that it won't be released until every sub
		 * update request is added.
		 */
		wbc_sync_io_init(&ctx->ioc_anchor, 1);
		ctx->ioc_anchor_used = 1;
		break;
	default:
		RETURN(-ENOTSUPP);
	}

	ctx->ioc_inited = 1;
	RETURN(0);
}

int wbcfs_context_fini(struct super_block *sb, struct wbc_context *ctx)
{
	int rc = 0, rc2;

	ENTRY;

	if (!ctx->ioc_inited)
		RETURN(0);

	switch (ctx->ioc_pol) {
	case WBC_FLUSH_POL_RQSET:
		rc = ptlrpc_set_wait(NULL, ctx->ioc_rqset);
		ptlrpc_set_destroy(ctx->ioc_rqset);
		RETURN(rc);
	case WBC_FLUSH_POL_BATCH:
		rc = md_batch_stop(ll_s2sbi(sb)->ll_md_exp, ctx->ioc_batch);
		/* fall through */
	case WBC_FLUSH_POL_PTLRPCD:
		/*
		 * @anchor was inited as 1 to prevent it to be released before
		 * we add all sub requests for IO, so drop one extra reference
		 * to make sure we could wait count to be zero.
		 */
		wbc_sync_io_note(&ctx->ioc_anchor, rc);
		rc2 = wbc_sync_io_wait(&ctx->ioc_anchor, 0);
		if (rc2 < 0 && rc == 0)
			rc = rc2;
		break;
	default:
		RETURN(-EOPNOTSUPP);
	}

	RETURN(rc);
}

int wbcfs_context_prepare(struct super_block *sb, struct wbc_context *ctx)
{
	if (ctx->ioc_inited)
		return 0;

	return wbcfs_context_init(sb, ctx, false);
}

int wbcfs_context_commit(struct super_block *sb, struct wbc_context *ctx)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int rc = 0, rc2;

	if (!ctx->ioc_sync)
		return 0;

	switch (ctx->ioc_pol) {
	case WBC_FLUSH_POL_RQSET:
		rc = ptlrpc_set_wait(NULL, ctx->ioc_rqset);
		ptlrpc_set_destroy(ctx->ioc_rqset);
		if (rc)
			RETURN(rc);

		ctx->ioc_rqset = ptlrpc_prep_set();
		if (ctx->ioc_rqset == NULL)
			RETURN(-ENOMEM);
		break;
	case WBC_FLUSH_POL_BATCH:
		rc = md_batch_flush(sbi->ll_md_exp, ctx->ioc_batch, false);
		if (rc)
			RETURN(rc);
		/* fall through */
	case WBC_FLUSH_POL_PTLRPCD:
		wbc_sync_io_note(&ctx->ioc_anchor, 0);
		rc2 = wbc_sync_io_wait(&ctx->ioc_anchor, 0);
		if (rc == 0 && rc2)
			rc = rc2;
		/*
		 * One extra reference again, as if @anchor is
		 * reused we assume it as 1 before using.
		 */
		atomic_add(1, &ctx->ioc_anchor.wsi_sync_nr);
		break;
	default:
		RETURN(-EOPNOTSUPP);
	}

	RETURN(rc);
}

static int wbc_flush_dir_child(struct wbc_context *ctx, struct inode *dir,
			       struct writeback_control_ext *wbcx,
			       struct md_op_item *item)
{
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	int rc;

	switch (ctx->ioc_pol) {
	case WBC_FLUSH_POL_PTLRPCD:
		LASSERT(ctx->ioc_rqset == NULL);
		/* fall through */
	case WBC_FLUSH_POL_RQSET:
		if (wbc_decomplete_lock_keep(ll_i2wbci(dir), wbcx)) {
			LASSERT(item->mop_opc == MD_OP_CREATE_LOCKLESS);
			rc = md_reint_async(sbi->ll_md_exp, item,
					    ctx->ioc_rqset);
		} else {
			LASSERT(item->mop_opc == MD_OP_CREATE_EXLOCK ||
				item->mop_opc == MD_OP_SETATTR_EXLOCK ||
				item->mop_opc == MD_OP_EXLOCK_ONLY);
			rc = md_intent_lock_async(sbi->ll_md_exp, item,
						  ctx->ioc_rqset);
		}
		break;
	case WBC_FLUSH_POL_BATCH:
		rc = md_batch_add(sbi->ll_md_exp, ctx->ioc_batch, item);
		break;
	default:
		rc = -ENOTSUPP;
		break;
	}

	RETURN(rc);
}

int wbcfs_flush_dir_child(struct wbc_context *ctx, struct inode *dir,
			  struct dentry *dchild, struct ldlm_lock *lock,
			  struct writeback_control_ext *wbcx, bool no_layout)
{
	struct md_op_item *item;
	unsigned int valid = 0;
	long opc;
	int rc;

	ENTRY;

	opc = wbc_flush_opcode_get(dchild->d_inode, dchild, wbcx, &valid);
	if (opc == MD_OP_NONE)
		RETURN(0);

	item = wbc_prep_op_item(opc, dir, dchild, lock, wbcx, valid, no_layout);
	if (IS_ERR(item))
		RETURN(PTR_ERR(item));

	if (md_opcode_need_exlock(opc))
		item->mop_einfo.ei_mode = LCK_EX;

	if (ctx->ioc_anchor_used) {
		atomic_inc(&ctx->ioc_anchor.wsi_sync_nr);
		item->mop_owner = ctx;

	}

	OBD_FAIL_TIMEOUT(OBD_FAIL_LLITE_WBC_FLUSH_PAUSE, cfs_fail_val);
	rc = wbc_flush_dir_child(ctx, dir, wbcx, item);
	if (rc) {
		CERROR("failed to flush dchild(%pd:%p): opc = %X, rc = %d\n",
		       item->mop_dentry, item->mop_dentry, item->mop_opc, rc);
		wbc_fini_op_item(item, rc);
	}

	RETURN(rc);
}

int wbcfs_file_open_local(struct inode *inode, struct file *file)
{
	struct ll_file_data *fd;
	struct dentry *dentry = file_dentry(file);
	struct wbc_dentry *wbcd = ll_d2wbcd(dentry);
	__u64 flags = file->f_flags;
	int rc = 0;

	ENTRY;

	fd = ll_file_data_get();
	if (fd == NULL)
		RETURN(-ENOMEM);

	fd->fd_file = file;
	file->private_data = fd;
	ll_readahead_init(inode, &fd->fd_ras);

	if ((flags + 1)  & O_ACCMODE)
		flags++;
	if (file->f_flags & O_TRUNC)
		flags |= FMODE_WRITE;
	fd->fd_omode = flags & (FMODE_READ | FMODE_WRITE | FMODE_EXEC);

	/* ll_cl_context intiialize */
	INIT_LIST_HEAD(&fd->fd_wbc_file.wbcf_open_item);

	/* Pin dentry, thus it will keep in MemFS until unlink. */
	dget(dentry);
	spin_lock(&wbcd->wbcd_open_lock);
	list_add(&fd->fd_wbc_file.wbcf_open_item, &wbcd->wbcd_open_files);
	spin_unlock(&wbcd->wbcd_open_lock);

	fd->fd_wbc_file.wbcf_readdir_pol = ll_i2wbcc(inode)->wbcc_readdir_pol;

	if (wbc_cache_mode_dop(ll_i2wbci(inode))) {
		rc = pcc_file_open(inode, file);
		if (rc) {
			ll_file_data_put(fd);
			file->private_data = NULL;
		}
	}

	RETURN(rc);
}

void wbcfs_file_release_local(struct inode *inode, struct file *file)
{
	struct ll_file_data *fd;
	struct dentry *dentry = file_dentry(file);
	struct wbc_dentry *wbcd = ll_d2wbcd(dentry);

	if (wbc_cache_mode_dop(ll_i2wbci(inode)))
		pcc_file_release(inode, file);

	fd = file->private_data;
	spin_lock(&wbcd->wbcd_open_lock);
	list_del_init(&fd->fd_wbc_file.wbcf_open_item);
	spin_unlock(&wbcd->wbcd_open_lock);
	ll_file_data_put(fd);
	file->private_data = NULL;
}

int wbcfs_dcache_dir_open(struct inode *inode, struct file *file)
{
	struct ll_file_data *fd = file->private_data;
	int rc;

	rc = dcache_dir_open(inode, file);
	fd->fd_wbc_file.wbcf_private_data = file->private_data;
	file->private_data = fd;
	return rc;
}

int wbcfs_dcache_dir_close(struct inode *inode, struct file *file)
{
	struct ll_file_data *fd = file->private_data;

	dput(fd->fd_wbc_file.wbcf_private_data);
	return 0;
}

void wbc_inode_lock_callback(struct inode *inode, struct ldlm_lock *lock,
			     bool *cached)
{
	struct wbc_inode *wbci = ll_i2wbci(inode);
	struct writeback_control_ext wbcx = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0, /* metadata-only */
		.for_callback = 1,
	};

	ENTRY;

	*cached = wbc_inode_has_protected(wbci);
	if (!*cached)
		RETURN_EXIT;

	down_write(&wbci->wbci_rw_sem);
	*cached = wbc_inode_has_protected(wbci);
	if (!*cached) {
		up_write(&wbci->wbci_rw_sem);
		RETURN_EXIT;
	}

	(void) wbc_make_inode_deroot(inode, lock, &wbcx);
	up_write(&wbci->wbci_rw_sem);
	RETURN_EXIT;
}

/*
 * TODO: Set cache policy for the root WBC directory according to
 * the predefined customized caching rules.
 */
void wbc_intent_inode_init(struct inode *dir, struct inode *inode,
			   struct lookup_intent *it)
{
	struct wbc_inode *dwbci = ll_i2wbci(dir);
	struct wbc_inode *wbci = ll_i2wbci(inode);

	ENTRY;

	LASSERT(it->it_op == IT_CREAT || it->it_op == IT_LOOKUP);
	spin_lock(&inode->i_lock);
	if (it->it_lock_mode == LCK_EX) {
		struct wbc_super *super = ll_i2wbcs(dir);

		LASSERT(!wbc_inode_has_protected(dwbci));
		wbci->wbci_cache_mode = super->wbcs_conf.wbcc_cache_mode;
		wbci->wbci_flush_mode = super->wbcs_conf.wbcc_flush_mode;
		/*
		 * Set this newly created WBC directory with the state of
		 * Protected(P) | Sync(S) | Root(R) | Complete(C).
		 */
		wbci->wbci_flags = WBC_STATE_FL_ROOT | WBC_STATE_FL_PROTECTED |
				   WBC_STATE_FL_SYNC | WBC_STATE_FL_COMPLETE;
		wbc_super_root_add(inode);
		wbci->wbci_lock_handle.cookie = it->it_lock_handle;
	} else {
		LASSERT(it->it_lock_mode == 0 &&
			wbc_inode_has_protected(dwbci));
		wbci->wbci_cache_mode = dwbci->wbci_cache_mode;
		wbci->wbci_flush_mode = dwbci->wbci_flush_mode;
		wbci->wbci_flags = WBC_STATE_FL_PROTECTED | WBC_STATE_FL_SYNC;
	}

	spin_unlock(&inode->i_lock);
	wbc_inode_operations_set(inode, inode->i_mode, inode->i_rdev);
	RETURN_EXIT;
}

/*
 * Customizable rule based auto WBC.
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
	struct cfs_rule *rule = &conf->wbcc_rule;
	struct wbc_inode *wbci = ll_i2wbci(dir);
	struct cfs_matcher matcher;
	bool excl_cache;

	if (conf->wbcc_cache_mode == WBC_MODE_NONE) {
		excl_cache = false;
	} else if (rule->rl_conds_str == NULL) {
		excl_cache = true;
	} else {
		matcher.mc_uid = from_kuid(&init_user_ns, current_uid());
		matcher.mc_gid = from_kgid(&init_user_ns, current_gid());
		matcher.mc_projid = ll_i2info(dir)->lli_projid;
		matcher.mc_name = &dentry->d_name;

		excl_cache = cfs_rule_match(rule, &matcher);
	}

	if (!excl_cache) {
		*extra_lock_flags = 0;
		return sbi->ll_intent_mkdir_enabled ?
		       MKDIR_POL_INTENT : MKDIR_POL_REINT;
	}

	if (wbc_inode_has_protected(wbci)) {
		LASSERT(!wbc_inode_complete(wbci));
		*extra_lock_flags = LDLM_FL_INTENT_PARENT_LOCKED;
	} else {
		LASSERT(wbc_inode_none(wbci));
		*extra_lock_flags = LDLM_FL_INTENT_EXLOCK_UPDATE;
	}

	return MKDIR_POL_EXCL;
}

int ll_new_inode_init(struct inode *dir, struct dentry *dchild,
		      struct inode *inode)
{
	struct wbc_inode *dwbci = ll_i2wbci(dir);
	int rc = 0;

	if (wbc_inode_has_protected(dwbci)) {
		struct wbc_inode *wbci = ll_i2wbci(inode);

		LASSERT(!wbc_inode_complete(dwbci));
		spin_lock(&inode->i_lock);
		wbci->wbci_cache_mode = dwbci->wbci_cache_mode;
		wbci->wbci_flush_mode = dwbci->wbci_flush_mode;
		wbci->wbci_flags = WBC_STATE_FL_PROTECTED | WBC_STATE_FL_SYNC;
		spin_unlock(&inode->i_lock);
		wbc_inode_operations_set(inode, inode->i_mode, inode->i_rdev);

		if (ll_d_setup(dchild, false)) {
			if (d_unhashed(dchild))
				d_add(dchild, inode);
			else
				d_instantiate(dchild, inode);

			d_lustre_revalidate(dchild);
		}
	} else {
		d_instantiate(dchild, inode);
	}

	return rc;
}

void ll_intent_inode_init(struct inode *dir, struct inode *inode,
			  struct lookup_intent *it)
{
	if (wbc_inode_has_protected(ll_i2wbci(dir)))
		wbc_intent_inode_init(dir, inode, it);
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
	seq_printf(m, "flush_pol: %s\n",
		   wbc_flushpol2string(conf->wbcc_flush_pol));
	seq_printf(m, "readdir_pol: %s\n",
		   wbc_readdir_pol2string(conf->wbcc_readdir_pol));
	seq_printf(m, "remove_pol: %s\n", wbc_rmpol2string(conf->wbcc_rmpol));
	seq_printf(m, "hiwm_ratio: %d\n", conf->wbcc_hiwm_ratio);
	seq_printf(m, "inodes_max: %lu\n", conf->wbcc_max_inodes);
	seq_printf(m, "inodes_free: %lu\n", conf->wbcc_free_inodes);
	seq_printf(m, "inodes_hiwm: %u\n", conf->wbcc_hiwm_inodes_count);
	seq_printf(m, "pages_max: %lu\n", conf->wbcc_max_pages);
	seq_printf(m, "pages_free: %lu\n",
		   (unsigned long)(conf->wbcc_max_pages -
		   percpu_counter_sum(&conf->wbcc_used_pages)));
	seq_printf(m, "pages_hiwm: %u\n", conf->wbcc_hiwm_pages_count);
	seq_printf(m, "batch_no_layout: %d\n", conf->wbcc_batch_no_layout);
	seq_printf(m, "max_nrpages_per_file: %lu\n",
		   conf->wbcc_max_nrpages_per_file);
	if (conf->wbcc_rule.rl_conds_str)
		seq_printf(m, "rule: %s\n", conf->wbcc_rule.rl_conds_str);
	else
		seq_printf(m, "rule: *\n");

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
	else if (strncmp(kernbuf, "lazy_keep", 10) == 0)
		cmd.wbcc_conf.wbcc_flush_mode = WBC_FLUSH_LAZY_KEEP;
	else if (strncmp(kernbuf, "aging_drop", 10) == 0)
		cmd.wbcc_conf.wbcc_flush_mode = WBC_FLUSH_AGING_DROP;
	else if (strncmp(kernbuf, "aging_keep", 10) == 0)
		cmd.wbcc_conf.wbcc_flush_mode = WBC_FLUSH_AGING_KEEP;
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

static int wbc_rmpol_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct wbc_conf *conf = ll_s2wbcc(sb);

	seq_printf(m, "%s\n", wbc_rmpol2string(conf->wbcc_rmpol));

	return 0;
}

static ssize_t wbc_rmpol_seq_write(struct file *file,
				   const char __user *buffer,
				   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct wbc_cmd cmd;
	char kernbuf[128];
	int rc;

	if (count >= sizeof(kernbuf))
		RETURN(-EINVAL);

	if (copy_from_user(kernbuf, buffer, count))
		RETURN(-EFAULT);

	kernbuf[count] = 0;
	memset(&cmd, 0, sizeof(cmd));
	if (strncmp(kernbuf, "sync", 4) == 0)
		cmd.wbcc_conf.wbcc_rmpol = WBC_RMPOL_SYNC;
	else
		return -EINVAL;

	cmd.wbcc_flags |= WBC_CMD_OP_RMPOL;
	rc = wbc_cmd_handle(ll_s2wbcs(sb), &cmd);
	return rc ? rc : count;
}
LDEBUGFS_SEQ_FOPS(wbc_rmpol);

static int wbc_rule_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct wbc_conf *conf = ll_s2wbcc(sb);

	if (conf->wbcc_rule.rl_conds_str)
		seq_printf(m, "rule: %s\n", conf->wbcc_rule.rl_conds_str);

	return 0;
}

static ssize_t wbc_rule_seq_write(struct file *file, const char __user *buffer,
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

	rc = wbc_rule_parse_and_handle(kernbuf, count, ll_s2wbcs(sb));
out_free_kernbuff:
	OBD_FREE(kernbuf, count + 1);
	return rc ? rc : count;
}
LDEBUGFS_SEQ_FOPS(wbc_rule);

struct ldebugfs_vars ldebugfs_llite_wbc_vars[] = {
	{ .name =	"conf",
	  .fops =	&wbc_conf_fops		},
	{ .name =	"flush_mode",
	  .fops =	&wbc_flush_mode_fops	},
	{ .name =	"max_rpcs",
	  .fops =	&wbc_max_rpcs_fops,	},
	{ .name =	"rmpol",
	  .fops =	&wbc_rmpol_fops,	},
	{ .name =	"rule",
	  .fops =	&wbc_rule_fops,		},
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
