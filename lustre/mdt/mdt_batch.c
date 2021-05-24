/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2020, DDN Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustre/mdt/mdt_batch.c
 *
 * Batch Metadata Updating on the server (MDT)
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

#include <lustre_mds.h>
#include "mdt_internal.h"

static struct ldlm_callback_suite mdt_dlm_cbs = {
	.lcs_completion	= ldlm_server_completion_ast,
	.lcs_blocking	= tgt_blocking_ast,
	.lcs_glimpse	= ldlm_server_glimpse_ast
};

static int mdt_batch_pack_repmsg(struct mdt_thread_info *info, __u32 opc)
{
	struct req_capsule *pill = info->mti_pill;
	int rc;

	if (opc == BUT_GETATTR)
		return 0;

	if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER)) {
		if (S_ISREG(info->mti_attr.ma_attr.la_mode))
			req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
					     MAX_MD_SIZE);
		else
			req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, 0);
	}

	rc = req_capsule_server_pack(pill);
	if (rc)
		CWARN("%s: cannot pack response: rc = %d\n",
		      mdt_obd_name(info->mti_mdt), rc);

	return rc;
}

static int mdt_batch_getattr(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = mdt_th_info(tsi->tsi_env);
	struct req_capsule *pill = &info->mti_sub_pill;
	int rc;

	ENTRY;

	rc = ldlm_handle_enqueue(info->mti_exp->exp_obd->obd_namespace,
				 pill, info->mti_dlm_req, &mdt_dlm_cbs);

	RETURN(rc);
}

static void mdt_ldlm_lock_cancel(struct mdt_thread_info *info)
{
	struct ldlm_reply *dlmrep;
	struct ldlm_lock *lock;

	dlmrep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
	lock = ldlm_handle2lock(&dlmrep->lock_handle);
	LASSERT(lock != NULL);
	ldlm_lock_cancel(lock);
	LDLM_LOCK_PUT(lock);
}

static int mdt_create_lockless(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = mdt_th_info(tsi->tsi_env);
	struct mdt_device *mdt = info->mti_mdt;
	struct md_attr *ma = &info->mti_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct mdt_object *parent;
	struct mdt_object *child;
	struct mdt_body *repbody;
	int rc, rc2;

	ENTRY;

	if (!fid_is_md_operative(rr->rr_fid1))
		RETURN(-EPERM);

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	LASSERT(repbody != NULL);

	parent = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(parent))
		RETURN(PTR_ERR(parent));

	if (!mdt_object_exists(parent))
		GOTO(put_parent, rc = -ENOENT);

	child = mdt_object_new(info->mti_env, mdt, rr->rr_fid2);
	if (unlikely(IS_ERR(child)))
		GOTO(put_parent, rc = PTR_ERR(child));

	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;

	/*
	 * Do not perform lookup sanity check. We know that name does
	 * not exist.
	 */
	info->mti_spec.sp_cr_lookup = 0;
	info->mti_spec.sp_feat = &dt_directory_features;

	rc = mdo_create(info->mti_env, mdt_object_child(parent), &rr->rr_name,
			mdt_object_child(child), &info->mti_spec, ma);
	if (rc < 0)
		GOTO(put_child, rc);

	if (md_should_create(info->mti_spec.sp_cr_flags))
		mdt_prep_ma_buf_from_rep(info, child, ma);

	rc = mdt_attr_get_complex(info, child, ma);
	if (rc)
		GOTO(put_child, rc);

	if (ma->ma_valid & MA_LOV) {
		LASSERT(info->mti_intent_lock && ma->ma_lmm_size != 0);
		repbody->mbo_eadatasize = ma->ma_lmm_size;
		if (S_ISREG(ma->ma_attr.la_mode))
			repbody->mbo_valid |= OBD_MD_FLEASIZE;
		else if (S_ISDIR(ma->ma_attr.la_mode))
			repbody->mbo_valid |= OBD_MD_FLDIREA;
	}

	if (ma->ma_valid & MA_LMV) {
		LASSERT(ma->ma_lmv_size != 0);
		repbody->mbo_eadatasize = ma->ma_lmv_size;
		LASSERT(S_ISDIR(ma->ma_attr.la_mode));
		repbody->mbo_valid |= OBD_MD_FLDIREA | OBD_MD_MEA;
	}

	if (ma->ma_valid & MA_LMV_DEF) {
		LASSERT(S_ISDIR(ma->ma_attr.la_mode));
		repbody->mbo_valid |= OBD_MD_FLDIREA | OBD_MD_DEFAULT_MEA;
	}

	/* Return fid & attr to client. */
	if (ma->ma_valid & MA_INODE)
		mdt_pack_attr2body(info, repbody, &ma->ma_attr,
				   mdt_object_fid(child));

put_child:
	mdt_object_put(info->mti_env, child);
put_parent:
	mdt_object_put(info->mti_env, parent);
	mdt_client_compatibility(info);

	rc2 = mdt_fix_reply(info);
	if (rc == 0)
		rc = rc2;
	RETURN(rc);
}

static int mdt_create_exlock(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = mdt_th_info(tsi->tsi_env);
	struct req_capsule *pill = &info->mti_sub_pill;
	int rc;

	ENTRY;

	rc = ldlm_handle_enqueue(info->mti_exp->exp_obd->obd_namespace,
				 pill, info->mti_dlm_req, &mdt_dlm_cbs);
	if (rc)
		RETURN(rc);

	rc = mdt_create_lockless(tsi);
	if (rc)
		mdt_ldlm_lock_cancel(info);

	RETURN(rc);
}

static int mdt_setattr_lockless(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = mdt_th_info(tsi->tsi_env);
	struct mdt_device *mdt = info->mti_mdt;
	struct md_attr *ma = &info->mti_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct mdt_object *mo;
	int rc, rc2;

	ENTRY;
	CDEBUG(D_INODE, "setattr "DFID" %x", PFID(rr->rr_fid1),
	       (unsigned int)ma->ma_attr.la_valid);

	mo = mdt_object_find(info->mti_env, mdt, rr->rr_fid1);
	if (IS_ERR(mo))
		RETURN(PTR_ERR(mo));

	if (!mdt_object_exists(mo))
		GOTO(out_put, rc = -ENOENT);

	if (mdt_object_remote(mo))
		GOTO(out_put, rc = -EREMOTE);

	ma->ma_enable_chprojid_gid = mdt->mdt_enable_chprojid_gid;
	if (ma->ma_attr.la_valid & LA_SIZE || rr->rr_flags & MRF_OPEN_TRUNC) {
		/* Check write access for the O_TRUNC case */
		if (mdt_write_read(mo) < 0)
			GOTO(out_put, rc = -ETXTBSY);

		/* LU-10286: compatibility check for FLR.
		 * Please check the comment in mdt_finish_open() for details
		 */
		if (!exp_connect_flr(info->mti_exp) ||
		    !exp_connect_overstriping(info->mti_exp)) {
			rc = mdt_big_xattr_get(info, mo, XATTR_NAME_LOV);
			if (rc < 0 && rc != -ENODATA)
				GOTO(out_put, rc);

			if (!exp_connect_flr(info->mti_exp)) {
				if (rc > 0 &&
				    mdt_lmm_is_flr(info->mti_big_lmm))
					GOTO(out_put, rc = -EOPNOTSUPP);
			}

			if (!exp_connect_overstriping(info->mti_exp)) {
				if (rc > 0 &&
				    mdt_lmm_is_overstriping(info->mti_big_lmm))
					GOTO(out_put, rc = -EOPNOTSUPP);
			}
		}

		/* For truncate, the file size sent from client
		 * is believable, but the blocks are incorrect,
		 * which makes the block size in LSOM attribute
		 * inconsisent with the real block size.
		 */
		rc = mdt_lsom_update(info, mo, true);
		if (rc)
			GOTO(out_put, rc);
	}

	if ((ma->ma_valid & MA_INODE) && ma->ma_attr.la_valid) {
		if (ma->ma_valid & MA_LOV)
			GOTO(out_put, rc = -EPROTO);

		/*
		 * FIXME: MDT supports FMD for regular files due to
		 * Data-on-MDT
		 */

		/* all attrs are packed into mti_attr in unpack_setattr */
		rc = mo_attr_set(info->mti_env, mdt_object_child(mo), ma);
		if (rc)
			GOTO(out_put, rc);
	}

	/* If file data is modified, add the dirty flag */
	if (ma->ma_attr_flags & MDS_DATA_MODIFIED)
		rc = mdt_add_dirty_flag(info, mo, ma);

out_put:
	mdt_object_put(info->mti_env, mo);
	mdt_client_compatibility(info);
	rc2 = mdt_fix_reply(info);
	if (rc == 0)
		rc = rc2;
	RETURN(rc);
}

static int mdt_setattr_exlock(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = mdt_th_info(tsi->tsi_env);
	struct req_capsule *pill = &info->mti_sub_pill;
	int rc;

	ENTRY;

	rc = ldlm_handle_enqueue(info->mti_exp->exp_obd->obd_namespace,
				 pill, info->mti_dlm_req, &mdt_dlm_cbs);
	if (rc)
		RETURN(rc);

	rc = mdt_setattr_lockless(tsi);
	if (rc)
		mdt_ldlm_lock_cancel(info);

	RETURN(rc);
}

static int mdt_exlock_only(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = mdt_th_info(tsi->tsi_env);
	struct req_capsule *pill = &info->mti_sub_pill;
	int rc;

	ENTRY;

	rc = ldlm_handle_enqueue(info->mti_exp->exp_obd->obd_namespace,
				 pill, info->mti_dlm_req, &mdt_dlm_cbs);

	RETURN(rc);
}

/* Batch UpdaTe Request with a format known in advance */
#define TGT_BUT_HDL(flags, opc, fn)			\
[opc - BUT_FIRST_OPC] = {				\
	.th_name	= #opc,				\
	.th_fail_id	= 0,				\
	.th_opc		= opc,				\
	.th_flags	= flags,			\
	.th_act		= fn,				\
	.th_fmt		= &RQF_ ## opc,			\
	.th_version	= LUSTRE_MDS_VERSION,		\
	.th_hp		= NULL,				\
}

static struct tgt_handler mdt_batch_handlers[] = {
TGT_BUT_HDL(HAS_KEY | HAS_REPLY,	BUT_GETATTR,	mdt_batch_getattr),
TGT_BUT_HDL(HAS_KEY | HAS_REPLY | IS_MUTABLE,
	    BUT_CREATE_EXLOCK,		mdt_create_exlock),
TGT_BUT_HDL(HAS_REPLY | IS_MUTABLE,
	    BUT_CREATE_LOCKLESS,	mdt_create_lockless),
TGT_BUT_HDL(HAS_KEY | IS_MUTABLE,
	    BUT_SETATTR_EXLOCK,		mdt_setattr_exlock),
TGT_BUT_HDL(IS_MUTABLE,
	    BUT_SETATTR_LOCKLESS,	mdt_setattr_lockless),
TGT_BUT_HDL(HAS_REPLY | HAS_KEY,
	    BUT_EXLOCK_ONLY,		mdt_exlock_only),
};

static struct tgt_handler *mdt_batch_handler_find(__u32 opc)
{
	struct tgt_handler *h;

	h = NULL;
	if (opc >= BUT_FIRST_OPC && opc < BUT_LAST_OPC) {
		h = &mdt_batch_handlers[opc - BUT_FIRST_OPC];
		LASSERTF(h->th_opc == opc, "opcode mismatch %d != %d\n",
			 h->th_opc, opc);
	} else {
		h = NULL; /* unsupported opc */
	}
	return h;
}

int mdt_batch(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = tsi2mdt_info(tsi);
	struct req_capsule *pill = &info->mti_sub_pill;
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	struct but_update_header *buh;
	struct but_update_buffer *bub = NULL;
	struct batch_update_reply *reply = NULL;
	struct ptlrpc_bulk_desc *desc = NULL;
	struct lustre_msg *repmsg = NULL;
	__u32 handled_update_count = 0;
	__u32 update_buf_count;
	__u32 packed_replen;
	void **update_bufs;
	bool grown = false;
	int buh_size;
	int rc;
	int i;

	ENTRY;

	buh_size = req_capsule_get_size(&req->rq_pill, &RMF_BUT_HEADER,
					RCL_CLIENT);
	if (buh_size <= 0)
		RETURN(err_serious(-EPROTO));

	buh = req_capsule_client_get(&req->rq_pill, &RMF_BUT_HEADER);
	if (buh == NULL)
		RETURN(err_serious(-EPROTO));

	if (buh->buh_magic != BUT_HEADER_MAGIC) {
		CERROR("%s: invalid update header magic %x expect %x: "
		       "rc = %d\n", tgt_name(tsi->tsi_tgt), buh->buh_magic,
		       BUT_HEADER_MAGIC, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	update_buf_count = buh->buh_count;
	if (update_buf_count == 0)
		RETURN(err_serious(-EPROTO));

	OBD_ALLOC_PTR_ARRAY(update_bufs, update_buf_count);
	if (update_bufs == NULL)
		RETURN(err_serious(-ENOMEM));

	if (buh->buh_inline_length > 0) {
		update_bufs[0] = buh->buh_inline_data;
	} else {
		struct but_update_buffer *tmp;
		int page_count = 0;

		bub = req_capsule_client_get(&req->rq_pill, &RMF_BUT_BUF);
		if (bub == NULL)
			GOTO(out, rc = err_serious(-EPROTO));

		for (i = 0; i < update_buf_count; i++)
			/* First *and* last might be partial pages, hence +1 */
			page_count += DIV_ROUND_UP(bub[i].bub_size,
						   PAGE_SIZE) + 1;

		desc = ptlrpc_prep_bulk_exp(req, page_count,
					    PTLRPC_BULK_OPS_COUNT,
					    PTLRPC_BULK_GET_SINK,
					    MDS_BULK_PORTAL,
					    &ptlrpc_bulk_kiov_nopin_ops);
		if (desc == NULL)
			GOTO(out, rc = err_serious(-ENOMEM));

		tmp = bub;
		for (i = 0; i < update_buf_count; i++, tmp++) {
			if (tmp->bub_size >= OUT_MAXREQSIZE)
				GOTO(out, rc = err_serious(-EPROTO));

			OBD_ALLOC_LARGE(update_bufs[i], tmp->bub_size);
			if (update_bufs[i] == NULL)
				GOTO(out, rc = err_serious(-ENOMEM));

			desc->bd_frag_ops->add_iov_frag(desc, update_bufs[i],
							tmp->bub_size);
		}

		req->rq_bulk_write = 1;
		rc = sptlrpc_svc_prep_bulk(req, desc);
		if (rc != 0)
			GOTO(out, rc = err_serious(rc));

		rc = target_bulk_io(req->rq_export, desc);
		if (rc < 0)
			GOTO(out, rc = err_serious(rc));
	}

	req_capsule_set_size(&req->rq_pill, &RMF_BUT_REPLY, RCL_SERVER,
			     buh->buh_reply_size);
	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc != 0) {
		CERROR("%s: Can't pack response: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		GOTO(out, rc);
	}

	/* Prepare the update reply buffer */
	reply = req_capsule_server_get(&req->rq_pill, &RMF_BUT_REPLY);
	if (reply == NULL)
		GOTO(out, rc = -EPROTO);

	reply->burp_magic = BUT_REPLY_MAGIC;
	packed_replen = sizeof(*reply);
	info->mti_batch_env = 1;
	info->mti_pill = pill;

	/* Walk through sub requests in the batch request to execute them. */
	for (i = 0; i < update_buf_count; i++) {
		struct batch_update_request *bur;
		struct lustre_msg *reqmsg = NULL;
		struct tgt_handler *h;
		int update_count;
		int j;

		bur = update_bufs[i];
		update_count = bur->burq_count;
		for (j = 0; j < update_count; j++) {
			__u32 replen;

			reqmsg = batch_update_reqmsg_next(bur, reqmsg);
			repmsg = batch_update_repmsg_next(reply, repmsg);

			if (handled_update_count > buh->buh_update_count)
				GOTO(out, rc = -EOVERFLOW);

			LASSERT(reqmsg != NULL && repmsg != NULL);
			LASSERTF(reqmsg->lm_magic == LUSTRE_MSG_MAGIC_V2,
				 "Invalid reqmsg magic %x expected %x\n",
				 reqmsg->lm_magic, LUSTRE_MSG_MAGIC_V2);

			h = mdt_batch_handler_find(reqmsg->lm_opc);
			if (unlikely(h == NULL)) {
				CERROR("%s: unsupported opc: 0x%x\n",
				       tgt_name(tsi->tsi_tgt), reqmsg->lm_opc);
				GOTO(out, rc = -ENOTSUPP);
			}

			/* TODO: Check resend case only for modifying RPC */

			LASSERT(h->th_fmt != NULL);
			req_capsule_subreq_init(pill, h->th_fmt, req,
						reqmsg, repmsg, RCL_SERVER);

			rc = mdt_batch_unpack(info, reqmsg->lm_opc);
			if (rc) {
				CERROR("Can't unpack subreq, rc = %d\n", rc);
				GOTO(out, rc);
			}

			rc = mdt_batch_pack_repmsg(info, reqmsg->lm_opc);
			if (rc)
				GOTO(out, rc);

			rc = h->th_act(tsi);
			if (rc)
				GOTO(out, rc);

			/*
			 * As @repmsg may be changed if the reply buffer is
			 * too small to grew, thus it needs to reload it here.
			 */
			if (repmsg != pill->rc_repmsg) {
				repmsg = pill->rc_repmsg;
				grown = true;
			}

			repmsg->lm_result = rc;
			mdt_thread_info_reset(info);

			replen = lustre_packed_msg_size(repmsg);
			packed_replen += replen;
			handled_update_count++;
		}
	}

	CDEBUG(D_INFO, "reply size %u packed replen %u\n",
	       buh->buh_reply_size, packed_replen);
	if (buh->buh_reply_size > packed_replen)
		req_capsule_shrink(&req->rq_pill, &RMF_BUT_REPLY,
				   packed_replen, RCL_SERVER);
out:
	if (reply != NULL) {
		if (grown) {
			reply = req_capsule_server_get(&req->rq_pill,
						       &RMF_BUT_REPLY);
			if (reply == NULL)
				GOTO(out_free, rc = -EPROTO);
		}
		reply->burp_count = handled_update_count;
	}

out_free:
	if (update_bufs != NULL) {
		if (bub != NULL) {
			for (i = 0; i < update_buf_count; i++, bub++) {
				if (update_bufs[i] != NULL)
					OBD_FREE_LARGE(update_bufs[i],
						       bub->bub_size);
			}
		}

		OBD_FREE_PTR_ARRAY(update_bufs, update_buf_count);
	}

	if (desc != NULL)
		ptlrpc_free_bulk(desc);

	mdt_thread_info_fini(info);
	RETURN(rc);
}

