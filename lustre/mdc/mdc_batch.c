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
 * lustre/mdc/mdc_batch.c
 *
 * Batch Metadata Updating on the client (MDC)
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/module.h>
#include <lustre_update.h>
#include <lustre_acl.h>

#include "mdc_internal.h"

static int mdc_ldlm_lock_pack(struct obd_export *exp,
			      struct req_capsule *pill,
			      union ldlm_policy_data *policy,
			      struct lu_fid *fid, struct md_op_item *item)
{
	struct ldlm_request *dlmreq;
	struct ldlm_res_id res_id;
	struct ldlm_enqueue_info *einfo = &item->mop_einfo;
	int rc;

	ENTRY;

	dlmreq = req_capsule_client_get(pill, &RMF_DLM_REQ);
	if (IS_ERR(dlmreq))
		RETURN(PTR_ERR(dlmreq));

	/* With Data-on-MDT the glimpse callback is needed too.
	 * It is set here in advance but not in mdc_finish_enqueue()
	 * to avoid possible races. It is safe to have glimpse handler
	 * for non-DOM locks and costs nothing.
	 */
	if (einfo->ei_cb_gl == NULL)
		einfo->ei_cb_gl = mdc_ldlm_glimpse_ast;

	fid_build_reg_res_name(fid, &res_id);
	rc = ldlm_cli_lock_create_pack(exp, dlmreq, einfo, &res_id,
				       policy, &item->mop_lock_flags,
				       NULL, 0, LVB_T_NONE, &item->mop_lockh);

	RETURN(rc);
}

static int mdc_batch_getattr_pack(struct batch_update_head *head,
				  struct lustre_msg *reqmsg,
				  size_t *max_pack_size,
				  struct md_op_item *item)
{
	struct obd_export *exp = head->buh_exp;
	struct lookup_intent *it = &item->mop_it;
	struct md_op_data *op_data = &item->mop_data;
	u64 valid = OBD_MD_FLGETATTR | OBD_MD_FLEASIZE | OBD_MD_FLMODEASIZE |
		    OBD_MD_FLDIREA | OBD_MD_MEA | OBD_MD_FLACL |
		    OBD_MD_DEFAULT_MEA;
	union ldlm_policy_data policy = {
		.l_inodebits = { MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE }
	};
	struct ldlm_intent *lit;
	bool have_secctx = false;
	struct req_capsule pill;
	__u32 easize;
	__u32 size;
	int rc;

	ENTRY;

	req_capsule_subreq_init(&pill, &RQF_BUT_GETATTR, NULL,
				reqmsg, NULL, RCL_CLIENT);

	/* send name of security xattr to get upon intent */
	if (it->it_op & (IT_LOOKUP | IT_GETATTR) &&
	    req_capsule_has_field(&pill, &RMF_FILE_SECCTX_NAME,
				  RCL_CLIENT) &&
	    op_data->op_file_secctx_name_size > 0 &&
	    op_data->op_file_secctx_name != NULL) {
		have_secctx = true;
		req_capsule_set_size(&pill, &RMF_FILE_SECCTX_NAME, RCL_CLIENT,
				     op_data->op_file_secctx_name_size);
	}

	req_capsule_set_size(&pill, &RMF_NAME, RCL_CLIENT,
			     op_data->op_namelen + 1);

	size = req_capsule_msg_size(&pill, RCL_CLIENT);
	if (unlikely(size >= *max_pack_size)) {
		*max_pack_size = size;
		return -E2BIG;
	}

	req_capsule_client_pack(&pill);
	/* pack the intent */
	lit = req_capsule_client_get(&pill, &RMF_LDLM_INTENT);
	lit->opc = (__u64)it->it_op;

	easize = MAX_MD_SIZE_OLD; /* obd->u.cli.cl_default_mds_easize; */

	/* pack the intended request */
	mdc_getattr_pack(&pill, valid, it->it_flags, op_data, easize);

	item->mop_lock_flags |= LDLM_FL_HAS_INTENT;
	rc = mdc_ldlm_lock_pack(head->buh_exp, &pill, &policy,
				&item->mop_data.op_fid1, item);
	if (rc)
		RETURN(rc);

	req_capsule_set_size(&pill, &RMF_MDT_MD, RCL_SERVER, easize);
	req_capsule_set_size(&pill, &RMF_ACL, RCL_SERVER,
			     LUSTRE_POSIX_ACL_MAX_SIZE_OLD);
	req_capsule_set_size(&pill, &RMF_DEFAULT_MDT_MD, RCL_SERVER,
			     /*sizeof(struct lmv_user_md)*/MIN_MD_SIZE);

	if (have_secctx) {
		char *secctx_name;

		secctx_name = req_capsule_client_get(&pill,
						     &RMF_FILE_SECCTX_NAME);
		memcpy(secctx_name, op_data->op_file_secctx_name,
		       op_data->op_file_secctx_name_size);

		req_capsule_set_size(&pill, &RMF_FILE_SECCTX,
				     RCL_SERVER, easize);

		CDEBUG(D_SEC, "packed '%.*s' as security xattr name\n",
		       op_data->op_file_secctx_name_size,
		       op_data->op_file_secctx_name);
	} else {
		req_capsule_set_size(&pill, &RMF_FILE_SECCTX, RCL_SERVER, 0);
	}

	if (exp_connect_encrypt(exp) && it->it_op & (IT_LOOKUP | IT_GETATTR))
		req_capsule_set_size(&pill, &RMF_FILE_ENCCTX,
				     RCL_SERVER, easize);
	else
		req_capsule_set_size(&pill, &RMF_FILE_ENCCTX,
				     RCL_SERVER, 0);

	req_capsule_set_replen(&pill);
	reqmsg->lm_opc = BUT_GETATTR;
	*max_pack_size = size;
	RETURN(rc);
}

static int mdc_batch_getattr_interpret(struct ptlrpc_request *req,
				       struct lustre_msg *repmsg,
				       struct object_update_callback *ouc,
				       int rc)
{
	struct md_op_item *item = (struct md_op_item *)ouc->ouc_data;
	struct ldlm_enqueue_info *einfo = &item->mop_einfo;
	struct batch_update_head *head = ouc->ouc_head;
	struct obd_export *exp = head->buh_exp;
	struct req_capsule pill;

	req_capsule_subreq_init(&pill, &RQF_BUT_GETATTR, req,
				NULL, repmsg, RCL_CLIENT);

	rc = ldlm_cli_enqueue_fini(exp, &pill, einfo, 1, &item->mop_lock_flags,
				   NULL, 0, &item->mop_lockh, rc, false);
	if (rc)
		GOTO(out, rc);

	rc = mdc_finish_enqueue(exp, &pill, einfo, &item->mop_it,
				&item->mop_lockh, rc);
out:
	return item->mop_cb(&pill, item, rc);
}

static void mdc_create_capsule_pack(struct req_capsule *pill,
				    struct md_op_data *op_data)
{
	req_capsule_set_size(pill, &RMF_NAME, RCL_CLIENT,
			     op_data->op_namelen + 1);
	req_capsule_set_size(pill, &RMF_FILE_SECCTX_NAME,
			     RCL_CLIENT, op_data->op_file_secctx_name != NULL ?
			     strlen(op_data->op_file_secctx_name) + 1 : 0);
	req_capsule_set_size(pill, &RMF_FILE_SECCTX, RCL_CLIENT,
			     op_data->op_file_secctx_size);
	req_capsule_set_size(pill, &RMF_FILE_ENCCTX, RCL_CLIENT,
			     op_data->op_file_encctx_size);
	req_capsule_set_size(pill, &RMF_EADATA, RCL_CLIENT, 0);
}

static int mdc_create_exlock_pack(struct batch_update_head *head,
				  struct lustre_msg *reqmsg,
				  size_t *max_pack_size,
				  struct md_op_item *item)
{
	static union ldlm_policy_data exlock_policy = {
				.l_inodebits = { MDS_INODELOCK_UPDATE } };
	struct md_op_data *op_data = &item->mop_data;
	struct lookup_intent *it = &item->mop_it;
	struct req_capsule pill;
	size_t size;
	int rc;

	ENTRY;

	req_capsule_subreq_init(&pill, &RQF_BUT_CREATE_EXLOCK, NULL,
				reqmsg, NULL, RCL_CLIENT);
	mdc_create_capsule_pack(&pill, op_data);

	size = req_capsule_msg_size(&pill, RCL_CLIENT);
	if (unlikely(size >= *max_pack_size)) {
		*max_pack_size = size;
		return -E2BIG;
	}

	req_capsule_client_pack(&pill);
	mdc_create_pack(&pill, op_data, op_data->op_data,
			op_data->op_data_size, it->it_create_mode,
			op_data->op_fsuid, op_data->op_fsgid, op_data->op_cap,
			op_data->op_rdev, it->it_flags);

	rc = mdc_ldlm_lock_pack(head->buh_exp, &pill, &exlock_policy,
				&op_data->op_fid2, item);
	if (rc)
		RETURN(rc);

	/* FIXME: Set buffer size for LMV/LOV EA properly.*/
	if (S_ISREG(item->mop_it.it_create_mode))
		req_capsule_set_size(&pill, &RMF_MDT_MD, RCL_SERVER,
				     MAX_MD_SIZE);
	else
		req_capsule_set_size(&pill, &RMF_MDT_MD, RCL_SERVER, 0);

	req_capsule_set_replen(&pill);
	reqmsg->lm_opc = BUT_CREATE_EXLOCK;
	*max_pack_size = size;
	head->buh_flags |= BATCH_FL_UPDATE;
	RETURN(rc);
}

static int mdc_create_exlock_interpret(struct ptlrpc_request *req,
				       struct lustre_msg *repmsg,
				       struct object_update_callback *ouc,
				       int rc)
{
	struct md_op_item *item = (struct md_op_item *)ouc->ouc_data;
	struct ldlm_enqueue_info *einfo = &item->mop_einfo;
	struct batch_update_head *head = ouc->ouc_head;
	struct obd_export *exp = head->buh_exp;
	struct req_capsule pill;

	req_capsule_subreq_init(&pill, &RQF_BUT_CREATE_EXLOCK, req,
				NULL, repmsg, RCL_CLIENT);

	rc = ldlm_cli_enqueue_fini(exp, &pill, einfo, 1, &item->mop_lock_flags,
				   NULL, 0, &item->mop_lockh, rc, false);
	if (rc < 0) {
		CERROR("%s: ldlm_cli_enqueue_fini() failed: rc = %d\n",
		       exp->exp_obd->obd_name, rc);
		GOTO(out, rc);
	}

	rc = mdc_finish_enqueue(exp, &pill, einfo, &item->mop_it,
				&item->mop_lockh, rc);
out:
	return item->mop_cb(&pill, item, rc);
}

static int mdc_create_lockless_pack(struct batch_update_head *head,
				    struct lustre_msg *reqmsg,
				    size_t *max_pack_size,
				    struct md_op_item *item)
{
	struct md_op_data *op_data = &item->mop_data;
	struct lookup_intent *it = &item->mop_it;
	struct req_capsule pill;
	size_t size;

	ENTRY;

	req_capsule_subreq_init(&pill, &RQF_BUT_CREATE_LOCKLESS, NULL,
				reqmsg, NULL, RCL_CLIENT);
	mdc_create_capsule_pack(&pill, op_data);
	size = req_capsule_msg_size(&pill, RCL_CLIENT);
	if (unlikely(size >= *max_pack_size)) {
		*max_pack_size = size;
		return -E2BIG;
	}

	req_capsule_client_pack(&pill);
	mdc_create_pack(&pill, op_data, op_data->op_data,
			op_data->op_data_size, it->it_create_mode,
			op_data->op_fsuid, op_data->op_fsgid, op_data->op_cap,
			op_data->op_rdev, it->it_flags);

	/* FIXME: Set buffer size for LMV/LOV EA properly.*/
	if (S_ISREG(item->mop_it.it_create_mode))
		req_capsule_set_size(&pill, &RMF_MDT_MD, RCL_SERVER,
				     MAX_MD_SIZE);
	else
		req_capsule_set_size(&pill, &RMF_MDT_MD, RCL_SERVER, 0);

	req_capsule_set_replen(&pill);
	reqmsg->lm_opc = BUT_CREATE_LOCKLESS;
	*max_pack_size = size;
	head->buh_flags |= BATCH_FL_UPDATE;
	RETURN(0);
}

static int mdc_create_lockless_interpret(struct ptlrpc_request *req,
					 struct lustre_msg *repmsg,
					 struct object_update_callback *ouc,
					 int rc)
{
	struct md_op_item *item = (struct md_op_item *)ouc->ouc_data;
	struct req_capsule pill;

	req_capsule_subreq_init(&pill, &RQF_BUT_CREATE_LOCKLESS, req,
				NULL, repmsg, RCL_CLIENT);

	return item->mop_cb(&pill, item, rc);
}

static int mdc_setattr_exlock_pack(struct batch_update_head *head,
				   struct lustre_msg *reqmsg,
				   size_t *max_pack_size,
				   struct md_op_item *item)
{
	static union ldlm_policy_data exlock_policy = {
				.l_inodebits = { MDS_INODELOCK_UPDATE } };
	struct req_capsule pill;
	__u32 size;
	int rc;

	ENTRY;

	req_capsule_subreq_init(&pill, &RQF_BUT_SETATTR_EXLOCK, NULL,
				reqmsg, NULL, RCL_CLIENT);
	size = req_capsule_msg_size(&pill, RCL_CLIENT);
	if (unlikely(size >= *max_pack_size)) {
		*max_pack_size = size;
		return -E2BIG;
	}

	req_capsule_client_pack(&pill);
	mdc_setattr_pack(&pill, &item->mop_data, NULL, 0);
	rc = mdc_ldlm_lock_pack(head->buh_exp, &pill, &exlock_policy,
				&item->mop_data.op_fid1, item);
	if (rc)
		RETURN(rc);

	req_capsule_set_replen(&pill);
	reqmsg->lm_opc = BUT_SETATTR_EXLOCK;
	*max_pack_size = size;
	head->buh_flags |= BATCH_FL_UPDATE;
	RETURN(rc);
}

static int mdc_setattr_exlock_interpret(struct ptlrpc_request *req,
					struct lustre_msg *repmsg,
					struct object_update_callback *ouc,
					int rc)
{
	struct md_op_item *item = (struct md_op_item *)ouc->ouc_data;
	struct ldlm_enqueue_info *einfo = &item->mop_einfo;
	struct batch_update_head *head = ouc->ouc_head;
	struct obd_export *exp = head->buh_exp;
	struct req_capsule pill;

	req_capsule_subreq_init(&pill, &RQF_BUT_SETATTR_EXLOCK, req,
				NULL, repmsg, RCL_CLIENT);

	rc = ldlm_cli_enqueue_fini(exp, &pill, einfo, 1, &item->mop_lock_flags,
				   NULL, 0, &item->mop_lockh, rc, false);
	if (rc < 0) {
		CERROR("%s: ldlm_cli_enqueue_fini() failed: rc = %d\n",
		       exp->exp_obd->obd_name, rc);
		GOTO(out, rc);
	}

	rc = mdc_finish_enqueue(exp, &pill, einfo, &item->mop_it,
				&item->mop_lockh, rc);
out:
	return item->mop_cb(&pill, item, rc);
}

static int mdc_setattr_lockless_pack(struct batch_update_head *head,
				     struct lustre_msg *reqmsg,
				     size_t *max_pack_size,
				     struct md_op_item *item)
{
	struct req_capsule pill;
	__u32 size;

	ENTRY;

	req_capsule_subreq_init(&pill, &RQF_BUT_SETATTR_LOCKLESS, NULL,
				reqmsg, NULL, RCL_CLIENT);
	size = req_capsule_msg_size(&pill, RCL_CLIENT);
	if (unlikely(size >= *max_pack_size)) {
		*max_pack_size = size;
		return -E2BIG;
	}

	req_capsule_client_pack(&pill);
	mdc_setattr_pack(&pill, &item->mop_data, NULL, 0);
	req_capsule_set_replen(&pill);
	reqmsg->lm_opc = BUT_SETATTR_LOCKLESS;
	*max_pack_size = size;
	head->buh_flags |= BATCH_FL_UPDATE;
	RETURN(0);
}

static int mdc_setattr_lockless_interpret(struct ptlrpc_request *req,
					  struct lustre_msg *repmsg,
					  struct object_update_callback *ouc,
					  int rc)
{
	struct md_op_item *item = (struct md_op_item *)ouc->ouc_data;
	struct req_capsule pill;

	req_capsule_subreq_init(&pill, &RQF_BUT_SETATTR_LOCKLESS, req,
				NULL, repmsg, RCL_CLIENT);

	return item->mop_cb(&pill, item, rc);
}

static int mdc_exlock_only_pack(struct batch_update_head *head,
				struct lustre_msg *reqmsg,
			    size_t *max_pack_size,
			    struct md_op_item *item)
{
	static union ldlm_policy_data exlock_policy = {
				.l_inodebits = { MDS_INODELOCK_UPDATE } };
	struct req_capsule pill;
	__u32 size;
	int rc;

	ENTRY;

	req_capsule_subreq_init(&pill, &RQF_BUT_EXLOCK_ONLY, NULL,
				reqmsg, NULL, RCL_CLIENT);
	size = req_capsule_msg_size(&pill, RCL_CLIENT);
	if (unlikely(size >= *max_pack_size)) {
		*max_pack_size = size;
		RETURN(-E2BIG);
	}

	req_capsule_client_pack(&pill);
	rc = mdc_ldlm_lock_pack(head->buh_exp, &pill, &exlock_policy,
				&item->mop_data.op_fid1, item);
	if (rc)
		RETURN(rc);

	req_capsule_set_replen(&pill);
	reqmsg->lm_opc = BUT_EXLOCK_ONLY;
	*max_pack_size = size;
	RETURN(rc);
}

static int mdc_exlock_only_interpret(struct ptlrpc_request *req,
				     struct lustre_msg *repmsg,
				     struct object_update_callback *ouc,
				     int rc)
{
	struct md_op_item *item = (struct md_op_item *)ouc->ouc_data;
	struct ldlm_enqueue_info *einfo = &item->mop_einfo;
	struct batch_update_head *head = ouc->ouc_head;
	struct obd_export *exp = head->buh_exp;
	struct req_capsule pill;

	req_capsule_subreq_init(&pill, &RQF_BUT_EXLOCK_ONLY, req,
				NULL, repmsg, RCL_CLIENT);

	rc = ldlm_cli_enqueue_fini(exp, &pill, einfo, 1, &item->mop_lock_flags,
				   NULL, 0, &item->mop_lockh, rc, false);
	if (rc < 0) {
		CERROR("%s: ldlm_cli_enqueue_fini() failed: rc = %d\n",
		       exp->exp_obd->obd_name, rc);
		GOTO(out, rc);
	}

	rc = mdc_finish_enqueue(exp, &pill, einfo, &item->mop_it,
				&item->mop_lockh, rc);
out:
	return item->mop_cb(&pill, item, rc);
}

static md_update_pack_t mdc_update_packers[MD_OP_MAX] = {
	[MD_OP_GETATTR]			= mdc_batch_getattr_pack,
	[MD_OP_CREATE_LOCKLESS]		= mdc_create_lockless_pack,
	[MD_OP_CREATE_EXLOCK]		= mdc_create_exlock_pack,
	[MD_OP_SETATTR_LOCKLESS]	= mdc_setattr_lockless_pack,
	[MD_OP_SETATTR_EXLOCK]		= mdc_setattr_exlock_pack,
	[MD_OP_EXLOCK_ONLY]		= mdc_exlock_only_pack,
};

object_update_interpret_t mdc_update_interpreters[MD_OP_MAX] = {
	[MD_OP_GETATTR]			= mdc_batch_getattr_interpret,
	[MD_OP_CREATE_LOCKLESS]		= mdc_create_lockless_interpret,
	[MD_OP_CREATE_EXLOCK]		= mdc_create_exlock_interpret,
	[MD_OP_SETATTR_LOCKLESS]	= mdc_setattr_lockless_interpret,
	[MD_OP_SETATTR_EXLOCK]		= mdc_setattr_exlock_interpret,
	[MD_OP_EXLOCK_ONLY]		= mdc_exlock_only_interpret,
};

int mdc_batch_add(struct obd_export *exp, struct lu_batch *bh,
		  struct md_op_item *item)
{
	__u32 opc = item->mop_opc;

	ENTRY;

	if (opc >= MD_OP_MAX || mdc_update_packers[opc] == NULL ||
	    mdc_update_interpreters[opc] == NULL) {
		CERROR("Unexpected opcode %d\n", opc);
		RETURN(-EFAULT);
	}

	RETURN(cli_batch_add(exp, bh, item, mdc_update_packers[opc],
			     mdc_update_interpreters[opc]));
}
