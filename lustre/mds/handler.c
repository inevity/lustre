/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/handler.c
 *  
 *  Lustre Metadata Server (mds) request handler
 * 
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com>
 * 
 *  This server is single threaded at present (but can easily be multi threaded). 
 * 
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/ext2_fs.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_net.h>
#include <linux/obd_class.h>

int mds_sendpage(struct ptlrpc_request *req, struct file *file, 
                 __u64 offset, struct niobuf *dst)
{
	int rc; 
	mm_segment_t oldfs = get_fs();

	if (req->rq_peer.peer_nid == 0) {
		/* dst->addr is a user address, but in a different task! */
		set_fs(KERNEL_DS); 
		rc = generic_file_read(file, (char *)(long)dst->addr, 
				       PAGE_SIZE, &offset); 
		set_fs(oldfs);

		if (rc != PAGE_SIZE) 
			return -EIO;
	} else {
                struct ptlrpc_bulk_desc *bulk;
		char *buf;

                bulk = ptlrpc_prep_bulk(&req->rq_peer);
                if (bulk == NULL)
                        return -ENOMEM;

                bulk->b_xid = req->rq_xid;

		OBD_ALLOC(buf, PAGE_SIZE);
		if (!buf) {
                        OBD_FREE(bulk, sizeof(*bulk));
			return -ENOMEM;
                }

		set_fs(KERNEL_DS); 
		rc = generic_file_read(file, buf, PAGE_SIZE, &offset); 
		set_fs(oldfs);

		if (rc != PAGE_SIZE) {
                        OBD_FREE(buf, PAGE_SIZE);
			return -EIO;
                }

		bulk->b_buf = buf;
		bulk->b_buflen = PAGE_SIZE;

		rc = ptlrpc_send_bulk(bulk, MDS_BULK_PORTAL);
                wait_event_interruptible(bulk->b_waitq,
                                         ptlrpc_check_bulk_sent(bulk));

                if (bulk->b_flags == PTL_RPC_INTR) {
                        EXIT;
                        /* FIXME: hey hey, we leak here. */
                        return -EINTR;
                }

                OBD_FREE(bulk, sizeof(*bulk));
                OBD_FREE(buf, PAGE_SIZE);
	}

	return 0;
}

struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid,
                              struct vfsmount **mnt)
{
	/* stolen from NFS */ 
	struct super_block *sb = mds->mds_sb; 
	unsigned long ino = fid->id;
	//__u32 generation = fid->generation;
	__u32 generation = 0;
	struct inode *inode;
	struct list_head *lp;
	struct dentry *result;

	if (ino == 0)
		return ERR_PTR(-ESTALE);

	inode = iget(sb, ino);
	if (inode == NULL)
		return ERR_PTR(-ENOMEM);

	CDEBUG(D_DENTRY, "--> mds_fid2dentry: sb %p\n", inode->i_sb); 

	if (is_bad_inode(inode)
	    || (generation && inode->i_generation != generation)
		) {
		/* we didn't find the right inode.. */
		CERROR("bad inode %lu, link: %d ct: %d or version  %u/%u\n",
			inode->i_ino,
			inode->i_nlink, atomic_read(&inode->i_count),
			inode->i_generation,
			generation);
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	/* now to find a dentry.
	 * If possible, get a well-connected one
	 */
	if (mnt)
		*mnt = mds->mds_vfsmnt;
	spin_lock(&dcache_lock);
	for (lp = inode->i_dentry.next; lp != &inode->i_dentry ; lp=lp->next) {
		result = list_entry(lp,struct dentry, d_alias);
		if (! (result->d_flags & DCACHE_NFSD_DISCONNECTED)) {
			dget_locked(result);
			result->d_vfs_flags |= DCACHE_REFERENCED;
			spin_unlock(&dcache_lock);
			iput(inode);
			if (mnt)
				mntget(*mnt);
			return result;
		}
	}
	spin_unlock(&dcache_lock);
	result = d_alloc_root(inode);
	if (result == NULL) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}
	if (mnt)
		mntget(*mnt);
	result->d_flags |= DCACHE_NFSD_DISCONNECTED;
	return result;
}

static inline void mds_get_objid(struct inode *inode, __u64 *id)
{
	memcpy(id, &inode->u.ext2_i.i_data, sizeof(*id));
}

int mds_getattr(struct ptlrpc_request *req)
{
	struct dentry *de;
	struct inode *inode;
	struct mds_rep *rep;
	int rc;
	
	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		CERROR("mds: out of memory\n");
		req->rq_status = -ENOMEM;
		return 0;
	}

	req->rq_rephdr->xid = req->rq_reqhdr->xid;
	rep = req->rq_rep.mds;

	de = mds_fid2dentry(&req->rq_obd->u.mds, &req->rq_req.mds->fid1, NULL);
	if (IS_ERR(de)) { 
		EXIT;
		req->rq_rephdr->status = -ENOENT;
		return 0;
	}

	inode = de->d_inode;
	rep->ino = inode->i_ino;
	rep->atime = inode->i_atime;
	rep->ctime = inode->i_ctime;
	rep->mtime = inode->i_mtime;
	rep->uid = inode->i_uid;
	rep->gid = inode->i_gid;
	rep->size = inode->i_size;
	rep->mode = inode->i_mode;
	rep->nlink = inode->i_nlink;
	rep->valid = ~0;
	mds_get_objid(inode, &rep->objid);
	dput(de); 
	return 0;
}

int mds_open(struct ptlrpc_request *req)
{
	struct dentry *de;
	struct mds_rep *rep;
	struct file *file;
	struct vfsmount *mnt;
	__u32 flags;
	int rc;
	
	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		CERROR("mds: out of memory\n");
		req->rq_status = -ENOMEM;
		return 0;
	}

	req->rq_rephdr->xid = req->rq_reqhdr->xid;
	rep = req->rq_rep.mds;

	de = mds_fid2dentry(&req->rq_obd->u.mds, &req->rq_req.mds->fid1, &mnt);
	if (IS_ERR(de)) { 
		EXIT;
		req->rq_rephdr->status = -ENOENT;
		return 0;
	}
	flags = req->rq_req.mds->flags;
	file = dentry_open(de, mnt, flags);
	if (!file || IS_ERR(file)) { 
		req->rq_rephdr->status = -EINVAL;
		return 0;
	}		
	
	rep->objid = (__u64) (unsigned long)file; 
	//mds_get_objid(inode, &rep->objid);
	dput(de); 
	return 0;
}

int mds_close(struct ptlrpc_request *req)
{
	struct dentry *de;
	struct mds_rep *rep;
	struct file *file;
	struct vfsmount *mnt;
	int rc;
	
	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		CERROR("mds: out of memory\n");
		req->rq_status = -ENOMEM;
		return 0;
	}

	req->rq_rephdr->xid = req->rq_reqhdr->xid;
	rep = req->rq_rep.mds;

	de = mds_fid2dentry(&req->rq_obd->u.mds, &req->rq_req.mds->fid1, &mnt);
	if (IS_ERR(de)) { 
		EXIT;
		req->rq_rephdr->status = -ENOENT;
		return 0;
	}

        file = (struct file *)(unsigned long) req->rq_req.mds->objid;
        req->rq_rephdr->status = filp_close(file, 0); 
	dput(de); 
	return 0;
}


int mds_readpage(struct ptlrpc_request *req)
{
	struct vfsmount *mnt;
	struct dentry *de;
	struct file *file; 
	struct niobuf *niobuf; 
	struct mds_rep *rep;
	int rc;
	
	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		CERROR("mds: out of memory\n");
		req->rq_status = -ENOMEM;
		return 0;
	}

	req->rq_rephdr->xid = req->rq_reqhdr->xid;
	rep = req->rq_rep.mds;

	de = mds_fid2dentry(&req->rq_obd->u.mds, &req->rq_req.mds->fid1, &mnt);
	if (IS_ERR(de)) { 
		EXIT;
		req->rq_rephdr->status = PTR_ERR(de); 
		return 0;
	}

        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

	file = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE); 
	/* note: in case of an error, dentry_open puts dentry */
	if (IS_ERR(file)) { 
		EXIT;
		req->rq_rephdr->status = PTR_ERR(file);
		return 0;
	}

	niobuf = mds_req_tgt(req->rq_req.mds);

	/* to make this asynchronous make sure that the handling function 
	   doesn't send a reply when this function completes. Instead a 
	   callback function would send the reply */ 
	rc = mds_sendpage(req, file, req->rq_req.mds->size, niobuf); 

	filp_close(file, 0);
	req->rq_rephdr->status = rc;
	EXIT;
	return 0;
}

int mds_reint(struct ptlrpc_request *req)
{
	int rc;
	char *buf = mds_req_tgt(req->rq_req.mds);
	int len = req->rq_req.mds->tgtlen;
	struct mds_update_record rec;
	
	rc = mds_update_unpack(buf, len, &rec);
	if (rc) { 
		CERROR("invalid record\n");
		req->rq_status = -EINVAL;
		return 0;
	}
	/* rc will be used to interrupt a for loop over multiple records */
	rc = mds_reint_rec(&rec, req); 
	return 0; 
}

int mds_handle(struct obd_device *dev, struct ptlrpc_service *svc,
               struct ptlrpc_request *req)
{
	int rc;
	struct ptlreq_hdr *hdr;

	ENTRY;

	hdr = (struct ptlreq_hdr *)req->rq_reqbuf;

	if (NTOH__u32(hdr->type) != MDS_TYPE_REQ) {
		CERROR("lustre_mds: wrong packet type sent %d\n",
		       NTOH__u32(hdr->type));
		rc = -EINVAL;
		goto out;
	}

	rc = mds_unpack_req(req->rq_reqbuf, req->rq_reqlen, 
			    &req->rq_reqhdr, &req->rq_req);
	if (rc) { 
		CERROR("lustre_mds: Invalid request\n");
		EXIT; 
		goto out;
	}

	switch (req->rq_reqhdr->opc) { 

	case MDS_GETATTR:
		CDEBUG(D_INODE, "getattr\n");
		rc = mds_getattr(req);
		break;

	case MDS_READPAGE:
		CDEBUG(D_INODE, "readpage\n");
		rc = mds_readpage(req);
		break;

	case MDS_REINT:
		CDEBUG(D_INODE, "reint\n");
		rc = mds_reint(req);
		break;

	default:
		return ptlrpc_error(dev, svc, req);
	}

out:
	if (rc) { 
		CERROR("no header\n");
		return 0;
	}

	if( req->rq_status) { 
		ptlrpc_error(dev, svc, req);
	} else { 
		CDEBUG(D_INODE, "sending reply\n"); 
		ptlrpc_reply(dev, svc, req); 
	}

	return 0;
}


/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct obd_ioctl_data* data = buf;
	struct mds_obd *mds = &obddev->u.mds;
	struct vfsmount *mnt;
	int err; 
        ENTRY;

	mnt = do_kern_mount(data->ioc_inlbuf2, 0, data->ioc_inlbuf1, NULL); 
	err = PTR_ERR(mnt);
	if (IS_ERR(mnt)) { 
		EXIT;
		return err;
	}

	mds->mds_sb = mnt->mnt_root->d_inode->i_sb;
	if (!obddev->u.mds.mds_sb) {
		EXIT;
		return -ENODEV;
	}

	mds->mds_vfsmnt = mnt;
	obddev->u.mds.mds_fstype = strdup(data->ioc_inlbuf2);

	mds->mds_ctxt.pwdmnt = mnt;
	mds->mds_ctxt.pwd = mnt->mnt_root;
	mds->mds_ctxt.fs = KERNEL_DS;

        mds->mds_service = ptlrpc_init_svc( 64 * 1024, 
                                            MDS_REQUEST_PORTAL,
                                            MDC_REPLY_PORTAL,
                                            "self", 
                                            mds_unpack_req,
                                            mds_pack_rep,
                                            mds_handle);

        rpc_register_service(mds->mds_service, "self");

        err = ptlrpc_start_thread(obddev, mds->mds_service, "lustre_mds"); 
        if (err) { 
                CERROR("cannot start thread\n");
        }
                

        MOD_INC_USE_COUNT;
        EXIT; 
        return 0;
} 

static int mds_cleanup(struct obd_device * obddev)
{
        struct super_block *sb;
	struct mds_obd *mds = &obddev->u.mds;

        ENTRY;

        if ( !(obddev->obd_flags & OBD_SET_UP) ) {
                EXIT;
                return 0;
        }

        if ( !list_empty(&obddev->obd_gen_clients) ) {
                CERROR("still has clients!\n");
                EXIT;
                return -EBUSY;
        }

	ptlrpc_stop_thread(mds->mds_service);
	rpc_unregister_service(mds->mds_service);

	if (!list_empty(&mds->mds_service->srv_reqs)) {
		// XXX reply with errors and clean up
		CERROR("Request list not empty!\n");
	}

        rpc_unregister_service(mds->mds_service);
        OBD_FREE(mds->mds_service, sizeof(*mds->mds_service));

        sb = mds->mds_sb;
        if (!mds->mds_sb){
                EXIT;
                return 0;
        }

	unlock_kernel();
	mntput(mds->mds_vfsmnt); 
        mds->mds_sb = 0;
	kfree(mds->mds_fstype);
	lock_kernel();

        MOD_DEC_USE_COUNT;
        EXIT;
        return 0;
}

/* use obd ops to offer management infrastructure */
static struct obd_ops mds_obd_ops = {
        o_setup:       mds_setup,
        o_cleanup:     mds_cleanup,
};

static int __init mds_init(void)
{
        obd_register_type(&mds_obd_ops, LUSTRE_MDS_NAME);
	return 0;
}

static void __exit mds_exit(void)
{
	obd_unregister_type(LUSTRE_MDS_NAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS) v0.01");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
