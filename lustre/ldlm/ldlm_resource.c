/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Peter Braam <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_LDLM
#ifdef __KERNEL__
# include <linux/lustre_dlm.h>
#else
# include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include "ldlm_internal.h"

kmem_cache_t *ldlm_resource_slab, *ldlm_lock_slab;

DECLARE_MUTEX(ldlm_namespace_lock);
struct list_head ldlm_namespace_list = LIST_HEAD_INIT(ldlm_namespace_list);
struct proc_dir_entry *ldlm_type_proc_dir = NULL;
struct proc_dir_entry *ldlm_ns_proc_dir = NULL;
struct proc_dir_entry *ldlm_svc_proc_dir = NULL;

#ifdef __KERNEL__
static int ldlm_proc_dump_ns(struct file *file, const char *buffer,
                             unsigned long count, void *data)
{
        ldlm_dump_all_namespaces(D_DLMTRACE);
        RETURN(count);
}

int ldlm_proc_setup(void)
{
        int rc;
        struct lprocfs_vars list[] = {
                { "dump_namespaces", NULL, ldlm_proc_dump_ns, NULL },
                { NULL }};
        ENTRY;
        LASSERT(ldlm_ns_proc_dir == NULL);

        ldlm_type_proc_dir = lprocfs_register(OBD_LDLM_DEVICENAME,
                                              proc_lustre_root,
                                              NULL, NULL);
        if (IS_ERR(ldlm_type_proc_dir)) {
                CERROR("LProcFS failed in ldlm-init\n");
                rc = PTR_ERR(ldlm_type_proc_dir);
                GOTO(err, rc);
        }

        ldlm_ns_proc_dir = lprocfs_register("namespaces",
                                            ldlm_type_proc_dir,
                                            NULL, NULL);
        if (IS_ERR(ldlm_ns_proc_dir)) {
                CERROR("LProcFS failed in ldlm-init\n");
                rc = PTR_ERR(ldlm_ns_proc_dir);
                GOTO(err_type, rc);
        }

        ldlm_svc_proc_dir = lprocfs_register("services",
                                            ldlm_type_proc_dir,
                                            NULL, NULL);
        if (IS_ERR(ldlm_svc_proc_dir)) {
                CERROR("LProcFS failed in ldlm-init\n");
                rc = PTR_ERR(ldlm_svc_proc_dir);
                GOTO(err_ns, rc);
        }

        rc = lprocfs_add_vars(ldlm_type_proc_dir, list, NULL);

        RETURN(0);

err_ns:
        lprocfs_remove(ldlm_ns_proc_dir);
err_type:
        lprocfs_remove(ldlm_type_proc_dir);
err:
        ldlm_type_proc_dir = NULL;
        ldlm_ns_proc_dir = NULL;
        ldlm_svc_proc_dir = NULL;
        RETURN(rc);
}

void ldlm_proc_cleanup(void)
{
        if (ldlm_svc_proc_dir) {
                lprocfs_remove(ldlm_svc_proc_dir);
                ldlm_svc_proc_dir = NULL;
        }

        if (ldlm_ns_proc_dir) {
                lprocfs_remove(ldlm_ns_proc_dir);
                ldlm_ns_proc_dir = NULL;
        }

        if (ldlm_type_proc_dir) {
                lprocfs_remove(ldlm_type_proc_dir);
                ldlm_type_proc_dir = NULL;
        }
}

static int lprocfs_uint_rd(char *page, char **start, off_t off,
                           int count, int *eof, void *data)
{
        unsigned int *temp = (unsigned int *)data;
        return snprintf(page, count, "%u\n", *temp);
}

static int lprocfs_read_lru_size(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct ldlm_namespace *ns = data;
        return lprocfs_uint_rd(page, start, off, count, eof,
                               &ns->ns_max_unused);
}

#define MAX_STRING_SIZE 128
static int lprocfs_write_lru_size(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        struct ldlm_namespace *ns = data;
        char dummy[MAX_STRING_SIZE + 1], *end;
        unsigned long tmp;

        dummy[MAX_STRING_SIZE] = '\0';
        if (copy_from_user(dummy, buffer, MAX_STRING_SIZE))
                return -EFAULT;

        if (count == 6 && memcmp(dummy, "clear", 5) == 0) {
                CDEBUG(D_DLMTRACE,
                       "dropping all unused locks from namespace %s\n",
                       ns->ns_name);
                tmp = ns->ns_max_unused;
                ns->ns_max_unused = 0;
                ldlm_cancel_lru(ns, LDLM_SYNC);
                ns->ns_max_unused = tmp;
	        return count;
        }

        tmp = simple_strtoul(dummy, &end, 0);
        if (tmp == 0 && *end) {
                CERROR("invalid value written\n");
                return -EINVAL;
        }

        CDEBUG(D_DLMTRACE, "changing namespace %s max_unused from %u to %u\n",
               ns->ns_name, ns->ns_max_unused, (unsigned int)tmp);

        ns->ns_max_unused = (unsigned int)tmp;
        ldlm_cancel_lru(ns, LDLM_ASYNC);
        return count;
}

void ldlm_proc_namespace(struct ldlm_namespace *ns)
{
        struct lprocfs_vars lock_vars[2];
        char lock_name[MAX_STRING_SIZE + 1];

        LASSERT(ns != NULL);
        LASSERT(ns->ns_name != NULL);

        lock_name[MAX_STRING_SIZE] = '\0';

        memset(lock_vars, 0, sizeof(lock_vars));
        lock_vars[0].read_fptr = lprocfs_rd_u64;
        lock_vars[0].name = lock_name;

        snprintf(lock_name, MAX_STRING_SIZE, "%s/resource_count", ns->ns_name);
        lock_vars[0].data = &ns->ns_resources;
        lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

        snprintf(lock_name, MAX_STRING_SIZE, "%s/lock_count", ns->ns_name);
        lock_vars[0].data = &ns->ns_locks;
        lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

        if (ns->ns_client) {
                snprintf(lock_name, MAX_STRING_SIZE, "%s/lock_unused_count",
                         ns->ns_name);
                lock_vars[0].data = &ns->ns_nr_unused;
                lock_vars[0].read_fptr = lprocfs_uint_rd;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

                snprintf(lock_name, MAX_STRING_SIZE, "%s/lru_size",
                         ns->ns_name);
                lock_vars[0].data = ns;
                lock_vars[0].read_fptr = lprocfs_read_lru_size;
                lock_vars[0].write_fptr = lprocfs_write_lru_size;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);
        }
}
#endif
#undef MAX_STRING_SIZE

struct ldlm_namespace *ldlm_namespace_new(char *name, __u32 client)
{
        struct ldlm_namespace *ns = NULL;
        struct list_head *bucket;
        int rc;
        ENTRY;

        rc = ldlm_get_ref();
        if (rc) {
                CERROR("ldlm_get_ref failed: %d\n", rc);
                RETURN(NULL);
        }

        OBD_ALLOC(ns, sizeof(*ns));
        if (!ns)
                GOTO(out_ref, NULL);

        OBD_VMALLOC(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        if (!ns->ns_hash)
                GOTO(out_ns, NULL);

        OBD_ALLOC(ns->ns_name, strlen(name) + 1);
        if (!ns->ns_name)
                GOTO(out_hash, NULL);

        strcpy(ns->ns_name, name);

        INIT_LIST_HEAD(&ns->ns_root_list);
        ns->ns_refcount = 0;
        ns->ns_client = client;
        spin_lock_init(&ns->ns_hash_lock);
        atomic_set(&ns->ns_locks, 0);
        ns->ns_resources = 0;
        init_waitqueue_head(&ns->ns_waitq);

        for (bucket = ns->ns_hash + RES_HASH_SIZE - 1; bucket >= ns->ns_hash;
             bucket--)
                INIT_LIST_HEAD(bucket);

        INIT_LIST_HEAD(&ns->ns_unused_list);
        ns->ns_nr_unused = 0;
        ns->ns_max_unused = LDLM_DEFAULT_LRU_SIZE;
        spin_lock_init(&ns->ns_unused_lock);

        down(&ldlm_namespace_lock);
        list_add(&ns->ns_list_chain, &ldlm_namespace_list);
        up(&ldlm_namespace_lock);
#ifdef __KERNEL__
        ldlm_proc_namespace(ns);
#endif
        RETURN(ns);

out_hash:
        POISON(ns->ns_hash, 0x5a, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        OBD_VFREE(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
out_ns:
        OBD_FREE(ns, sizeof(*ns));
out_ref:
        ldlm_put_ref(0);
        RETURN(NULL);
}

extern struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock);

/* If flags contains FL_LOCAL_ONLY, don't try to tell the server, just cleanup.
 * This is currently only used for recovery, and we make certain assumptions
 * as a result--notably, that we shouldn't cancel locks with refs. -phil
 *
 * Called with the ns_lock held. */
static void cleanup_resource(struct ldlm_resource *res, struct list_head *q,
                             int flags)
{
        struct list_head *tmp;
        int rc = 0, client = res->lr_namespace->ns_client;
        int local_only = (flags & LDLM_FL_LOCAL_ONLY);
        ENTRY;

        
        do {
                struct ldlm_lock *lock = NULL;
 
                /* first, we look for non-cleaned-yet lock
                 * all cleaned locks are marked by CLEANED flag */
                lock_res(res);
                list_for_each(tmp, q) {
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        if (lock->l_flags & LDLM_FL_CLEANED) {
                                lock = NULL;
                                continue;
                        }
                        LDLM_LOCK_GET(lock);
                        lock->l_flags |= LDLM_FL_CLEANED;
                        break;
                }
                
                if (lock == NULL) {
                        unlock_res(res);
                        break;
                }

                /* Set CBPENDING so nothing in the cancellation path
                 * can match this lock */
                lock->l_flags |= LDLM_FL_CBPENDING;
                lock->l_flags |= LDLM_FL_FAILED;
                lock->l_flags |= flags;

                if (local_only && (lock->l_readers || lock->l_writers)) {
                        /* This is a little bit gross, but much better than the
                         * alternative: pretend that we got a blocking AST from
                         * the server, so that when the lock is decref'd, it
                         * will go away ... */
                        /* ... without sending a CANCEL message. */
                        lock->l_flags |= LDLM_FL_LOCAL_ONLY;
                        unlock_res(res);
                        LDLM_DEBUG(lock, "setting FL_LOCAL_ONLY");
                        if (lock->l_completion_ast)
                                lock->l_completion_ast(lock, 0, NULL);
                        LDLM_LOCK_PUT(lock);
                        continue;
                }

                if (client) {
                        struct lustre_handle lockh;

                        unlock_res(res);
                        ldlm_lock2handle(lock, &lockh);
                        if (!local_only) {
                                rc = ldlm_cli_cancel(&lockh);
                                if (rc)
                                        CERROR("ldlm_cli_cancel: %d\n", rc);
                        }
                        /* Force local cleanup on errors, too. */
                        if (local_only || rc != ELDLM_OK)
                                ldlm_lock_cancel(lock);
                } else {
                        ldlm_resource_unlink_lock(lock);
                        unlock_res(res);
                        LDLM_DEBUG(lock, "Freeing a lock still held by a "
                                   "client node");
                        ldlm_lock_destroy(lock);
                }
                LDLM_LOCK_PUT(lock);
        } while (1);

        EXIT;
}

int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int flags)
{
        struct list_head *tmp;
        int i;

        if (ns == NULL) {
                CDEBUG(D_INFO, "NULL ns, skipping cleanup\n");
                return ELDLM_OK;
        }

        /* FIXME: protect by ns_hash_lock -bzzz */
        for (i = 0; i < RES_HASH_SIZE; i++) {
                spin_lock(&ns->ns_hash_lock);
                tmp = ns->ns_hash[i].next;
                while (tmp != &(ns->ns_hash[i])) {
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        spin_unlock(&ns->ns_hash_lock);
                        ldlm_resource_getref(res);

                        cleanup_resource(res, &res->lr_granted, flags);
                        cleanup_resource(res, &res->lr_converting, flags);
                        cleanup_resource(res, &res->lr_waiting, flags);

                        spin_lock(&ns->ns_hash_lock);
                        tmp  = tmp->next;

                        /* XXX what a mess: don't force cleanup if we're
                         * local_only (which is only used by recovery).  In that
                         * case, we probably still have outstanding lock refs
                         * which reference these resources. -phil */
                        if (!ldlm_resource_putref_locked(res) &&
                            !(flags & LDLM_FL_LOCAL_ONLY)) {
                                CERROR("Resource refcount nonzero (%d) after "
                                       "lock cleanup; forcing cleanup.\n",
                                       atomic_read(&res->lr_refcount));
                                ldlm_resource_dump(D_ERROR, res);
                                atomic_set(&res->lr_refcount, 1);
                                ldlm_resource_putref_locked(res);
                        }
                }
                spin_unlock(&ns->ns_hash_lock);
        }

        return ELDLM_OK;
}

/* Cleanup, but also free, the namespace */
int ldlm_namespace_free(struct ldlm_namespace *ns, int force)
{
        if (!ns)
                RETURN(ELDLM_OK);

        down(&ldlm_namespace_lock);
        list_del(&ns->ns_list_chain);
        up(&ldlm_namespace_lock);

        /* At shutdown time, don't call the cancellation callback */
        ldlm_namespace_cleanup(ns, 0);

#ifdef __KERNEL__
        {
                struct proc_dir_entry *dir;
                dir = lprocfs_srch(ldlm_ns_proc_dir, ns->ns_name);
                if (dir == NULL) {
                        CERROR("dlm namespace %s has no procfs dir?\n",
                               ns->ns_name);
                } else {
                        lprocfs_remove(dir);
                }
        }
#endif

        POISON(ns->ns_hash, 0x5a, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        OBD_VFREE(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        OBD_FREE(ns->ns_name, strlen(ns->ns_name) + 1);
        OBD_FREE(ns, sizeof(*ns));

        ldlm_put_ref(force);

        return ELDLM_OK;
}

static __u32 ldlm_hash_fn(struct ldlm_resource *parent, struct ldlm_res_id name)
{
        __u32 hash = 0;
        int i;

        for (i = 0; i < RES_NAME_SIZE; i++)
                hash += name.name[i];

        hash += (__u32)((unsigned long)parent >> 4);

        return (hash & RES_HASH_MASK);
}

static struct ldlm_resource *ldlm_resource_new(void)
{
        struct ldlm_resource *res;

        OBD_SLAB_ALLOC(res, ldlm_resource_slab, SLAB_NOFS, sizeof *res);
        if (res == NULL)
                return NULL;

        memset(res, 0, sizeof(*res));

        INIT_LIST_HEAD(&res->lr_children);
        INIT_LIST_HEAD(&res->lr_childof);
        INIT_LIST_HEAD(&res->lr_granted);
        INIT_LIST_HEAD(&res->lr_converting);
        INIT_LIST_HEAD(&res->lr_waiting);
        atomic_set(&res->lr_refcount, 1);
        spin_lock_init(&res->lr_lock);

        /* one who creates the resource must unlock
         * the semaphore after lvb initialization */
        init_MUTEX_LOCKED(&res->lr_lvb_sem);

        return res;
}

/* must be called with hash lock held */
static struct ldlm_resource *
ldlm_resource_find(struct ldlm_namespace *ns, struct ldlm_res_id name, __u32 hash)
{
        struct list_head *bucket, *tmp;
        struct ldlm_resource *res;

        LASSERT_SPIN_LOCKED(&ns->ns_hash_lock);
        bucket = ns->ns_hash + hash;

        list_for_each(tmp, bucket) {
                res = list_entry(tmp, struct ldlm_resource, lr_hash);
                if (memcmp(&res->lr_name, &name, sizeof(res->lr_name)) == 0)
                        return res;
        }

        return NULL;
}

/* Args: locked namespace
 * Returns: newly-allocated, referenced, unlocked resource */
static struct ldlm_resource *
ldlm_resource_add(struct ldlm_namespace *ns, struct ldlm_resource *parent,
                  struct ldlm_res_id name, __u32 hash, __u32 type)
{
        struct list_head *bucket;
        struct ldlm_resource *res, *old_res;
        ENTRY;

        LASSERTF(type >= LDLM_MIN_TYPE && type <= LDLM_MAX_TYPE,
                 "type: %d", type);

        res = ldlm_resource_new();
        if (!res)
                RETURN(NULL);

        memcpy(&res->lr_name, &name, sizeof(res->lr_name));
        res->lr_namespace = ns;
        res->lr_type = type;
        res->lr_most_restr = LCK_NL;

        spin_lock(&ns->ns_hash_lock);
        old_res = ldlm_resource_find(ns, name, hash);
        if (old_res) {
                /* someone won the race and added the resource before */
                ldlm_resource_getref(old_res);
                spin_unlock(&ns->ns_hash_lock);
                OBD_SLAB_FREE(res, ldlm_resource_slab, sizeof *res);
                /* synchronize WRT resource creation */
                if (ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
                        down(&old_res->lr_lvb_sem);
                        up(&old_res->lr_lvb_sem);
                }
                RETURN(old_res);
        }

        /* we won! let's add the resource */
        bucket = ns->ns_hash + hash;
        list_add(&res->lr_hash, bucket);
        ns->ns_resources++;
        ns->ns_refcount++;

        if (parent == NULL) {
                list_add(&res->lr_childof, &ns->ns_root_list);
        } else {
                res->lr_parent = parent;
                list_add(&res->lr_childof, &parent->lr_children);
        }
        spin_unlock(&ns->ns_hash_lock);

        if (ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
                int rc;

                OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CREATE_RESOURCE, 2);
                rc = ns->ns_lvbo->lvbo_init(res);
                if (rc)
                        CERROR("lvbo_init failed for resource "
			       LPU64": rc %d\n", name.name[0], rc);
                /* we create resource with locked lr_lvb_sem */
                up(&res->lr_lvb_sem);
        }

        RETURN(res);
}

/* Args: unlocked namespace
 * Locks: takes and releases ns->ns_lock and res->lr_lock
 * Returns: referenced, unlocked ldlm_resource or NULL */
struct ldlm_resource *
ldlm_resource_get(struct ldlm_namespace *ns, struct ldlm_resource *parent,
                  struct ldlm_res_id name, __u32 type, int create)
{
        __u32 hash = ldlm_hash_fn(parent, name);
        struct ldlm_resource *res = NULL;
        ENTRY;

        LASSERT(ns != NULL);
        LASSERT(ns->ns_hash != NULL);
        LASSERT(name.name[0] != 0);

        spin_lock(&ns->ns_hash_lock);
        res = ldlm_resource_find(ns, name, hash);
        if (res) {
                ldlm_resource_getref(res);
                spin_unlock(&ns->ns_hash_lock);
                /* synchronize WRT resource creation */
                if (ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
                        down(&res->lr_lvb_sem);
                        up(&res->lr_lvb_sem);
                }
                RETURN(res);
        }
        spin_unlock(&ns->ns_hash_lock);

        if (create == 0)
                RETURN(NULL);

        res = ldlm_resource_add(ns, parent, name, hash, type);
        RETURN(res);
}

struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res)
{
        LASSERT(res != NULL);
        LASSERT(res != LP_POISON);
        atomic_inc(&res->lr_refcount);
        CDEBUG(D_INFO, "getref res: %p count: %d\n", res,
               atomic_read(&res->lr_refcount));
        return res;
}

void __ldlm_resource_putref_final(struct ldlm_resource *res)
{
        struct ldlm_namespace *ns = res->lr_namespace;

        LASSERT_SPIN_LOCKED(&ns->ns_hash_lock);

        if (!list_empty(&res->lr_granted)) {
                ldlm_resource_dump(D_ERROR, res);
                LBUG();
        }

        if (!list_empty(&res->lr_converting)) {
                ldlm_resource_dump(D_ERROR, res);
                LBUG();
        }

        if (!list_empty(&res->lr_waiting)) {
                ldlm_resource_dump(D_ERROR, res);
                LBUG();
        }

        if (!list_empty(&res->lr_children)) {
                ldlm_resource_dump(D_ERROR, res);
                LBUG();
        }

        ns->ns_refcount--;
        list_del_init(&res->lr_hash);
        list_del_init(&res->lr_childof);

        ns->ns_resources--;
        if (ns->ns_resources == 0)
                wake_up(&ns->ns_waitq);
}

/* Returns 1 if the resource was freed, 0 if it remains. */
int ldlm_resource_putref(struct ldlm_resource *res)
{
        struct ldlm_namespace *ns = res->lr_namespace;
        int rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "putref res: %p count: %d\n", res,
               atomic_read(&res->lr_refcount) - 1);
        LASSERT(atomic_read(&res->lr_refcount) > 0);
        LASSERT(atomic_read(&res->lr_refcount) < LI_POISON);

        LASSERT(atomic_read(&res->lr_refcount) >= 0);
        if (atomic_dec_and_lock(&res->lr_refcount, &ns->ns_hash_lock)) {
                __ldlm_resource_putref_final(res);
                spin_unlock(&ns->ns_hash_lock);
                if (res->lr_lvb_data)
                        OBD_FREE(res->lr_lvb_data, res->lr_lvb_len);
                OBD_SLAB_FREE(res, ldlm_resource_slab, sizeof *res);
                rc = 1;
        }

        RETURN(rc);
}

/* Returns 1 if the resource was freed, 0 if it remains. */
int ldlm_resource_putref_locked(struct ldlm_resource *res)
{
        int rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "putref res: %p count: %d\n", res,
               atomic_read(&res->lr_refcount) - 1);
        LASSERT(atomic_read(&res->lr_refcount) > 0);
        LASSERT(atomic_read(&res->lr_refcount) < LI_POISON);

        LASSERT(atomic_read(&res->lr_refcount) >= 0);
        if (atomic_dec_and_test(&res->lr_refcount)) {
                __ldlm_resource_putref_final(res);
                if (res->lr_lvb_data)
                        OBD_FREE(res->lr_lvb_data, res->lr_lvb_len);
                OBD_SLAB_FREE(res, ldlm_resource_slab, sizeof *res);
                rc = 1;
        }

        RETURN(rc);
}

void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock)
{
        check_res_locked(res);

        ldlm_resource_dump(D_OTHER, res);
        CDEBUG(D_OTHER, "About to add this lock:\n");
        ldlm_lock_dump(D_OTHER, lock, 0);

        if (lock->l_destroyed) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                return;
        }

        LASSERT(list_empty(&lock->l_res_link));

        list_add_tail(&lock->l_res_link, head);
}

void ldlm_resource_insert_lock_after(struct ldlm_lock *original,
                                     struct ldlm_lock *new)
{
        struct ldlm_resource *res = original->l_resource;

        check_res_locked(res);

        ldlm_resource_dump(D_OTHER, res);
        CDEBUG(D_OTHER, "About to insert this lock after %p:\n", original);
        ldlm_lock_dump(D_OTHER, new, 0);

        if (new->l_destroyed) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                return;
        }

        LASSERT(list_empty(&new->l_res_link));
        list_add(&new->l_res_link, &original->l_res_link);
}

void ldlm_resource_unlink_lock(struct ldlm_lock *lock)
{
        check_res_locked(lock->l_resource);
        list_del_init(&lock->l_res_link);
}

void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc)
{
        desc->lr_type = res->lr_type;
        memcpy(&desc->lr_name, &res->lr_name, sizeof(desc->lr_name));
}

void ldlm_dump_all_namespaces(int level)
{
        struct list_head *tmp;

        down(&ldlm_namespace_lock);

        list_for_each(tmp, &ldlm_namespace_list) {
                struct ldlm_namespace *ns;
                ns = list_entry(tmp, struct ldlm_namespace, ns_list_chain);
                ldlm_namespace_dump(level, ns);
        }

        up(&ldlm_namespace_lock);
}

void ldlm_namespace_dump(int level, struct ldlm_namespace *ns)
{
        struct list_head *tmp;

        CDEBUG(level, "--- Namespace: %s (rc: %d, client: %d)\n",
               ns->ns_name, ns->ns_refcount, ns->ns_client);

        if (time_before(jiffies, ns->ns_next_dump))
                return;

        spin_lock(&ns->ns_hash_lock);
        tmp = ns->ns_root_list.next;
        while (tmp != &ns->ns_root_list) {
                struct ldlm_resource *res;
                res = list_entry(tmp, struct ldlm_resource, lr_childof);

                ldlm_resource_getref(res);
                spin_unlock(&ns->ns_hash_lock);

                lock_res(res);
                ldlm_resource_dump(level, res);
                unlock_res(res);
                
                spin_lock(&ns->ns_hash_lock);
                tmp = tmp->next;
                ldlm_resource_putref_locked(res);
        }
        ns->ns_next_dump = jiffies + 10 * HZ;
        spin_unlock(&ns->ns_hash_lock);
}

void ldlm_resource_dump(int level, struct ldlm_resource *res)
{
        struct list_head *tmp;
        int pos;

        if (RES_NAME_SIZE != 4)
                LBUG();

        CDEBUG(level, "--- Resource: %p ("LPU64"/"LPU64"/"LPU64"/"LPU64
               ") (rc: %d)\n", res, res->lr_name.name[0], res->lr_name.name[1],
               res->lr_name.name[2], res->lr_name.name[3],
               atomic_read(&res->lr_refcount));

        if (!list_empty(&res->lr_granted)) {
                pos = 0;
                CDEBUG(level, "Granted locks:\n");
                list_for_each(tmp, &res->lr_granted) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
        if (!list_empty(&res->lr_converting)) {
                pos = 0;
                CDEBUG(level, "Converting locks:\n");
                list_for_each(tmp, &res->lr_converting) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
        if (!list_empty(&res->lr_waiting)) {
                pos = 0;
                CDEBUG(level, "Waiting locks:\n");
                list_for_each(tmp, &res->lr_waiting) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
}
