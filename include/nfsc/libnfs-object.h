/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef LIBNFS_OBJECT_H
#define LIBNFS_OBJECT_H

#include "libnfs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Filehandle-based NFSv4.2 operations for filesystem adapters. Objects are
 * immutable references to server objects, not cached pathnames or OPEN state.
 * They belong to the mounted context that created them. Free them before
 * destroying that context. Replacing a directory entry does not retarget an
 * object. Deleting the last server link may still make it stale.
 *
 * Names are single components: empty names, '.', '..' and '/' are rejected.
 * Lookup does not follow symlinks; the filesystem adapter resolves them.
 *
 * Async calls follow nfs_cb conventions: a negative return queues nothing
 * and does not call cb. On success cb is called once. Input objects can be
 * freed after the call returns; open filehandles follow the usual libnfs
 * lifetime rules. Lookup/create results are borrowed until cb returns,
 * except result->object, which becomes the caller's responsibility.
 */
struct nfs4_object;
struct nfs4_object_result {
        struct nfs4_object *object;
        struct nfs_stat_64 attributes;
};

EXTERN struct nfs4_object *nfs4_object_root(struct nfs_context *nfs);
EXTERN struct nfs4_object *nfs4_object_from_open(struct nfs_context *nfs,
                                               struct nfsfh *fh);
EXTERN void nfs4_object_free(struct nfs4_object *object);
/* Borrowed opaque identity bytes, valid until object_free(). */
EXTERN const void *nfs4_object_key(const struct nfs4_object *object,
                                  size_t *length);
EXTERN int nfs4_object_lookup_async(struct nfs_context *, const struct nfs4_object *,
                                   const char *, nfs_cb, void *);
EXTERN int nfs4_object_getattr_async(struct nfs_context *, const struct nfs4_object *,
                                    nfs_cb, void *);
/* Open this object with CLAIM_FH, without resolving its former name. */
EXTERN int nfs4_object_open_async(struct nfs_context *, const struct nfs4_object *,
                                 int flags, nfs_cb, void *);
/* Returns an ordinary nfsfh, usable with read/write/fstat/close. */
EXTERN int nfs4_object_openat_async(struct nfs_context *, const struct nfs4_object *,
                                   const char *, int flags, int mode, nfs_cb, void *);
EXTERN int nfs4_object_opendir_async(struct nfs_context *, const struct nfs4_object *,
                                    nfs_cb, void *);
EXTERN int nfs4_object_readlink_async(struct nfs_context *, const struct nfs4_object *,
                                     nfs_cb, void *);
/* Non-regular objects: mode includes S_IFDIR/S_IFLNK/etc; lookup-style result. */
EXTERN int nfs4_object_create_async(struct nfs_context *, const struct nfs4_object *,
                                   const char *, int mode, int dev,
                                   const char *link_target, nfs_cb, void *);
EXTERN int nfs4_object_remove_async(struct nfs_context *, const struct nfs4_object *,
                                   const char *, nfs_cb, void *);
EXTERN int nfs4_object_rename_async(struct nfs_context *, const struct nfs4_object *,
                                   const char *, const struct nfs4_object *,
                                   const char *, nfs_cb, void *);
EXTERN int nfs4_object_link_async(struct nfs_context *, const struct nfs4_object *,
                                 const struct nfs4_object *, const char *, nfs_cb, void *);
EXTERN int nfs4_object_access_async(struct nfs_context *, const struct nfs4_object *,
                                   int mode, nfs_cb, void *);

#define NFS4_OBJECT_SIZE       (1U << 0)
#define NFS4_OBJECT_MODE       (1U << 1)
#define NFS4_OBJECT_UID        (1U << 2)
#define NFS4_OBJECT_GID        (1U << 3)
#define NFS4_OBJECT_ATIME      (1U << 4)
#define NFS4_OBJECT_MTIME      (1U << 5)
#define NFS4_OBJECT_ATIME_NOW  (1U << 6)
#define NFS4_OBJECT_MTIME_NOW  (1U << 7)
/* One SETATTR, followed by GETATTR; cb receives struct nfs_stat_64. */
EXTERN int nfs4_object_setattr_async(struct nfs_context *, const struct nfs4_object *,
                                    struct nfsfh *open_fh,
                                    const struct nfs_stat_64 *, unsigned mask,
                                    nfs_cb, void *);

#ifdef __cplusplus
}
#endif
#endif
