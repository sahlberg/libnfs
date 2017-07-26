/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2017 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
/*
 * High level api to nfsv4 filesystems
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif

#ifdef WIN32
#include "win32_compat.h"
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#define PRIu64 "llu"
#endif

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif

#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

#if defined(__ANDROID__) && !defined(HAVE_SYS_STATVFS_H)
#define statvfs statfs
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#endif

#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "libnfs-zdr.h"
#include "slist.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"


struct nfs4_cb_data;
typedef void (*op_filler)(struct nfs4_cb_data *data, nfs_argop4 *op);

struct lookup_link_data {
        unsigned int idx;
};

/* Function and arguments to append the requested operations we want
 * for the resolved path.
 */
struct lookup_filler {
        op_filler func;
        int num_op;
        int flags;
        void *data;  /* Freed by nfs4_cb_data destructor */

        struct {
                int   len;
                void *val;
        } blob0;   /* val is freed by nfs4_cb_data destructor */
        struct {
                int   len;
                void *val;
        } blob1;   /* val is freed by nfs4_cb_data destructor */
};

struct rw_data {
        uint64_t offset;
        int update_pos;
};

struct nfs4_cb_data {
        struct nfs_context *nfs;
/* Do not follow symlinks for the final component on a lookup.
 * I.e. stat vs lstat
 */
#define LOOKUP_FLAG_NO_FOLLOW 0x0001
        int flags;

        /* Application callback and data */
        nfs_cb cb;
        void *private_data;

        /* internal callback */
        rpc_cb continue_cb;

        char *path; /* path to lookup */
        struct lookup_filler filler;

        /* Data we need when resolving a symlink in the path */
        struct lookup_link_data link;

        /* Data we need for updating offset in read/write */
        struct rw_data rw_data;
};

static void
free_nfs4_cb_data(struct nfs4_cb_data *data)
{
        free(data->path);
        free(data->filler.data);
        free(data->filler.blob0.val);
        free(data->filler.blob1.val);
        free(data);
}

static int
check_nfs4_error(struct nfs_context *nfs, int status,
                 struct nfs4_cb_data *data, void *command_data,
                 char *op_name)
{
        COMPOUND4res *res = command_data;

        if (status == RPC_STATUS_ERROR) {
                data->cb(-EFAULT, nfs, res, data->private_data);
                return 1;
        }
        if (status == RPC_STATUS_CANCEL) {
                data->cb(-EINTR, nfs, "Command was cancelled",
                         data->private_data);
                return 1;
        }
        if (status == RPC_STATUS_TIMEOUT) {
                data->cb(-EINTR, nfs, "Command timed out",
                         data->private_data);
                return 1;
        }
        if (res && res->status != NFS4_OK) {
                nfs_set_error(nfs, "NFS4: %s (path %s) failed with "
                              "%s(%d)", op_name,
                              data->path,
                              nfsstat4_to_str(res->status),
                              nfsstat4_to_errno(res->status));
                data->cb(nfsstat3_to_errno(res->status), nfs,
                         nfs_get_error(nfs), data->private_data);
                return 1;
        }

        return 0;
}

static int
nfs4_find_op(struct nfs_context *nfs, struct nfs4_cb_data *data,
             COMPOUND4res *res, int op, const char *op_name)
{
        int i;

        for (i = 0; i < (int)res->resarray.resarray_len; i++) {
                if (res->resarray.resarray_val[i].resop == op) {
                        break;
                }
        }
        if (i == res->resarray.resarray_len) {
                nfs_set_error(nfs, "No %s result.", op_name);
                data->cb(-EINVAL, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return -1;
        }

        return i;
}

static uint64_t
nfs_pntoh64(const uint32_t *buf)
{
        uint64_t val;

        val   = ntohl(*(uint32_t *)(void *)buf++);
        val <<= 32;
        val  |= ntohl(*(uint32_t *)(void *)buf);

        return val;
}

#define CHECK_GETATTR_BUF_SPACE(len, size)                              \
    if (len < size) {                                                   \
        nfs_set_error(nfs, "Not enough data in fattr4");                \
        return -1;                                                      \
    }

static int
nfs_parse_attributes(struct nfs_context *nfs, struct nfs4_cb_data *data,
                     struct nfs_stat_64 *st, const char *buf, int len)
{
        int type, slen, pad;

        /* Type */
        CHECK_GETATTR_BUF_SPACE(len, 4);
        type = ntohl(*(uint32_t *)(void *)buf);
        buf += 4;
        len -= 4;
        /* Size */
        CHECK_GETATTR_BUF_SPACE(len, 8);
        st->nfs_size = nfs_pntoh64((uint32_t *)(void *)buf);
        buf += 8;
        len -= 8;
        /* Inode */
        CHECK_GETATTR_BUF_SPACE(len, 8);
        st->nfs_ino = nfs_pntoh64((uint32_t *)(void *)buf);
        buf += 8;
        len -= 8;
        /* Mode */
        CHECK_GETATTR_BUF_SPACE(len, 4);
        st->nfs_mode = ntohl(*(uint32_t *)(void *)buf);
        buf += 4;
        len -= 4;
        switch (type) {
        case NF4REG:
                st->nfs_mode |= S_IFREG;
                break;
        case NF4DIR:
                st->nfs_mode |= S_IFDIR;
                break;
        case NF4BLK:
                st->nfs_mode |= S_IFBLK;
                break;
        case NF4CHR:
                st->nfs_mode |= S_IFCHR;
                break;
        case NF4LNK:
                st->nfs_mode |= S_IFLNK;
                break;
        case NF4SOCK:
                st->nfs_mode |= S_IFSOCK;
                break;
        case NF4FIFO:
                st->nfs_mode |= S_IFIFO;
                break;
        default:
                break;
        }
        /* Num Links */
        CHECK_GETATTR_BUF_SPACE(len, 4);
        st->nfs_nlink = ntohl(*(uint32_t *)(void *)buf);
        buf += 4;
        len -= 4;
        /* Owner */
        CHECK_GETATTR_BUF_SPACE(len, 4);
        slen = ntohl(*(uint32_t *)(void *)buf);
        buf += 4;
        len -= 4;
        pad = (4 - (slen & 0x03)) & 0x03;
        CHECK_GETATTR_BUF_SPACE(len, slen);
        while (slen) {
                if (isdigit(*buf)) {
                        st->nfs_uid *= 10;
                        st->nfs_uid += *buf - '0';
                } else {
                        nfs_set_error(nfs, "Bad digit in fattr3 uid");
                        return -1;
                }
                buf++;
                slen--;
        }
        CHECK_GETATTR_BUF_SPACE(len, pad);
        buf += pad;
        len -= pad;
        /* Group */
        CHECK_GETATTR_BUF_SPACE(len, 4);
        slen = ntohl(*(uint32_t *)(void *)buf);
        buf += 4;
        len -= 4;
        pad = (4 - (slen & 0x03)) & 0x03;
        CHECK_GETATTR_BUF_SPACE(len, slen);
        while (slen) {
                if (isdigit(*buf)) {
                        st->nfs_gid *= 10;
                        st->nfs_gid += *buf - '0';
                } else {
                        nfs_set_error(nfs, "Bad digit in fattr3 gid");
                        return -1;
                }
                buf++;
                slen--;
        }
        CHECK_GETATTR_BUF_SPACE(len, pad);
        buf += pad;
        len -= pad;
        /* Space Used */
        CHECK_GETATTR_BUF_SPACE(len, 8);
        st->nfs_used = nfs_pntoh64((uint32_t *)(void *)buf);
        buf += 8;
        len -= 8;
        /* ATime */
        CHECK_GETATTR_BUF_SPACE(len, 12);
        st->nfs_atime = nfs_pntoh64((uint32_t *)(void *)buf);
        buf += 8;
        len -= 8;
        st->nfs_atime_nsec = ntohl(*(uint32_t *)(void *)buf);
        buf += 4;
        len -= 4;
        /* CTime */
        CHECK_GETATTR_BUF_SPACE(len, 12);
        st->nfs_ctime = nfs_pntoh64((uint32_t *)(void *)buf);
        buf += 8;
        len -= 8;
        st->nfs_ctime_nsec = ntohl(*(uint32_t *)(void *)buf);
        buf += 4;
        len -= 4;
        /* MTime */
        CHECK_GETATTR_BUF_SPACE(len, 12);
        st->nfs_mtime = nfs_pntoh64((uint32_t *)(void *)buf);
        buf += 8;
        len -= 8;
        st->nfs_mtime_nsec = ntohl(*(uint32_t *)(void *)buf);
        buf += 4;
        len -= 4;

        st->nfs_blksize = 4096;
        st->nfs_blocks  = st->nfs_used / 4096;

        return 0;
}

/* Caller will free the returned path. */
static char *
nfs4_resolve_path(struct nfs_context *nfs, const char *path)
{
        char *new_path = NULL;

        /* Absolute paths we just use as is.
         * Relateive paths have cwd prepended to them and then become
         * absolute paths too.
         */
        if (path[0] == '/') {
                new_path = strdup(path);
        } else {
                new_path = malloc(strlen(path) + strlen(nfs->cwd) + 2);
                if (new_path != NULL) {
                        sprintf(new_path, "%s/%s", nfs->cwd, path);
                }
        }
        if (new_path == NULL) {
                nfs_set_error(nfs, "Out of memory: failed to "
                              "allocate path string");
                return NULL;
        }

        if (nfs_normalize_path(nfs, new_path)) {
                nfs_set_error(nfs, "Failed to normalize real path. %s",
                              nfs_get_error(nfs));
                free(new_path);
                return NULL;
        }

        return new_path;
}

static int
nfs4_num_path_components(struct nfs_context *nfs, const char *path)
{
        int i;

        for (i = 0; (path = strchr(path, '/')); path++, i++)
                ;

        return i;
}

/*
 * Allocate op and populate the path components.
 * Will mutate path.
 *
 * Returns:
 *     -1 : On error.
 *  <idx> : On success. Idx represents the next free index in op.
 *          Caller must free op.
 */
static int
nfs4_allocate_op(struct nfs_context *nfs, nfs_argop4 **op,
                 char *path, int num_extra)
{
        char *ptr;
        int i, count;
        GETATTR4args *gaargs;
        static uint32_t attributes[2];

        *op = NULL;

        count = nfs4_num_path_components(nfs, path);

        *op = malloc(sizeof(**op) * (2 + 2 * count + num_extra));
        if (*op == NULL) {
                nfs_set_error(nfs, "Failed to allocate op array");
                return -1;
        }

        i = 0;
        if (nfs->rootfh.len) {
                static struct PUTFH4args *pfh;

                pfh = &(*op)[i].nfs_argop4_u.opputfh;
                pfh->object.nfs_fh4_len = nfs->rootfh.len;
                pfh->object.nfs_fh4_val = nfs->rootfh.val;
                (*op)[i++].argop = OP_PUTFH;
        } else {
                (*op)[i++].argop = OP_PUTROOTFH;
        }

        ptr = &path[1];
        while (ptr && *ptr != 0) {
                char *tmp;
                LOOKUP4args *la;

                tmp = strchr(ptr, '/');
                if (tmp) {
                        *tmp = 0;
                        tmp = tmp + 1;
                }
                (*op)[i].argop = OP_LOOKUP;
                la = &(*op)[i].nfs_argop4_u.oplookup;
                
                la->objname.utf8string_len = strlen(ptr);
                la->objname.utf8string_val = ptr;

                ptr = tmp;
                i++;
        }                

        gaargs = &(*op)[i].nfs_argop4_u.opgetattr;
        (*op)[i++].argop = OP_GETATTR;
        memset(gaargs, 0, sizeof(*gaargs));

        attributes[0] =
                1 << FATTR4_TYPE |
                1 << FATTR4_SIZE |
                1 << FATTR4_FILEID;
        attributes[1] =
                1 << (FATTR4_MODE - 32) |
                1 << (FATTR4_NUMLINKS - 32) |
                1 << (FATTR4_OWNER - 32) |
                1 << (FATTR4_OWNER_GROUP - 32) |
                1 << (FATTR4_SPACE_USED - 32) |
                1 << (FATTR4_TIME_ACCESS - 32) |
                1 << (FATTR4_TIME_METADATA - 32) |
                1 << (FATTR4_TIME_MODIFY - 32);
        gaargs->attr_request.bitmap4_len = 2;
        gaargs->attr_request.bitmap4_val = attributes;

        return i;
}

static int
nfs4_lookup_path_async(struct nfs_context *nfs,
                       struct nfs4_cb_data *data,
                       rpc_cb cb);

static void
nfs4_lookup_path_2_cb(struct rpc_context *rpc, int status, void *command_data,
                void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        READLINK4res *rlres = NULL;
        char *path, *tmp, *end;
        int i;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "READLINK")) {
                free_nfs4_cb_data(data);
                return;
        }

        path = strdup(data->path);
        if (path == NULL) {
                nfs_set_error(nfs, "Out of memory duplicating path.");
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs),
                         data->private_data);
                free_nfs4_cb_data(data);
                return;
        }

        tmp = &path[0];
        while (data->link.idx-- > 1) {
                tmp = strchr(tmp + 1, '/');
        }
        *tmp++ = 0;
        end = strchr(tmp, '/');
        if (end == NULL) {
                /* Symlink was the last component. */
                end = "";
        } else {
                *end++ = 0;
        }

        if ((i = nfs4_find_op(nfs, data, res, OP_READLINK, "READLINK")) < 0) {
                free(path);
                return;
        }
        rlres = &res->resarray.resarray_val[i].nfs_resop4_u.opreadlink;
        
        tmp = malloc(strlen(data->path) + 3 + strlen(rlres->READLINK4res_u.resok4.link.utf8string_val));
        if (tmp == NULL) {
                nfs_set_error(nfs, "Out of memory duplicating path.");
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs),
                         data->private_data);
                free_nfs4_cb_data(data);
                free(path);
                return;
        }

        sprintf(tmp, "%s/%s/%s", path, rlres->READLINK4res_u.resok4.link.utf8string_val, end);
        free(path);
        free(data->path);
        data->path = tmp;

        if (nfs4_lookup_path_async(nfs, data, data->continue_cb) < 0) {
                data->cb(-ENOMEM, nfs, res, data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
}

static int
nfs4_open_readlink(struct rpc_context *rpc, COMPOUND4res *res,
                   struct nfs4_cb_data *data);

static void
nfs4_lookup_path_1_cb(struct rpc_context *rpc, int status, void *command_data,
                void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4args args;
        nfs_argop4 *op;
        COMPOUND4res *res = command_data;
        int i;
        int resolve_link = 0;
        char *path, *tmp;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (status == RPC_STATUS_ERROR) {
                data->cb(-EFAULT, nfs, res, data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
        if (status == RPC_STATUS_CANCEL) {
                data->cb(-EINTR, nfs, "Command was cancelled",
                         data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
        if (status == RPC_STATUS_TIMEOUT) {
                data->cb(-EINTR, nfs, "Command timed out",
                         data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
        if (res->status != NFS4_OK &&
            res->status != NFS4ERR_SYMLINK) {
                nfs_set_error(nfs, "NFS4: (path %s) failed with "
                              "%s(%d)",
                              data->path,
                              nfsstat4_to_str(res->status),
                              nfsstat4_to_errno(res->status));
                data->cb(nfsstat3_to_errno(res->status), nfs,
                         nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return;
        }

        for (i = 0; i < (int)res->resarray.resarray_len; i++) {
                if (res->resarray.resarray_val[i].resop == OP_GETATTR) {
                        GETATTR4resok *garesok;
                        struct nfs_stat_64 st;

                        garesok = &res->resarray.resarray_val[i].nfs_resop4_u.opgetattr.GETATTR4res_u.resok4;

                        memset(&st, 0, sizeof(st));
                        if (nfs_parse_attributes(nfs, data, &st,
                                 garesok->obj_attributes.attr_vals.attrlist4_val,
                                 garesok->obj_attributes.attr_vals.attrlist4_len) < 0) {
                                data->cb(-EINVAL, nfs, nfs_get_error(nfs), data->private_data);
                                free_nfs4_cb_data(data);
                                return;
                        }
                        if ((st.nfs_mode & S_IFMT) == S_IFLNK) {
                                /* The final component of the path was a
                                 * symlink so we may need to resolve it.
                                 */
                                resolve_link = 1;
                        }
                }
        }

        /* Open/create is special since the final component for the file
         * object is sent as part of the OP_OPEN command. So even if the
         * directory path is all good and resolved, we still need to check
         * the attributes for the final component and resolve it if it too
         * is a symlink.
         */
        if (!resolve_link) {
                if (nfs4_open_readlink(rpc, res, data) < 0) {
                        /* It was a symlink and we have started trying to
                         * resolve it. Nothing more to do here.
                         */
                        return;
                }
        }

        if (data->flags & LOOKUP_FLAG_NO_FOLLOW) {
                /* Do not resolve the final component of the path
                 * if it is a symlink.
                 */
                resolve_link = 0;
        }

        /* Everything is good so we can just pass it on to the next
         * phase.
         */
        if (res->status == NFS4_OK && !resolve_link) {
                data->continue_cb(rpc, NFS4_OK, res, data);
                return;
        }

        /* Find the lookup that failed and the associated fh */
        data->link.idx = 0;
        for (i = 0; i < (int)res->resarray.resarray_len; i++) {
                if (res->resarray.resarray_val[i].resop == OP_LOOKUP) {
                        if (res->resarray.resarray_val[i].nfs_resop4_u.oplookup.status == NFS4ERR_SYMLINK) {
                                break;
                        }
                        data->link.idx++;
                }
        }

        if (!resolve_link && i == res->resarray.resarray_len) {
                nfs_set_error(nfs, "Symlink not found during lookup.");
                data->cb(-EFAULT, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return;
        }

        /* Build a new path that strips of everything after the symlink. */
        path = strdup(data->path);
        if (path == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to duplicate "
                              "path.");
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs),
                         data->private_data);
                free_nfs4_cb_data(data);
                return;
        }

        /* The symlink is not the last component, so find the '/' before
         * the symlink and zero it out.
         */
        if (!resolve_link) {
                tmp = path;
                for (i = 0; i < data->link.idx; i++) {
                        tmp = strchr(tmp + 1, '/');
                }
                *tmp = 0;
        }

        /* We need to resolve the symlink */
        if ((i = nfs4_allocate_op(nfs, &op, path, 1)) < 0) {
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                free(path);
                return;
        }

        /* Append a READLINK command */
        op[i++].argop = OP_READLINK;

        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = i;
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(nfs->rpc, nfs4_lookup_path_2_cb, &args,
                                    data) != 0) {
                nfs_set_error(nfs, "Failed to queue READLINK command. %s",
                              nfs_get_error(nfs));
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                free(path);
                return;
        }
        free(path);
}

static int
nfs4_lookup_path_async(struct nfs_context *nfs,
                       struct nfs4_cb_data *data,
                       rpc_cb cb)
{
        COMPOUND4args args;
        nfs_argop4 *op;
        char *path;
        int i;

        path = nfs4_resolve_path(nfs, data->path);
        if (path == NULL) {
                return -1;
        }
        free(data->path);
        data->path = path;

        path = strdup(path);
        if (path == NULL) {
                return -1;
        }

        if ((i = nfs4_allocate_op(nfs, &op, path, data->filler.num_op)) < 0) {
                free(path);
                return -1;
        }

        data->filler.func(data, &op[i]);
        data->continue_cb = cb;

        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = i + data->filler.num_op;
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(nfs->rpc, nfs4_lookup_path_1_cb, &args,
                                    data) != 0) {
                nfs_set_error(nfs, "Failed to queue LOOKUP command. %s",
                              nfs_get_error(nfs));
                free(path);
                free(op);
                return -1;
        }

        free(path);
        free(op);
        return 0;
}

static void
nfs4_populate_getattr(struct nfs4_cb_data *data, nfs_argop4 *op)
{
        op[0].argop = OP_GETFH;
}

static void
nfs4_mount_4_cb(struct rpc_context *rpc, int status, void *command_data,
                void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        GETFH4resok *gfhresok;
        int i;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "GETFH")) {
                free_nfs4_cb_data(data);
                return;
        }

        if ((i = nfs4_find_op(nfs, data, res, OP_GETFH, "GETFH")) < 0) {
                return;
        }
        gfhresok = &res->resarray.resarray_val[i].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;

        nfs->rootfh.len = gfhresok->object.nfs_fh4_len;
        nfs->rootfh.val = malloc(nfs->rootfh.len);
        if (nfs->rootfh.val == NULL) {
                nfs_set_error(nfs, "%s: %s", __FUNCTION__, nfs_get_error(nfs));
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
        memcpy(nfs->rootfh.val,
               gfhresok->object.nfs_fh4_val,
               nfs->rootfh.len);


        data->cb(0, nfs, NULL, data->private_data);
        free_nfs4_cb_data(data);
}

static void
nfs4_mount_3_cb(struct rpc_context *rpc, int status, void *command_data,
                void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "SETCLIENTID_CONFIRM")) {
                free_nfs4_cb_data(data);
                return;
        }

        data->filler.func = nfs4_populate_getattr;
        data->filler.num_op = 1;
        data->filler.data = malloc(2 * sizeof(uint32_t));
        if (data->filler.data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "data structure.");
                data->cb(-ENOMEM, nfs, res, data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
        memset(data->filler.data, 0, 2 * sizeof(uint32_t));


        if (nfs4_lookup_path_async(nfs, data, nfs4_mount_4_cb) < 0) {
                data->cb(-ENOMEM, nfs, res, data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
}

static void
nfs4_mount_2_cb(struct rpc_context *rpc, int status, void *command_data,
                void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        COMPOUND4args args;
        nfs_argop4 op[1];
        SETCLIENTID_CONFIRM4args *scidcargs;
        SETCLIENTID4resok *scidresok;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "SETCLIENTID")) {
                free_nfs4_cb_data(data);
                return;
        }

        scidresok = &res->resarray.resarray_val[0].nfs_resop4_u.opsetclientid.SETCLIENTID4res_u.resok4;
        nfs->clientid = scidresok->clientid;
        memcpy(nfs->setclientid_confirm,
               scidresok->setclientid_confirm,
               NFS4_VERIFIER_SIZE);

        memset(op, 0, sizeof(op));
        scidcargs = &op[0].nfs_argop4_u.opsetclientid_confirm;
        op[0].argop = OP_SETCLIENTID_CONFIRM;
        scidcargs->clientid = nfs->clientid;
        memcpy(scidcargs->setclientid_confirm,
               nfs->setclientid_confirm,
               NFS4_VERIFIER_SIZE);
               
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, nfs4_mount_3_cb, &args,
                                    private_data) != 0) {
                nfs_set_error(nfs, "Failed to queue SETCLIENTID_CONFIRM. %s",
                              nfs_get_error(nfs));
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
}

static void
nfs4_mount_1_cb(struct rpc_context *rpc, int status, void *command_data,
                void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4args args;
        nfs_argop4 op[1];
        SETCLIENTID4args *scidargs;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, NULL, "CONNECT")) {
                free_nfs4_cb_data(data);
                return;
        }

        memset(op, 0, sizeof(op));
        op[0].argop = OP_SETCLIENTID;
        scidargs = &op[0].nfs_argop4_u.opsetclientid;
        memcpy(scidargs->client.verifier, nfs->verifier, sizeof(verifier4));
        scidargs->client.id.id_len = strlen(nfs->client_name);
        scidargs->client.id.id_val = nfs->client_name;
        /* TODO: Decide what we should do here. As long as we only
         * expose a single FD to the application we will not be able to
         * do NFSv4 callbacks easily.
         * Just give it garbage for now until we figure out how we should
         * solve this. Until then we will just have to avoid doing things
         * that require a callback.
         * ( Clients (i.e. Linux) ignore this anyway and just call back to
         *   the originating address and program anyway. )
         */
        scidargs->callback.cb_program = 0; /* NFS4_CALLBACK */
        scidargs->callback.cb_location.r_netid = "tcp";
        scidargs->callback.cb_location.r_addr = "0.0.0.0.0.0";
        scidargs->callback_ident = 0x00000001;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, nfs4_mount_2_cb, &args, data) != 0) {
                nfs_set_error(nfs, "Failed to queue SETCLIENTID. %s",
                              nfs_get_error(nfs));
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
}

int
nfs4_mount_async(struct nfs_context *nfs, const char *server,
                 const char *export, nfs_cb cb, void *private_data)
{
        struct nfs4_cb_data *data;
        char *new_server, *new_export;

        new_server = strdup(server);
        free(nfs->server);
        nfs->server = new_server;

        new_export = strdup(export);
        if (nfs_normalize_path(nfs, new_export)) {
                nfs_set_error(nfs, "Bad export path. %s",
                              nfs_get_error(nfs));
                free(new_export);
                return -1;
        }
        free(nfs->export);
        nfs->export = new_export;


        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "memory for nfs mount data");
                return -1;
        }
        memset(data, 0, sizeof(*data));

        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;
        data->path         = strdup(new_export);

        if (rpc_connect_program_async(nfs->rpc, server,
                                      NFS4_PROGRAM, NFS_V4,
                                      nfs4_mount_1_cb, data) != 0) {
                nfs_set_error(nfs, "Failed to start connection");
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

static void
nfs4_chdir_1_cb(struct rpc_context *rpc, int status, void *command_data,
                void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "CHDIR")) {
                free_nfs4_cb_data(data);
                return;
        }

        /* Ok, all good. Lets steal the path string. */
        free(nfs->cwd);
        nfs->cwd = data->path;
        data->path = NULL;

        data->cb(0, nfs, NULL, data->private_data);
        free_nfs4_cb_data(data);
}

int nfs4_chdir_async(struct nfs_context *nfs, const char *path,
                     nfs_cb cb, void *private_data)
{
        struct nfs4_cb_data *data;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));
        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;
        data->path = nfs4_resolve_path(nfs, path);

        if (data->path == NULL) {
                nfs_set_error(nfs, "Out of memory duplicating path");
                free_nfs4_cb_data(data);
                return -1;
        }

        data->filler.func = nfs4_populate_getattr;
        data->filler.num_op = 1;
        data->filler.data = malloc(2 * sizeof(uint32_t));
        if (data->filler.data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "data structure.");
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return -1;
        }
        memset(data->filler.data, 0, 2 * sizeof(uint32_t));

        if (nfs4_lookup_path_async(nfs, data, nfs4_chdir_1_cb) < 0) {
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

static void
nfs4_xstat64_cb(struct rpc_context *rpc, int status, void *command_data,
                void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        GETATTR4resok *garesok;
        struct nfs_stat_64 st;
        int i;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "STAT64")) {
                free_nfs4_cb_data(data);
                return;
        }

        if ((i = nfs4_find_op(nfs, data, res, OP_GETATTR, "GETATTR")) < 0) {
                return;
        }
        garesok = &res->resarray.resarray_val[i].nfs_resop4_u.opgetattr.GETATTR4res_u.resok4;

        memset(&st, 0, sizeof(st));
        if (nfs_parse_attributes(nfs, data, &st,
                                 garesok->obj_attributes.attr_vals.attrlist4_val,
                                 garesok->obj_attributes.attr_vals.attrlist4_len) < 0) {
                data->cb(-EINVAL, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
        }

        data->cb(0, nfs, &st, data->private_data);
        free_nfs4_cb_data(data);
}

int
nfs4_stat64_async(struct nfs_context *nfs, const char *path,
                  int no_follow, nfs_cb cb, void *private_data)
{
        struct nfs4_cb_data *data;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));
        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;
        if (no_follow) {
                data->flags |= LOOKUP_FLAG_NO_FOLLOW;
        }
        data->path = nfs4_resolve_path(nfs, path);
        if (data->path == NULL) {
                nfs_set_error(nfs, "Out of memory duplicating path");
                free_nfs4_cb_data(data);
                return -1;
        }

        data->filler.func = nfs4_populate_getattr;
        data->filler.num_op = 1;
        data->filler.data = malloc(2 * sizeof(uint32_t));
        if (data->filler.data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "data structure.");
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return -1;
        }
        memset(data->filler.data, 0, 2 * sizeof(uint32_t));

        if (nfs4_lookup_path_async(nfs, data, nfs4_xstat64_cb) < 0) {
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

/* Takes object name as filler.data
 * blob0 as the fattr4 attribute mask
 * blob1 as the fattr4 attribute list
 */
static void
nfs4_populate_mkdir(struct nfs4_cb_data *data, nfs_argop4 *op)
{
        CREATE4args *cargs;

        cargs = &op[0].nfs_argop4_u.opcreate;
        memset(cargs, 0, sizeof(*cargs));
        cargs->objtype.type = NF4DIR;
        cargs->objname.utf8string_val = data->filler.data;
        cargs->objname.utf8string_len = strlen(cargs->objname.utf8string_val);
        cargs->createattrs.attrmask.bitmap4_len = data->filler.blob0.len;
        cargs->createattrs.attrmask.bitmap4_val = data->filler.blob0.val;
        cargs->createattrs.attr_vals.attrlist4_len = data->filler.blob1.len;
        cargs->createattrs.attr_vals.attrlist4_val = data->filler.blob1.val;
        op[0].argop = OP_CREATE;
}

static void
nfs4_mkdir_cb(struct rpc_context *rpc, int status, void *command_data,
              void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "MKDIR")) {
                free_nfs4_cb_data(data);
                return;
        }

        data->cb(0, nfs, NULL, data->private_data);
        free_nfs4_cb_data(data);
}

int
nfs4_mkdir2_async(struct nfs_context *nfs, const char *orig_path, int mode,
                 nfs_cb cb, void *private_data)
{
        struct nfs4_cb_data *data;
        uint32_t *u32ptr;
        char *path;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));

        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;

        data->path = nfs4_resolve_path(nfs, orig_path);
        if (data->path == NULL) {
                nfs_set_error(nfs, "Out of memory resolving path");
                free_nfs4_cb_data(data);
                return -1;
        }

        path = strrchr(data->path, '/');
        if (path == data->path) {
                char *ptr;

                for (ptr = data->path; *ptr; ptr++) {
                        *ptr = *(ptr + 1);
                }
                /* No path to lookup */
                data->filler.data = data->path;
                data->path = strdup("/");
        } else {
                *path++ = 0;
                data->filler.data = strdup(path);
        }
        data->filler.func = nfs4_populate_mkdir;
        data->filler.num_op = 1;
        
        /* attribute mask */
        u32ptr = malloc(2 * sizeof(uint32_t));
        if (u32ptr == NULL) {
                nfs_set_error(nfs, "Out of memory allocating bitmap");
                free_nfs4_cb_data(data);
                return -1;
        }
        u32ptr[0] = 0;
        u32ptr[1] = 1 << (FATTR4_MODE - 32);
        data->filler.blob0.len = 2;
        data->filler.blob0.val = u32ptr;

        /* attribute values */
        u32ptr = malloc(1 * sizeof(uint32_t));
        if (u32ptr == NULL) {
                nfs_set_error(nfs, "Out of memory allocating attributes");
                free_nfs4_cb_data(data);
                return -1;
        }
        u32ptr[0] = htonl(mode);
        data->filler.blob1.len = 4;
        data->filler.blob1.val = u32ptr;

        if (nfs4_lookup_path_async(nfs, data, nfs4_mkdir_cb) < 0) {
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

/* Takes object name as filler.data
 */
static void
nfs4_populate_rmdir(struct nfs4_cb_data *data, nfs_argop4 *op)
{
        REMOVE4args *rmargs;

        rmargs = &op[0].nfs_argop4_u.opremove;
        memset(rmargs, 0, sizeof(*rmargs));
        rmargs->target.utf8string_val = data->filler.data;
        rmargs->target.utf8string_len = strlen(rmargs->target.utf8string_val);
        op[0].argop = OP_REMOVE;
}

static void
nfs4_rmdir_cb(struct rpc_context *rpc, int status, void *command_data,
              void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "RMDIR")) {
                free_nfs4_cb_data(data);
                return;
        }

        data->cb(0, nfs, NULL, data->private_data);
        free_nfs4_cb_data(data);
}

int
nfs4_rmdir_async(struct nfs_context *nfs, const char *orig_path,
                 nfs_cb cb, void *private_data)
{
        struct nfs4_cb_data *data;
        char *path;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));

        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;

        data->path = nfs4_resolve_path(nfs, orig_path);
        if (data->path == NULL) {
                nfs_set_error(nfs, "Out of memory resolving path");
                free_nfs4_cb_data(data);
                return -1;
        }

        path = strrchr(data->path, '/');
        if (path == data->path) {
                char *ptr;

                for (ptr = data->path; *ptr; ptr++) {
                        *ptr = *(ptr + 1);
                }
                /* No path to lookup */
                data->filler.data = data->path;
                data->path = strdup("/");
        } else {
                *path++ = 0;
                data->filler.data = strdup(path);
        }
        data->filler.func = nfs4_populate_rmdir;
        data->filler.num_op = 1;

        if (nfs4_lookup_path_async(nfs, data, nfs4_rmdir_cb) < 0) {
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

static void
nfs4_open_confirm_cb(struct rpc_context *rpc, int status, void *command_data,
                     void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        OPEN_CONFIRM4resok *ocresok;
        int i;
        struct nfsfh *fh;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "OPEN_CONFIRM")) {
                free_nfs4_cb_data(data);
                return;
        }

        if ((i = nfs4_find_op(nfs, data, res, OP_OPEN_CONFIRM,
                              "OPEN_CONFIRM")) < 0) {
                return;
        }
        ocresok = &res->resarray.resarray_val[i].nfs_resop4_u.opopen_confirm.OPEN_CONFIRM4res_u.resok4;

        fh = data->filler.blob0.val;
        data->filler.blob0.val = NULL;
        data->filler.blob1.val = NULL;

        fh->stateid.seqid = ocresok->open_stateid.seqid;
        memcpy(fh->stateid.other, ocresok->open_stateid.other, 12);

        data->cb(0, nfs, fh, data->private_data);
        free_nfs4_cb_data(data);
}

static void
nfs4_open_cb(struct rpc_context *rpc, int status, void *command_data,
              void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        ACCESS4resok *aresok;
        OPEN4resok *oresok;
        GETFH4resok *gresok;
        int i;
        struct nfsfh *fh;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "OPEN")) {
                free_nfs4_cb_data(data);
                return;
        }

        /* Parse Access and check that we have the access that we need */
        if ((i = nfs4_find_op(nfs, data, res, OP_ACCESS, "ACCESS")) < 0) {
                return;
        }
        aresok = &res->resarray.resarray_val[i].nfs_resop4_u.opaccess.ACCESS4res_u.resok4;
        if (aresok->supported != aresok->access) {
                nfs_set_error(nfs, "Insufficient ACCESS. Wanted %08x but "
                              "got %08x.", aresok->access, aresok->supported);
                data->cb(-EINVAL, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return;
        }

        /* Parse GetFH */
        if ((i = nfs4_find_op(nfs, data, res, OP_GETFH, "GETFH")) < 0) {
                return;
        }
        gresok = &res->resarray.resarray_val[i].nfs_resop4_u.opgetfh.GETFH4res_u.resok4;

        fh = malloc(sizeof(*fh));
        if (fh == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "nfsfh");
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
        memset(fh, 0 , sizeof(*fh));

        data->filler.blob0.val = fh;

        fh->fh.len = gresok->object.nfs_fh4_len;
        fh->fh.val = malloc(fh->fh.len);
        if (fh->fh.val == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "nfsfh");
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
        memcpy(fh->fh.val, gresok->object.nfs_fh4_val, fh->fh.len);

        data->filler.blob1.val = fh->fh.val;

        /* Parse Open */
        if ((i = nfs4_find_op(nfs, data, res, OP_OPEN, "OPEN")) < 0) {
                return;
        }
        oresok = &res->resarray.resarray_val[i].nfs_resop4_u.opopen.OPEN4res_u.resok4;
        fh->stateid.seqid = oresok->stateid.seqid;
        memcpy(fh->stateid.other, oresok->stateid.other, 12);


        if (oresok->rflags & OPEN4_RESULT_CONFIRM) {
                COMPOUND4args args;
                nfs_argop4 op[2];

                memset(op, 0, sizeof(op));
                op[0].argop = OP_PUTFH;
                op[0].nfs_argop4_u.opputfh.object.nfs_fh4_len = fh->fh.len;
                op[0].nfs_argop4_u.opputfh.object.nfs_fh4_val = fh->fh.val;
                op[1].argop = OP_OPEN_CONFIRM;
                op[1].nfs_argop4_u.opopen_confirm.open_stateid.seqid =
                        fh->stateid.seqid;
                memcpy(op[1].nfs_argop4_u.opopen_confirm.open_stateid.other,
                       fh->stateid.other, 12);
                op[1].nfs_argop4_u.opopen_confirm.seqid = nfs->seqid;
                nfs->seqid++;

                memset(&args, 0, sizeof(args));
                args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
                args.argarray.argarray_val = op;

                if (rpc_nfs4_compound_async(rpc, nfs4_open_confirm_cb, &args,
                                            private_data) != 0) {
                        data->cb(-ENOMEM, nfs, nfs_get_error(nfs),
                                 data->private_data);
                        free_nfs4_cb_data(data);
                        return;
                }
                return;
        }

        data->filler.blob0.val = NULL;
        data->filler.blob1.val = NULL;
        data->cb(0, nfs, fh, data->private_data);
        free_nfs4_cb_data(data);
}

static void
nfs4_open_readlink_cb(struct rpc_context *rpc, int status, void *command_data,
                 void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        READLINK4resok *rlresok;
        int i;
        char *path;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "READLINK")) {
                free_nfs4_cb_data(data);
                return;
        }

        if ((i = nfs4_find_op(nfs, data, res, OP_READLINK, "READLINK")) < 0) {
                return;
        }

        rlresok = &res->resarray.resarray_val[i].nfs_resop4_u.opreadlink.READLINK4res_u.resok4;

        path = malloc(2 + strlen(data->path) +
                      strlen(rlresok->link.utf8string_val));
        if (path == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "path");
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs),
                         data->private_data);
                free_nfs4_cb_data(data);
                return;
        }
        sprintf(path, "%s/%s", data->path, rlresok->link.utf8string_val);

        /* We have resolved the final component and created a new path.
         * Try to call open again.
         */
        if (nfs4_open_async(nfs, path, data->filler.flags,
                            data->cb, data->private_data) < 0) {
                data->cb(-ENOMEM, nfs, nfs_get_error(nfs), data->private_data);
                free_nfs4_cb_data(data);
                free(path);
                return;
        }
        free_nfs4_cb_data(data);
        free(path);
}

static void
nfs4_populate_lookup_readlink(struct nfs4_cb_data *data, nfs_argop4 *op)
{
        LOOKUP4args *largs;

        op[0].argop = OP_LOOKUP;

        largs = &op[0].nfs_argop4_u.oplookup;
        largs->objname.utf8string_len = strlen(data->filler.data);
        largs->objname.utf8string_val = data->filler.data;

        op[1].argop = OP_READLINK;
}

/* If the final component in the open was a symlink we need to resolve it and
 * re-try the nfs4_open_async()
 */
static int
nfs4_open_readlink(struct rpc_context *rpc, COMPOUND4res *res,
                   struct nfs4_cb_data *data)
{
        struct nfs_context *nfs = data->nfs;
        int i;

        for (i = 0; i < (int)res->resarray.resarray_len; i++) {
                OPEN4res *ores;

                if (res->resarray.resarray_val[i].resop != OP_OPEN) {
                        continue;
                }
                ores = &res->resarray.resarray_val[i].nfs_resop4_u.opopen;

                if (ores->status != NFS4ERR_SYMLINK) {
                        continue;
                }

                if (data->filler.flags & O_NOFOLLOW) {
                        nfs_set_error(nfs, "Symlink encountered during "
                                      "open(O_NOFOLLOW)");
                        data->cb(-ELOOP, nfs, nfs_get_error(nfs),
                                 data->private_data);
                        return -1;
                }

                /* The object we need to do readlink on is already stored in
                 * data->filler.data so *populate* can just grab it from there.
                 */
                data->filler.func = nfs4_populate_lookup_readlink;
                data->filler.num_op = 2;

                if (nfs4_lookup_path_async(nfs, data,
                                           nfs4_open_readlink_cb) < 0) {
                        data->cb(-ENOMEM, nfs, nfs_get_error(nfs),
                                 data->private_data);
                        free_nfs4_cb_data(data);
                        return -1;
                }
                return -1;
        }

        return 0;
}

/* filler.flags are the open flags
 * filler.data is the object name
 */
static void
nfs4_populate_open(struct nfs4_cb_data *data, nfs_argop4 *op)
{
        struct nfs_context *nfs = data->nfs;
        ACCESS4args *aargs;
        OPEN4args *oargs;

        /* Access */
        op[0].argop = OP_ACCESS;
        aargs = &op[0].nfs_argop4_u.opaccess;
        memset(aargs, 0, sizeof(*aargs));

	if (data->filler.flags & O_WRONLY) {
		aargs->access |= ACCESS4_MODIFY;
	}
	if (data->filler.flags & O_RDWR) {
		aargs->access |= ACCESS4_READ|ACCESS4_MODIFY;
	}
	if (!(data->filler.flags & (O_WRONLY|O_RDWR))) {
		aargs->access |= ACCESS4_READ;
	}

        /* Open */
        op[1].argop = OP_OPEN;
        oargs = &op[1].nfs_argop4_u.opopen;
        memset(oargs, 0, sizeof(*oargs));

        oargs->seqid = nfs->seqid++;
        oargs->share_access = OPEN4_SHARE_ACCESS_READ;
        oargs->share_deny = OPEN4_SHARE_DENY_NONE;
        oargs->owner.clientid = nfs->clientid;
        oargs->owner.owner.owner_len = strlen(nfs->client_name);
        oargs->owner.owner.owner_val = nfs->client_name;
        oargs->openhow.opentype = OPEN4_NOCREATE;
        oargs->claim.claim = CLAIM_NULL;
        oargs->claim.open_claim4_u.file.utf8string_len =
                strlen(data->filler.data);
        oargs->claim.open_claim4_u.file.utf8string_val =
                data->filler.data;

        /* GetFH */
        op[2].argop = OP_GETFH;
}

int
nfs4_open_async(struct nfs_context *nfs, const char *orig_path, int flags,
                nfs_cb cb, void *private_data)
{
        struct nfs4_cb_data *data;
        char *path;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));

        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;

        data->path = nfs4_resolve_path(nfs, orig_path);
        if (data->path == NULL) {
                nfs_set_error(nfs, "Out of memory resolving path");
                free_nfs4_cb_data(data);
                return -1;
        }

        path = strrchr(data->path, '/');
        if (path == data->path) {
                char *ptr;

                for (ptr = data->path; *ptr; ptr++) {
                        *ptr = *(ptr + 1);
                }
                /* No path to lookup */
                data->filler.data = data->path;
                data->path = strdup("/");
        } else {
                *path++ = 0;
                data->filler.data = strdup(path);
        }

        data->filler.func = nfs4_populate_open;
        data->filler.num_op = 3;
        data->filler.flags = flags;

        if (nfs4_lookup_path_async(nfs, data, nfs4_open_cb) < 0) {
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

int
nfs4_fstat64_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb,
                   void *private_data)
{
        COMPOUND4args args;
        nfs_argop4 op[2];
        PUTFH4args *pfargs;
        GETATTR4args *gaargs;
        uint32_t attributes[2];
        struct nfs4_cb_data *data;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));

        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;

        op[0].argop = OP_PUTFH;
        pfargs = &op[0].nfs_argop4_u.opputfh;
        pfargs->object.nfs_fh4_len = nfsfh->fh.len;
        pfargs->object.nfs_fh4_val = nfsfh->fh.val;

        gaargs = &op[1].nfs_argop4_u.opgetattr;
        op[1].argop = OP_GETATTR;
        memset(gaargs, 0, sizeof(*gaargs));

        attributes[0] =
                1 << FATTR4_TYPE |
                1 << FATTR4_SIZE |
                1 << FATTR4_FILEID;
        attributes[1] =
                1 << (FATTR4_MODE - 32) |
                1 << (FATTR4_NUMLINKS - 32) |
                1 << (FATTR4_OWNER - 32) |
                1 << (FATTR4_OWNER_GROUP - 32) |
                1 << (FATTR4_SPACE_USED - 32) |
                1 << (FATTR4_TIME_ACCESS - 32) |
                1 << (FATTR4_TIME_METADATA - 32) |
                1 << (FATTR4_TIME_MODIFY - 32);
        gaargs->attr_request.bitmap4_len = 2;
        gaargs->attr_request.bitmap4_val = attributes;

        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(nfs->rpc, nfs4_xstat64_cb, &args,
                                    data) != 0) {
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

static void
nfs4_close_cb(struct rpc_context *rpc, int status, void *command_data,
              void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        struct nfsfh *nfsfh;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        nfsfh = data->filler.blob0.val;
        data->filler.blob0.val = NULL;

        if (check_nfs4_error(nfs, status, data, res, "OPEN_CONFIRM")) {
                free_nfs4_cb_data(data);
                return;
        }

        data->cb(0, nfs, NULL, data->private_data);
        nfs_free_nfsfh(nfsfh);
        free_nfs4_cb_data(data);
}

int
nfs4_close_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb,
                 void *private_data)
{
        COMPOUND4args args;
        nfs_argop4 op[3];
        PUTFH4args *pfargs;
        COMMIT4args *coargs;
        CLOSE4args *clargs;
        struct nfs4_cb_data *data;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));

        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;

        memset(op, 0, sizeof(op));

        op[0].argop = OP_PUTFH;
        pfargs = &op[0].nfs_argop4_u.opputfh;
        pfargs->object.nfs_fh4_len = nfsfh->fh.len;
        pfargs->object.nfs_fh4_val = nfsfh->fh.val;

        op[1].argop = OP_COMMIT;
        coargs = &op[1].nfs_argop4_u.opcommit;
        coargs->offset = 0;
        coargs->count = 0;

        op[2].argop = OP_CLOSE;
        clargs = &op[2].nfs_argop4_u.opclose;
        clargs->seqid = nfs->seqid++;
        clargs->open_stateid.seqid = nfsfh->stateid.seqid;
        memcpy(clargs->open_stateid.other, nfsfh->stateid.other, 12);

        data->filler.blob0.val = nfsfh;


        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(nfs->rpc, nfs4_close_cb, &args,
                                    data) != 0) {
                data->filler.blob0.val = NULL;
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

static void
nfs4_pread_cb(struct rpc_context *rpc, int status, void *command_data,
              void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        READ4resok *rres = NULL;
        struct nfsfh *nfsfh;
        int i;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        nfsfh = data->filler.blob0.val;
        data->filler.blob0.val = NULL;

        if (check_nfs4_error(nfs, status, data, res, "READ")) {
                free_nfs4_cb_data(data);
                return;
        }

        if ((i = nfs4_find_op(nfs, data, res, OP_READ, "READ")) < 0) {
                return;
        }
        rres = &res->resarray.resarray_val[i].nfs_resop4_u.opread.READ4res_u.resok4;

        if (data->rw_data.update_pos) {
                nfsfh->offset = data->rw_data.offset + rres->data.data_len;
        }

        data->cb(rres->data.data_len, nfs, rres->data.data_val,
                 data->private_data);
        free_nfs4_cb_data(data);
}

int
nfs4_pread_async_internal(struct nfs_context *nfs, struct nfsfh *nfsfh,
                          uint64_t offset, size_t count, nfs_cb cb,
                          void *private_data, int update_pos)
{
        COMPOUND4args args;
        nfs_argop4 op[2];
        PUTFH4args *pfargs;
        READ4args *rargs;
        struct nfs4_cb_data *data;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));

        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;

        data->filler.blob0.val = nfsfh;
        data->rw_data.offset = offset;
        data->rw_data.update_pos = update_pos;
        
        memset(op, 0, sizeof(op));

        op[0].argop = OP_PUTFH;
        pfargs = &op[0].nfs_argop4_u.opputfh;
        pfargs->object.nfs_fh4_len = nfsfh->fh.len;
        pfargs->object.nfs_fh4_val = nfsfh->fh.val;

        op[1].argop = OP_READ;
        rargs = &op[1].nfs_argop4_u.opread;
        rargs->stateid.seqid = nfsfh->stateid.seqid;
        memcpy(rargs->stateid.other, nfsfh->stateid.other, 12);
        rargs->offset = offset;
        rargs->count = count;


        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(nfs->rpc, nfs4_pread_cb, &args,
                                    data) != 0) {
                data->filler.blob0.val = NULL;
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

static void
nfs4_symlink_cb(struct rpc_context *rpc, int status, void *command_data,
              void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "SYMLINK")) {
                free_nfs4_cb_data(data);
                return;
        }

        data->cb(0, nfs, NULL, data->private_data);
        free_nfs4_cb_data(data);
}

/* Takes object name as filler.data
 * blob0 as the target
 */
static void
nfs4_populate_symlink(struct nfs4_cb_data *data, nfs_argop4 *op)
{
        CREATE4args *cargs;

        cargs = &op[0].nfs_argop4_u.opcreate;
        memset(cargs, 0, sizeof(*cargs));
        cargs->objtype.type = NF4LNK;
        cargs->objtype.createtype4_u.linkdata.utf8string_len =
                strlen(data->filler.blob0.val);
        cargs->objtype.createtype4_u.linkdata.utf8string_val =
                data->filler.blob0.val;
        cargs->objname.utf8string_val = data->filler.data;
        cargs->objname.utf8string_len = strlen(cargs->objname.utf8string_val);
        op[0].argop = OP_CREATE;
}

int
nfs4_symlink_async(struct nfs_context *nfs, const char *target,
                   const char *linkname, nfs_cb cb, void *private_data)
{
        struct nfs4_cb_data *data;
        char *path;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));
        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;

        data->path = nfs4_resolve_path(nfs, linkname);
        if (data->path == NULL) {
                nfs_set_error(nfs, "Out of memory resolving path");
                free_nfs4_cb_data(data);
                return -1;
        }

        path = strrchr(data->path, '/');
        if (path == data->path) {
                char *ptr;

                for (ptr = data->path; *ptr; ptr++) {
                        *ptr = *(ptr + 1);
                }
                /* No path to lookup */
                data->filler.data = data->path;
                data->path = strdup("/");
        } else {
                *path++ = 0;
                data->filler.data = strdup(path);
        }
        data->filler.func = nfs4_populate_symlink;
        data->filler.num_op = 1;

        data->filler.blob0.val = strdup(target);

        if (nfs4_lookup_path_async(nfs, data, nfs4_symlink_cb) < 0) {
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}

static void
nfs4_readlink_cb(struct rpc_context *rpc, int status, void *command_data,
                 void *private_data)
{
        struct nfs4_cb_data *data = private_data;
        struct nfs_context *nfs = data->nfs;
        COMPOUND4res *res = command_data;
        READLINK4resok *rlresok;
        int i;

        assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (check_nfs4_error(nfs, status, data, res, "READLINK")) {
                free_nfs4_cb_data(data);
                return;
        }

        if ((i = nfs4_find_op(nfs, data, res, OP_READLINK, "READLINK")) < 0) {
                return;
        }

        rlresok = &res->resarray.resarray_val[i].nfs_resop4_u.opreadlink.READLINK4res_u.resok4;

        data->cb(0, nfs, rlresok->link.utf8string_val, data->private_data);
        free_nfs4_cb_data(data);
}

static void
nfs4_populate_readlink(struct nfs4_cb_data *data, nfs_argop4 *op)
{
        op[0].argop = OP_READLINK;
}

int
nfs4_readlink_async(struct nfs_context *nfs, const char *path, nfs_cb cb,
                    void *private_data)
{
        struct nfs4_cb_data *data;

        data = malloc(sizeof(*data));
        if (data == NULL) {
                nfs_set_error(nfs, "Out of memory. Failed to allocate "
                              "cb data");
                return -1;
        }
        memset(data, 0, sizeof(*data));
        data->nfs          = nfs;
        data->cb           = cb;
        data->private_data = private_data;
        data->path = nfs4_resolve_path(nfs, path);
        data->flags |= LOOKUP_FLAG_NO_FOLLOW;

        if (data->path == NULL) {
                nfs_set_error(nfs, "Out of memory duplicating path");
                free_nfs4_cb_data(data);
                return -1;
        }

        data->filler.func = nfs4_populate_readlink;
        data->filler.num_op = 1;

        if (nfs4_lookup_path_async(nfs, data, nfs4_readlink_cb) < 0) {
                free_nfs4_cb_data(data);
                return -1;
        }

        return 0;
}
