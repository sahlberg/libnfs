/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2025
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
/*
 * A non-blocking and eventdriven implementation of rpcbind using libnfs.
 * TODO: Call NULL periodically and reap dead services from the database.
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE


#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <talloc.h>
#include <tevent.h>
#include <time.h>
#include <unistd.h>

#include "mountd.h"

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-raw-nlm.h"
#include "../libnfs-server.h"

struct mountd_export {
        struct mountd_export *next;
        char *path;
        struct nfs_fh3 fh;
};
        
struct mountd_state {
        struct tevent_context *tevent;
        struct rpc_context *rpc;
        struct mountd_export *exports;
};

struct mountd_export *mountd_add_export(struct mountd_state *mountd, char *path, int fh_len, char *fh)
{
        struct mountd_export *export;

        export = talloc(mountd, struct mountd_export);
        if (export == NULL) {
                return NULL;
        }
        export->path = talloc_strdup(export, path);
        if (export->path == NULL) {
                talloc_free(export);
                return NULL;
        }
        export->fh.data.data_len = fh_len;
        export->fh.data.data_val = talloc_size(export, fh_len);
        if (export->fh.data.data_val == NULL) {
                talloc_free(export);
                return NULL;
        }
        memcpy(export->fh.data.data_val, fh, fh_len);
        export->next = mountd->exports;
        mountd->exports = export;
        return export;
}

static int mount3_null_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
}

static int mount3_export_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct mountd_state *mountd = (struct mountd_state *)opaque;
        struct mountd_export *e;
        TALLOC_CTX *tmp_ctx;
        MOUNT3EXPORTres *res = NULL, *tmp;
        int rc = -1;

        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
                goto err;
        }
        for(e = mountd->exports; e; e = e->next) {
                tmp = talloc(tmp_ctx, MOUNT3EXPORTres);
                if (tmp == NULL) {
                        goto err;
                }
                tmp->ex_dir = e->path;
                tmp->ex_groups = NULL;
                tmp->ex_next = res;
                res = tmp;
        }
        /* The response is "a pointer to MOUNT3EXPORTres", but in zdr we have to pass
         * a pointer to the response we want to send, hence the &
         */
        rc = rpc_send_reply(rpc, call, &res, (zdrproc_t)zdr_MOUNT3EXPORTres_ptr, 0);
 err:        
        talloc_free(tmp_ctx);
        return rc;
}

struct mountd_state *mountd_init(TALLOC_CTX *ctx, struct tevent_context *tevent)
{
        struct mountd_state *mountd;
        struct libnfs_servers *servers;
        int i;

        static struct service_proc mount3_pt[] = {
                {MOUNT3_NULL, mount3_null_proc,
                 (zdrproc_t)zdr_void, 0, NULL},
#if 0
                {MOUNT3_MNT, mount3_mnt_proc,
                 (zdrproc_t)zdr_MOUNT3_MNTargs, sizeof(MOUNT3_MNTargs), NULL},
                {MOUNT3_DUMP, mount3_dump_proc,
                 (zdrproc_t)zdr_MOUNT3_DUMPargs, sizeof(MOUNT3_DUMPargs), NULL},
                {MOUNT3_UMNT, mount3_umnt_proc,
                 (zdrproc_t)zdr_MOUNT3_UMNTargs, sizeof(MOUNT3_UMNTargs), NULL},
                {MOUNT3_UMNTALL, mount3_umntall_proc,
                 (zdrproc_t)zdr_MOUNT3_UMNTALLargs, sizeof(MOUNT3_UMNTALLargs), NULL},
#endif
                {MOUNT3_EXPORT, mount3_export_proc,
                 (zdrproc_t)zdr_void, 0, NULL},
        };
        static struct libnfs_server_procs server_procs[] = {
                { MOUNT_PROGRAM, MOUNT_V3, mount3_pt, sizeof(mount3_pt) / sizeof(mount3_pt[0]) },
                { 0, 0, 0, 0}
        };

        mountd = talloc(ctx, struct mountd_state);
        if (mountd == NULL) {
                printf("Failed to talloc mountd\n");
                goto err;
        }
        for (i = 0; i < sizeof(mount3_pt) / sizeof(mount3_pt[0]); i++) {
                mount3_pt[i].opaque = mountd;
        }
        mountd->rpc = NULL;
        mountd->tevent = tevent;
        mountd->exports = NULL;

        servers = libnfs_create_server(mountd, tevent, 0, "libnfs mountd",
                                       TRANSPORT_UDP | TRANSPORT_UDP6 |
                                       TRANSPORT_TCP | TRANSPORT_TCP6,
                                       &server_procs[0]);
        if (servers == NULL) {
                printf("Failed to set set up mountd server\n");
                goto err;
        }
        printf("Mountd up and running\n");

        return mountd;
 err:
        talloc_free(mountd);
        return NULL;
}
