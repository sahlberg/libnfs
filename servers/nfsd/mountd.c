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
#include <errno.h>
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

#define LIST_ADD(list, item, nxt)                               \
        do {                                                    \
                (item)->nxt = (*list);                          \
                (*list) = (item);                               \
        } while (0);

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
        LIST_ADD(&mountd->exports, export, next);
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

static int mount3_mnt_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct mountd_state *mountd = (struct mountd_state *)opaque;
        MOUNT3MNTargs *args = call->body.cbody.args;
        MOUNT3MNTres res;
        struct mountd_client *client;
        struct mountd_export *e;
        static char addr[64] = {0};
        struct sockaddr_storage *ss, tcp_ss;
        int rc;
        uint32_t auth_flavors[] = { AUTH_UNIX };
        memset(&res, 0, sizeof(res));

        client = talloc(mountd, struct mountd_client);
        if (client == NULL) {
                res.fhs_status = MNT3ERR_SERVERFAULT;
                goto out;
        }

        for(e = mountd->exports; e; e = e->next) {
                if (!strcmp(e->path, *args)) {
                        break;
                }
        }
        if (e == NULL) {
                res.fhs_status = MNT3ERR_NOENT;
                goto out;
        }

        if (rpc_is_udp_socket(rpc)) {
                ss = (struct sockaddr_storage *)rpc_get_udp_src_sockaddr(rpc);
        } else {
                socklen_t ss_len;

                if (getpeername(rpc_get_fd(rpc), (struct sockaddr *)&tcp_ss, &ss_len)) {
                        res.fhs_status = MNT3ERR_SERVERFAULT;
                        goto out;
                }
                ss = &tcp_ss;
        }
        switch (ss->ss_family) {
        case AF_INET:
                inet_ntop(ss->ss_family, &((struct sockaddr_in *)ss)->sin_addr, addr, sizeof(addr));
                break;
        case AF_INET6:
                inet_ntop(ss->ss_family, &((struct sockaddr_in6 *)ss)->sin6_addr, addr, sizeof(addr));
                break;
        }

        client->client = talloc_strdup(client, addr);
        if (client->client == NULL) {
                res.fhs_status = MNT3ERR_SERVERFAULT;
                goto out;
        }
        client->path = talloc_strdup(client, e->path);
        if (client->path == NULL) {
                res.fhs_status = MNT3ERR_SERVERFAULT;
                goto out;
        }

        LIST_ADD(&mountd->clients, client, next);
        client = NULL;
        res.fhs_status = MNT3_OK;
        res.mountres3_u.mountinfo.fhandle.fhandle3_len = e->fh.data.data_len;
        res.mountres3_u.mountinfo.fhandle.fhandle3_val = e->fh.data.data_val;
        res.mountres3_u.mountinfo.auth_flavors.auth_flavors_len = sizeof(auth_flavors) / sizeof(auth_flavors[0]);
        res.mountres3_u.mountinfo.auth_flavors.auth_flavors_val = &auth_flavors[0];
        
 out:
        rc = rpc_send_reply(rpc, call, &res, (zdrproc_t)zdr_MOUNT3MNTres, 0);
        talloc_free(client);
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
                {MOUNT3_MNT, mount3_mnt_proc,
                 (zdrproc_t)zdr_MOUNT3MNTargs, sizeof(MOUNT3MNTargs), NULL},
#if 0
                {MOUNT3_DUMP, mount3_dump_proc,
                 (zdrproc_t)zdr_MOUNT3DUMPargs, sizeof(MOUNT3DUMPargs), NULL},
                {MOUNT3_UMNT, mount3_umnt_proc,
                 (zdrproc_t)zdr_MOUNT3UMNTargs, sizeof(MOUNT3UMNTargs), NULL},
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
