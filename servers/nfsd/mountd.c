/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
  Copyright 2025 Ronnie Sahlberg

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the “Software”),
  to deal in the Software without restriction, including without
  limitation the rights to use, copy, modify, merge, publish, distribute,
  sublicense, and/or sell copies of the Software, and to permit persons
  to whom the Software is furnished to do so, subject to the following
  conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE


#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
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

#define LIST_REMOVE(list, item, nxt)                            \
	if ((*list) == (item)) { 				\
	   (*list) = (item)->nxt;				\
	} else {						\
	   void *head = (*list);				\
	   while ((*list)->nxt && (*list)->nxt != (item))       \
	     (*list) = (*list)->nxt;				\
	   if ((*list)->nxt != NULL) {		    	    	\
	      (*list)->nxt = (*list)->nxt->nxt;		        \
	   }  		      					\
	   (*list) = head;					\
	}

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

static char *client_address(struct rpc_context *rpc)
{
        struct sockaddr_storage *ss, tcp_ss;
        static char addr[64] = {0};

        if (rpc_is_udp_socket(rpc)) {
                ss = (struct sockaddr_storage *)rpc_get_udp_src_sockaddr(rpc);
        } else {
                socklen_t ss_len;

                if (getpeername(rpc_get_fd(rpc), (struct sockaddr *)&tcp_ss, &ss_len)) {
                        return NULL;
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

        return addr;
}

static int mount3_mnt_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct mountd_state *mountd = (struct mountd_state *)opaque;
        MOUNT3MNTargs *args = call->body.cbody.args;
        MOUNT3MNTres res;
        struct mountd_client *client;
        struct mountd_export *e;
        int rc;
        uint32_t auth_flavors[] = { AUTH_UNIX };
        memset(&res, 0, sizeof(res));
        char *addr;

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

        addr = client_address(rpc);
        if (addr == NULL) {
                res.fhs_status = MNT3ERR_SERVERFAULT;
                goto out;
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

        pthread_mutex_lock(&mountd->clients_mutex);
        LIST_ADD(&mountd->clients, client, next);
        pthread_mutex_unlock(&mountd->clients_mutex);
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


static int mount3_umnt_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct mountd_state *mountd = (struct mountd_state *)opaque;
        MOUNT3UMNTargs *args = call->body.cbody.args;
        struct mountd_client *c;
        char *addr;
        int rc;
        
        addr = client_address(rpc);
        if (addr == NULL) {
                return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
        }
        
        pthread_mutex_lock(&mountd->clients_mutex);
        for (c = mountd->clients; c; c = c->next) {
                if (!strcmp(c->client, addr) && !strcmp(c->path, *args)) {
                        LIST_REMOVE(&mountd->clients, c, next);
                        pthread_mutex_unlock(&mountd->clients_mutex);
                        talloc_free(c);
                        return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
                }
        }
        pthread_mutex_unlock(&mountd->clients_mutex);
        return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
}

static int mount3_umntall_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct mountd_state *mountd = (struct mountd_state *)opaque;
        struct mountd_client *c, *nl = NULL;
        char *addr;
        int rc;
        
        addr = client_address(rpc);
        if (addr == NULL) {
                return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
        }
        
        pthread_mutex_lock(&mountd->clients_mutex);
        for (c = mountd->clients; c; c = c->next) {
                LIST_REMOVE(&mountd->clients, c, next);
                if (!strcmp(c->client, addr)) {
                        talloc_free(c);
                        continue;
                }
                LIST_ADD(&nl, c, next);
        }
        pthread_mutex_unlock(&mountd->clients_mutex);
        mountd->clients = nl;
        return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
}


static int mount3_dump_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct mountd_state *mountd = (struct mountd_state *)opaque;
        TALLOC_CTX *tmp_ctx;
        MOUNT3DUMPres *res = NULL, *tmp;
        struct mountd_client *c;
        int rc;

        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
                goto err;
        }

        pthread_mutex_lock(&mountd->clients_mutex);
        for (c = mountd->clients; c; c = c->next) {
                tmp = talloc(tmp_ctx, MOUNT3DUMPres);
                if (tmp == NULL) {
                        pthread_mutex_unlock(&mountd->clients_mutex);
                        goto err;
                }
                tmp->ml_hostname = c->client;
                tmp->ml_directory = c->path;
                tmp->ml_next = res;
                res = tmp;
        }
        pthread_mutex_unlock(&mountd->clients_mutex);
        rc = rpc_send_reply(rpc, call, &res, (zdrproc_t)zdr_MOUNT3DUMPres_ptr, 0);
 err:        
        talloc_free(tmp_ctx);
        return rc;
}

static int mountd_destructor(struct mountd_state *mountd)
{
        pthread_mutex_destroy(&mountd->clients_mutex);
        return 0;
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
                {MOUNT3_DUMP, mount3_dump_proc,
                 (zdrproc_t)zdr_void, 0, NULL},
                {MOUNT3_UMNT, mount3_umnt_proc,
                 (zdrproc_t)zdr_MOUNT3UMNTargs, sizeof(MOUNT3UMNTargs), NULL},
                {MOUNT3_UMNTALL, mount3_umntall_proc,
                 (zdrproc_t)zdr_void, 0, NULL},
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
        talloc_set_destructor(mountd, mountd_destructor);
        for (i = 0; i < sizeof(mount3_pt) / sizeof(mount3_pt[0]); i++) {
                mount3_pt[i].opaque = mountd;
        }
        mountd->tevent = tevent;
        mountd->exports = NULL;
        mountd->clients = NULL;
        pthread_mutex_init(&mountd->clients_mutex, NULL);

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
