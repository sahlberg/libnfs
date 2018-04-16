/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

/* THIS IS NOT A PROPER NFS4 CLIENT!
 * This software is only meant to illustrate how to plug libnfs into
 * an eventsystem like libevent and then use the raw rpc api
 * connect to an nfsv4 server and read a file.
 * If any kind of error occurs it will immediately terminate by calling
 * exit() without even attempting to cleanup.
 * If the access to the server is successful it should however run valgrind
 * clean.
 *
 * NFSv4 access is done through the raw async interface and is cumbersome
 * to use for NFSv4 due to the richness of the protocol.
 * A future aim will be to build better helper functions to make ease
 * of use better.
 */

/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2015
   
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

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif


#ifdef WIN32
#include <win32/win32_compat.h>
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#else
#include <sys/stat.h>
#include <string.h>
#endif
 
#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-nfs4.h"

#include <tevent.h>
#include <talloc.h>

struct tevent_context *ev;

struct client {
	struct nfs_context *nfs;
        struct rpc_context *rpc;
        char *server;
        char *path;

        struct tevent_fd *fde;
        int callback_fd;

        /* For SETCLIENTID */
        verifier4 verifier;
        char *id;
        clientid4 clientid;
        verifier4 setclientid_confirm;
        
        /* For OPEN */
        char *owner;
        int op_len;

        /* filehandle and state for the open file */
        nfs_fh4 fh;
        uint32_t seqid;
        stateid4 stateid;

        /* offset when reading */
        uint64_t offset;
        
        int is_finished;
};

static void set_nonblocking(int fd)
{
	int v = 0;
#if defined(WIN32)
	long nonblocking=1;
	v = ioctl(fd, FIONBIO, &nonblocking);
#else
	v = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, v | O_NONBLOCK);
#endif
}

static int client_destructor(struct client *c)
{
        if (c->nfs) {
                nfs_destroy_context(c->nfs);
        }
        if (c->callback_fd != -1) {
                close(c->callback_fd);
        }
};

void usage(void)
{
	fprintf(stderr, "Usage: nfs4-cat-talloc <file>\n");
	fprintf(stderr, "  <file> is an nfs url.\n");
	exit(0);
}

static void update_events(struct rpc_context *rpc,
                          struct tevent_fd *fde)
{
        int events = rpc_which_events(rpc);
        int flags = 0;
        
        if (events & POLLIN) {
                flags |= TEVENT_FD_READ;
        }

        if (events & POLLOUT) {
                flags |= TEVENT_FD_WRITE;
        }

        tevent_fd_set_flags(fde, flags);
}

struct server {
        struct rpc_context *rpc;
        struct tevent_fd *fde;
};


/*
 * Helper functions to send client RPC requests.
 */
static void send_setclientid(struct rpc_context *rpc,
                             rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        SETCLIENTID4args *sc4args;
        nfs_argop4 op[1];
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        struct sockaddr_in *in;
        struct sockaddr_in6 *in6;
        char *netid;
        char str[240], addr[256];
        unsigned short port;

        if (getsockname(client->callback_fd, (struct sockaddr *)&ss, &len) < 0) {
                fprintf(stderr, "getsockaddr failed\n");
                talloc_free(client);
                exit(10);
        }
        
        switch (ss.ss_family) {
        case AF_INET:
                netid = "tcp";
                in = (struct sockaddr_in *)&ss;
                inet_ntop(AF_INET, &in->sin_addr, str, sizeof(str));
                port = ntohs(in->sin_port);
                break;
        case AF_INET6:
                netid = "tcp6";
                in6 = (struct sockaddr_in6 *)&ss;
                inet_ntop(AF_INET6, &in6->sin6_addr, str, sizeof(str));
                port = ntohs(in6->sin6_port);
                break;
        }
        sprintf(addr, "%s.%d.%d", str, port >> 8, port & 0xff);
        
        memset(op, 0, sizeof(op));
        
        op[0].argop = OP_SETCLIENTID;
        sc4args = &op[0].nfs_argop4_u.opsetclientid;
        memcpy(sc4args->client.verifier, client->verifier, sizeof(verifier4));
        sc4args->client.id.id_len = strlen(client->id);
        sc4args->client.id.id_val = client->id;
        sc4args->callback.cb_program = NFS4_CALLBACK;
        sc4args->callback.cb_location.r_netid = netid;
        sc4args->callback.cb_location.r_addr = addr;
        sc4args->callback_ident = 0x00000001;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 SETCLIENTID request\n");
                talloc_free(client);
                exit(10);
        }
}

static void send_setclientid_confirm(struct rpc_context *rpc,
                                     rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        SETCLIENTID_CONFIRM4args *scc4args;
        nfs_argop4 op[1];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_SETCLIENTID_CONFIRM;
        scc4args = &op[0].nfs_argop4_u.opsetclientid_confirm;
        scc4args->clientid = client->clientid;
        memcpy(scc4args->setclientid_confirm, client->setclientid_confirm,
               NFS4_VERIFIER_SIZE);
               
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 SETCLIENTID_CONFIRM request\n");
                talloc_free(client);
                exit(10);
        }
}

static void send_getrootfh(struct rpc_context *rpc,
                           rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        nfs_argop4 op[2];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_PUTROOTFH;
        op[1].argop = OP_GETFH;

        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;
	if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
		fprintf(stderr, "Failed to send nfs4 GETROOTFH request\n");
                talloc_free(client);
		exit(10);
	}
}

static void send_open(struct rpc_context *rpc, nfs_fh4 dir, char *path,
                        rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        ACCESS4args *a4args;
        LOOKUP4args *l4args;
        OPEN4args *o4args;
        nfs_argop4 *op;
        int i = 0, idx = 0;
        char *tmp;
        
        /*
         * Count how many directories we have in the path.
         */
        tmp = path;
        while (tmp = strchr(tmp, '/')) {
                i++;
                tmp++;
        }

        op = talloc_zero_array(client, nfs_argop4, 4 + i);

        op[idx].argop = OP_PUTFH;
        op[idx].nfs_argop4_u.opputfh.object = dir;
        idx++;

        while (i-- > 0) {
                tmp = strchr(path, '/');
                *tmp++ = '\0';

                op[idx].argop = OP_LOOKUP;
                l4args = &op[idx].nfs_argop4_u.oplookup;
                l4args->objname.utf8string_len = strlen(path);
                l4args->objname.utf8string_val = path;
                idx++;

                path = tmp;
        }

        op[idx].argop = OP_OPEN;
        o4args = &op[idx].nfs_argop4_u.opopen;
        o4args->seqid = client->seqid;
        o4args->share_access = OPEN4_SHARE_ACCESS_READ;
        o4args->share_deny = OPEN4_SHARE_DENY_NONE;
        o4args->owner.clientid = client->clientid;
        o4args->owner.owner.owner_len = strlen(client->owner);
        o4args->owner.owner.owner_val = client->owner;
        o4args->openhow.opentype = OPEN4_NOCREATE;
        o4args->claim.claim = CLAIM_NULL;
        o4args->claim.open_claim4_u.file.utf8string_len = strlen(path);
        o4args->claim.open_claim4_u.file.utf8string_val = path;
        idx++;

        op[idx].argop = OP_GETFH;
        idx++;
        
        op[idx].argop = OP_ACCESS;
        a4args = &op[idx].nfs_argop4_u.opaccess;
        a4args->access = ACCESS4_READ;
        
        client->seqid++;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = idx;
        args.argarray.argarray_val = op;

	if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
		fprintf(stderr, "Failed to send nfs4 OPEN request\n");
                talloc_free(client);
		exit(10);
        }
        talloc_free(op);
}

static void send_open_confirm(struct rpc_context *rpc, nfs_fh4 object, rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        OPEN_CONFIRM4args *oc4args;
        PUTFH4args *pfh4args;
        nfs_argop4 op[2];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_PUTFH;
        pfh4args = &op[0].nfs_argop4_u.opputfh;
        pfh4args->object = object;

        op[1].argop = OP_OPEN_CONFIRM;
        oc4args = &op[1].nfs_argop4_u.opopen_confirm;
        oc4args->open_stateid.seqid = client->seqid;
        memcpy(oc4args->open_stateid.other,
               client->stateid.other, 12);
        oc4args->seqid = client->seqid;

        client->seqid++;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 CLOSE request\n");
                talloc_free(client);
                exit(10);
        }
}

static void send_read(struct rpc_context *rpc, nfs_fh4 object,
                      uint64_t offset, uint32_t count,
                      rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        PUTFH4args *pfh4args;
        READ4args *r4args;
        nfs_argop4 op[3];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_PUTFH;
        pfh4args = &op[0].nfs_argop4_u.opputfh;
        pfh4args->object = object;

        op[1].argop = OP_READ;
        r4args = &op[1].nfs_argop4_u.opread;
        r4args->stateid.seqid = client->seqid;
        memcpy(r4args->stateid.other, client->stateid.other, 12);
        r4args->offset = offset;
        r4args->count = count;

        op[2].argop = OP_GETATTR;

        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 READ request\n");
                talloc_free(client);
                exit(10);
        }
}

static void send_close(struct rpc_context *rpc, nfs_fh4 object,
                        rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        CLOSE4args *c4args;
        PUTFH4args *pfh4args;
        nfs_argop4 op[2];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_PUTFH;
        pfh4args = &op[0].nfs_argop4_u.opputfh;
        pfh4args->object = object;
        
        op[1].argop = OP_CLOSE;
        c4args = &op[1].nfs_argop4_u.opclose;
        c4args->seqid = client->seqid;
        c4args->open_stateid.seqid = client->seqid;
        memcpy(c4args->open_stateid.other, client->stateid.other, 12);

        client->seqid++;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 CLOSE request\n");
                talloc_free(client);
                exit(10);
        }
}

        
/*
 * Callbacks for completed requests.
 */
void close_cb(struct rpc_context *rpc, int status, void *data,
              void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;

        /*
         * FINISHED
         */
        /*
         * Note that we can not start tearing down and destroying the contexts
         * right here as we are still in a callback from ... rpc_service().
         * Instead flag that we should abort and start doing the teardown
         * in client_io once we return from libnfs.
         */
        client->is_finished = 1;
}

void read_cb(struct rpc_context *rpc, int status, void *data,
             void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;
        struct READ4res *r4res;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to read file on server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to read file on server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
        }

        r4res = &res->resarray.resarray_val[1].nfs_resop4_u.opread;
        write(1,
              r4res->READ4res_u.resok4.data.data_val,
              r4res->READ4res_u.resok4.data.data_len);

        /*
         * Are we at end-of-file? If so we can close the file and exit.
         */
        if (r4res->READ4res_u.resok4.eof) {
                send_close(rpc, client->fh, close_cb, client);
                return;
        }

        /*
         * We still have more data to read.
         */
        client->offset += r4res->READ4res_u.resok4.data.data_len;

        send_read(rpc, client->fh, client->offset, 4096, read_cb, client);
}

void open_confirm_cb(struct rpc_context *rpc, int status, void *data,
                     void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to confirm open file on server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to confirm open file on server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
        }

        send_read(rpc, client->fh, client->offset, 4096, read_cb, client);
}

void open_cb(struct rpc_context *rpc, int status, void *data,
             void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;
        GETFH4res *gfh4res;
        OPEN4res *o4res;
        int idx;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to open file on server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
        }

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to open file on server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
        }

        /* Find the index for the OPEN opcode */
        for (idx = 1; idx < res->resarray.resarray_len - 1; idx++) {
                if ((res->resarray.resarray_val[idx].resop == OP_OPEN) &&
                    (res->resarray.resarray_val[idx + 1].resop == OP_GETFH)) {
                        break;
                }
        }
        if (idx >= res->resarray.resarray_len - 1) {
		fprintf(stderr, "No OP_OPEN in server response\n");
                talloc_free(client);
		exit(10);
        }

        /* Store the open handle in the client structure */
        gfh4res = &res->resarray.resarray_val[idx+1].nfs_resop4_u.opgetfh;
        client->fh.nfs_fh4_len = gfh4res->GETFH4res_u.resok4.object.nfs_fh4_len;
        client->fh.nfs_fh4_val = talloc_size(client, client->fh.nfs_fh4_len);
        if (client->fh.nfs_fh4_val == NULL) {
                fprintf(stderr, "Failed to allocate data for nfs_fh4\n");
                talloc_free(client);
                exit(10);
        }
        memcpy(client->fh.nfs_fh4_val,
               gfh4res->GETFH4res_u.resok4.object.nfs_fh4_val,
               client->fh.nfs_fh4_len);

        /* Store stateid for the open handle in the client structure */
        o4res = &res->resarray.resarray_val[idx].nfs_resop4_u.opopen;
        client->stateid.seqid = o4res->OPEN4res_u.resok4.stateid.seqid;
        memcpy(client->stateid.other,
               o4res->OPEN4res_u.resok4.stateid.other, 12);

        /* Check if server wants us to confirm the open */
        if (o4res->OPEN4res_u.resok4.rflags & OPEN4_RESULT_CONFIRM) {
                send_open_confirm(rpc, client->fh, open_confirm_cb, client);
                return;
        }
        
        send_read(rpc, client->fh, client->offset, 4096, read_cb, client);
}

void getrootfh_cb(struct rpc_context *rpc, int status, void *data,
                  void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;
        GETFH4res *gfh4res;
        
	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to get root filehandle of server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to get root filehandle of server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
        }

        gfh4res = &res->resarray.resarray_val[1].nfs_resop4_u.opgetfh;
        send_open(rpc, gfh4res->GETFH4res_u.resok4.object,
                  client->path, open_cb, client);
}

void setclientid_confirm_cb(struct rpc_context *rpc, int status, void *data,
                            void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;
        char *path;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to set client id of server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to set client id of server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
        }

        send_getrootfh(rpc, getrootfh_cb, client);
}

void setclientid_cb(struct rpc_context *rpc, int status, void *data,
                void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;
        SETCLIENTID4res *sc4res;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to set client id on server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to set client id on server %s\n",
                        client->server);
                talloc_free(client);
		exit(10);
        }

        sc4res = &res->resarray.resarray_val[0].nfs_resop4_u.opsetclientid;
        client->clientid = sc4res->SETCLIENTID4res_u.resok4.clientid;
        memcpy(client->setclientid_confirm,
               sc4res->SETCLIENTID4res_u.resok4.setclientid_confirm,
               NFS4_VERIFIER_SIZE);

        send_setclientid_confirm(rpc, setclientid_confirm_cb, client);
}

/*
 * NULL procedure for the callback protocol.
 */
static int cb_null_proc(struct rpc_context *rpc, struct rpc_msg *call)
{
        rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);

        return 0;
}

/*
 * CB_COMPOUND procedure for the callback protocol.
 * This is where the server will inform us about lease breaks and similar.
 */
static int cb_compound_proc(struct rpc_context *rpc, struct rpc_msg *call)
{
        CB_COMPOUND4args *args = call->body.cbody.args;

        fprintf(stderr, "cb_compund_cb. Do something here.\n");
        return 0;
}

struct service_proc pt[] = {
        {CB_NULL, cb_null_proc,
            (zdrproc_t)zdr_void, 0},
        {CB_COMPOUND, cb_compound_proc,
         (zdrproc_t)zdr_CB_COMPOUND4args, sizeof(CB_COMPOUND4args)},
};

static void server_io(struct tevent_context *ev, struct tevent_fd *fde,
                      uint16_t events, void *private_data)
{
        struct server *server = private_data;
        int revents = 0;

        if (events & TEVENT_FD_READ) {
                revents |= POLLIN;
        }
        if (events & TEVENT_FD_WRITE) {
                revents |= POLLOUT;
        }

        if (rpc_service(server->rpc, revents) < 0) {
                talloc_free(server);
                return;
        }

        update_events(server->rpc, server->fde);
}

static int server_destructor(struct server *s)
{
        if (s->rpc) {
                rpc_destroy_context(s->rpc);
        }
}

/*
 * This callback is invoked when others (the nfsv4 server) initiates a
 * NFSv4 CALLBACK sessions to us.
 * We accept() the connection and create a local rpc server context
 * for the callback protocol.
 */
static void client_accept(struct tevent_context *ev, struct tevent_fd *fde,
                          uint16_t events, void *private_data)
{
	struct client *client = private_data;
        struct server *server;
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        int fd;

        server = talloc_zero(client, struct server);
        talloc_set_destructor(server, server_destructor);

        if ((fd = accept(client->callback_fd, (struct sockaddr *)&ss, &len)) < 0) {
                fprintf(stderr, "accept failed\n");
                talloc_free(server);
                return;
        }
        set_nonblocking(fd);

        server->rpc = rpc_init_server_context(fd);
        if (server->rpc == NULL) {
                fprintf(stderr, "Failed to create server rpc context\n");
                talloc_free(server);
                return;
        }

        rpc_register_service(server->rpc, NFS4_CALLBACK, NFS_CB,
                             pt, sizeof(pt) / sizeof(pt[0]));

        server->fde = tevent_add_fd(ev, server, fd, TEVENT_FD_READ,
                                    server_io, server);
        tevent_fd_set_auto_close(server->fde);
        update_events(server->rpc, server->fde);
}

/*
 * This callback is invoked when our async connect() to the server has
 * completed. At this point we know which IP address was used locally for
 * the connection and can bind our nfsv4 callback server instance to it.
 */
void connect_cb(struct rpc_context *rpc, int status, void *data,
                void *private_data)
{
	struct client *client = private_data;
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        struct sockaddr_in *in;
        struct sockaddr_in6 *in6;
        struct tevent_fd *fde;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "connection to NFSv4 server %s failed\n",
                        client->server);
                talloc_free(client);
		exit(10);
	}

        /*
         * NFSv4 CALLBACK
         * Now that we have a client connection we can register a callback
         * server port on the same IP address as was used to the outgoing
         * client connection. That way we know that the address used by the
         * server is routable, and uses the same version of ip, that the client
         * supports and can route to.
         */
        if (getsockname(rpc_get_fd(rpc), (struct sockaddr *)&ss, &len) < 0) {
                fprintf(stderr, "getsockaddr failed\n");
                talloc_free(client);
                exit(10);
        }
        switch (ss.ss_family) {
        case AF_INET:
                in = (struct sockaddr_in *)&ss;
                in->sin_port=0;
                break;
        case AF_INET6:
                in6 = (struct sockaddr_in6 *)&ss;
                in6->sin6_port=0;
                break;
        default:
		fprintf(stderr, "Can not handle AF_FAMILY:%d", ss.ss_family);
                talloc_free(client);
		exit(10);
        }

        client->callback_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (client->callback_fd == -1) {
                fprintf(stderr, "Failed to create callback socket\n");
                talloc_free(client);
                exit(10);
        }
        set_nonblocking(client->callback_fd);

        if (bind(client->callback_fd, (struct sockaddr *)&ss, sizeof(ss)) < 0) {
                fprintf(stderr, "Failed to bind callback socket\n");
                talloc_free(client);
                exit(10);
        }

        if (listen(client->callback_fd, 16) < 0) {
                fprintf(stderr, "failed to listen to callback socket\n");
                talloc_free(client);
                exit(10);
        }

        fde = tevent_add_fd(ev, client, client->callback_fd, TEVENT_FD_READ,
                            client_accept, private_data);
        tevent_fd_set_auto_close(fde);
        
        update_events(client->rpc, client->fde);
        
        /*
         * Now that we are finished setting up the callback server port
         * we can proceed and negotiate the nfsv4 client id.
         */
        send_setclientid(rpc, setclientid_cb, client);
}


static void client_io(struct tevent_context *ev, struct tevent_fd *fde,
                      uint16_t events, void *private_data)
{
        struct client *client = private_data;
        int revents = 0;

        if (events & TEVENT_FD_READ) {
                revents |= POLLIN;
        }
        if (events & TEVENT_FD_WRITE) {
                revents |= POLLOUT;
        }

        if (rpc_service(client->rpc, revents) < 0) {
                fprintf(stderr, "rpc_service failed\n");
                talloc_free(client);
                exit(10);
        }
        update_events(client->rpc, client->fde);
        if (client->is_finished) {
                talloc_free(client);
        }
}

int main(int argc, char *argv[])
{
        TALLOC_CTX *ctx = talloc_new(NULL);
	struct client *client;
        struct nfs_url *url;
        int i, fd;

#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		fprintf(stderr, "Failed to start Winsock2\n");
		exit(10);
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

        srandom(time(NULL) ^ getpid());

	if (argc < 2) {
		usage();
	}

	ev = tevent_context_init(ctx);
        
        client = talloc_zero(ctx, struct client);
        talloc_set_destructor(client, client_destructor);
        client->callback_fd = -1;

	client->nfs = nfs_init_context();
	if (client->nfs == NULL) {
		fprintf(stderr, "failed to init nfs context\n");
                talloc_free(ctx);
		exit(10);
	}
        
        url = nfs_parse_url_dir(client->nfs, argv[1]);
        if (url == NULL) {
		fprintf(stderr, "failed to parse url\n");
                talloc_free(ctx);
		exit(10);
	}
        client->server = talloc_strdup(client, url->server);
        client->path = talloc_strdup(client, &url->path[1]); // skip leading '/'
        nfs_destroy_url(url);

        for (i = 0; i < NFS4_VERIFIER_SIZE; i++) {
                client->verifier[i] = random() & 0xff;
        }
        client->id = talloc_asprintf(client, "Libnfs %s tcp pid:%d",
                                    argv[1], getpid());
        client->owner = talloc_asprintf(client, "open id:libnfs pid:%d",
                                        getpid());
        /*
         * From here on we will mainly use the rpc context directly
         * and not the nfs context so lets store the rpc context here
         * for easy access.
         */
        client->rpc = nfs_get_rpc_context(client->nfs);

	if (rpc_connect_program_async(client->rpc, client->server,
                                      NFS4_PROGRAM, NFS_V4,
                                      connect_cb, client) != 0) {
		fprintf(stderr, "Failed to start connection: %s\n",
                        rpc_get_error(client->rpc));
                talloc_free(ctx);
		exit(10);
	}

        /*
         * Set up the events we need for the outgoing client RPC channel.
         */
        fd = rpc_get_fd(client->rpc);
        client->fde = tevent_add_fd(ev, client, fd, TEVENT_FD_READ,
                                    client_io, (void *)client);
        update_events(client->rpc, client->fde);

        tevent_loop_wait(ev);

        talloc_free(ctx);
        return 0;
}
