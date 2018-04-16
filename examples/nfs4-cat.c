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

#include <event2/event.h>

struct event_base *base;

struct client {
        struct rpc_context *rpc;
        struct event *read_event;
        struct event *write_event;
        struct event *listen_event;

        char *server;
        char *path;
        int op_len;
        int is_finished;

	verifier4 verifier;
        char *id;
        char *owner;
        clientid4 clientid;
        verifier4 setclientid_confirm;

        /* filehandle and state for the open file */
        nfs_fh4 fh;
        uint32_t seqid;
        stateid4 stateid;

        /* offset when reading */
        uint64_t offset;

        int callback_fd;
};

struct server {
        struct server *next;
        struct rpc_context *rpc;
        struct event *read_event;
        struct event *write_event;
};
struct server *server_list;

void usage(void)
{
	fprintf(stderr, "Usage: nfs4-cat <file>\n");
	fprintf(stderr, "  <file> is an nfs url.\n");
	exit(0);
}

static void update_events(struct rpc_context *rpc, struct event *read_event,
                          struct event *write_event)
{
        int events = rpc_which_events(rpc);

        if (read_event) {
                if (events & POLLIN) {
                        event_add(read_event, NULL);
                } else {
                        event_del(read_event);
                }
        }
        if (write_event) {
                if (events & POLLOUT) {
                        event_add(write_event, NULL);
                } else {
                        event_del(write_event);
                }
        }
}


static void free_server(struct server *server)
{
        if (server->rpc) {
                rpc_disconnect(server->rpc, NULL);
                rpc_destroy_context(server->rpc);
                server->rpc = NULL;
        }
        if (server->read_event) {
                event_free(server->read_event);
                server->read_event = NULL;
        }
        if (server->write_event) {
                event_free(server->write_event);
                server->write_event = NULL;
        }
        
        free(server);
}

static void server_io(evutil_socket_t fd, short events, void *private_data)
{
        struct server *server = private_data;
        int revents = 0;

        if (events & EV_READ) {
                revents |= POLLIN;
        }
        if (events & EV_WRITE) {
                revents |= POLLOUT;
        }

        if (rpc_service(server->rpc, revents) < 0) {
                fprintf(stderr, "rpc_service() failed for server\n");
                exit(10);
        }

        update_events(server->rpc, server->read_event, server->write_event);
}

static void client_io(evutil_socket_t fd, short events, void *private_data)
{
        struct client *client = private_data;
        struct server *server;
        int revents = 0;

        if (events & EV_READ) {
                revents |= POLLIN;
        }
        if (events & EV_WRITE) {
                revents |= POLLOUT;
        }

        if (rpc_service(client->rpc, revents) < 0) {
                fprintf(stderr, "rpc_service failed\n");
                exit(10);
        }
        update_events(client->rpc, client->read_event, client->write_event);

        if (client->is_finished) {
                /*
                 * Stop listening for new connections.
                 */
                event_free(client->listen_event);
                client->listen_event = NULL;

                /*
                 * Stop listening for events on the client context.
                 */
                event_free(client->read_event);
                client->read_event = NULL;
                event_free(client->write_event);
                client->write_event = NULL;

                /*
                 * Stop listening to server connections.
                 */
                for (server = server_list; server; server = server->next) {
                        if (server->read_event) {
                                event_free(server->read_event);
                                server->read_event = NULL;
                        }
                        if (server->write_event) {
                                event_free(server->write_event);
                                server->write_event = NULL;
                        }
                }
        }
}

/*
 * Helper functions to send client RPC requests.
 */
static void send_setclientid_confirm(struct rpc_context *rpc,
                                     rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        nfs_argop4 op[1];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_SETCLIENTID_CONFIRM;
        op[0].nfs_argop4_u.opsetclientid_confirm.clientid = client->clientid;
        memcpy(op[0].nfs_argop4_u.opsetclientid_confirm.setclientid_confirm, client->setclientid_confirm, NFS4_VERIFIER_SIZE);
               
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 SETCLIENTID_CONFIRM request\n");
                exit(10);
        }
}

static void send_setclientid(struct rpc_context *rpc,
                             rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
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
        memcpy(op[0].nfs_argop4_u.opsetclientid.client.verifier, client->verifier, sizeof(verifier4));
        op[0].nfs_argop4_u.opsetclientid.client.id.id_len = strlen(client->id);
        op[0].nfs_argop4_u.opsetclientid.client.id.id_val = client->id;
                
        op[0].nfs_argop4_u.opsetclientid.callback.cb_program = NFS4_CALLBACK;

        op[0].nfs_argop4_u.opsetclientid.callback.cb_location.r_netid = netid;
        op[0].nfs_argop4_u.opsetclientid.callback.cb_location.r_addr = addr;

        op[0].nfs_argop4_u.opsetclientid.callback_ident = 0x00000001;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 SETCLIENTID request\n");
                exit(10);
        }
}

static void send_getrootfh(struct rpc_context *rpc,
                           rpc_cb cb, void *private_data)
{
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
		exit(10);
	}
}

static void send_open(struct rpc_context *rpc, nfs_fh4 dir, char *path,
                        rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        nfs_argop4 *op;
        int i = 0, idx = 0;
        char *tmp;
        
        printf("OPEN called\n");
        /*
         * Count how many directories we have in the path.
         */
        tmp = path;
        while (tmp = strchr(tmp, '/')) {
                i++;
                tmp++;
        }

        op = malloc(sizeof(nfs_argop4) * (4 + i));
        memset(op, 0, sizeof(nfs_argop4) * (4 + i));

        op[idx].argop = OP_PUTFH;
        op[idx].nfs_argop4_u.opputfh.object = dir;
        idx++;

        while (i-- > 0) {
                tmp = strchr(path, '/');
                *tmp++ = '\0';

                op[idx].argop = OP_LOOKUP;
                op[idx].nfs_argop4_u.oplookup.objname.utf8string_len = strlen(path);
                op[idx].nfs_argop4_u.oplookup.objname.utf8string_val = path;
                idx++;

                path = tmp;
        }

        op[idx].argop = OP_OPEN;
        op[idx].nfs_argop4_u.opopen.seqid = client->seqid;
        op[idx].nfs_argop4_u.opopen.share_access = OPEN4_SHARE_ACCESS_READ;
        op[idx].nfs_argop4_u.opopen.share_deny = OPEN4_SHARE_DENY_NONE;
        op[idx].nfs_argop4_u.opopen.owner.clientid = client->clientid;
        op[idx].nfs_argop4_u.opopen.owner.owner.owner_len = strlen(client->owner);
        op[idx].nfs_argop4_u.opopen.owner.owner.owner_val = client->owner;
        op[idx].nfs_argop4_u.opopen.openhow.opentype = OPEN4_NOCREATE;
        op[idx].nfs_argop4_u.opopen.claim.claim = CLAIM_NULL;
        op[idx].nfs_argop4_u.opopen.claim.open_claim4_u.file.utf8string_len = strlen(path);
        op[idx].nfs_argop4_u.opopen.claim.open_claim4_u.file.utf8string_val = path;
        idx++;

        op[idx].argop = OP_GETFH;
        idx++;
        
        op[idx].argop = OP_ACCESS;
        op[idx].nfs_argop4_u.opaccess.access = ACCESS4_READ;
        
        client->seqid++;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = idx;
        args.argarray.argarray_val = op;

	if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
		fprintf(stderr, "Failed to send nfs4 OPEN request\n");
		exit(10);
        }
}

static void send_open_confirm(struct rpc_context *rpc, nfs_fh4 object, rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        nfs_argop4 op[2];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_PUTFH;
        op[0].nfs_argop4_u.opputfh.object = object;
        op[1].argop = OP_OPEN_CONFIRM;
        op[1].nfs_argop4_u.opopen_confirm.open_stateid.seqid = client->seqid;
        memcpy(op[1].nfs_argop4_u.opopen_confirm.open_stateid.other, client->stateid.other, 12);
        op[1].nfs_argop4_u.opopen_confirm.seqid = client->seqid;

        client->seqid++;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 CLOSE request\n");
                exit(10);
        }
}

static void send_read(struct rpc_context *rpc, nfs_fh4 object,
                      uint64_t offset, uint32_t count,
                      rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        nfs_argop4 op[3];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_PUTFH;
        op[0].nfs_argop4_u.opputfh.object = object;
        op[1].argop = OP_READ;
        op[1].nfs_argop4_u.opread.stateid.seqid = client->seqid;
        memcpy(op[1].nfs_argop4_u.opread.stateid.other, client->stateid.other, 12);
        op[1].nfs_argop4_u.opread.offset = offset;
        op[1].nfs_argop4_u.opread.count = count;
        op[2].argop = OP_GETATTR;

        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 READ request\n");
                exit(10);
        }
}

static void send_close(struct rpc_context *rpc, nfs_fh4 object,
                        rpc_cb cb, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4args args;
        nfs_argop4 op[2];

        memset(op, 0, sizeof(op));
        op[0].argop = OP_PUTFH;
        op[0].nfs_argop4_u.opputfh.object = object;
        op[1].argop = OP_CLOSE;
        op[1].nfs_argop4_u.opclose.seqid = client->seqid;
        op[1].nfs_argop4_u.opclose.open_stateid.seqid = client->seqid;
        memcpy(op[1].nfs_argop4_u.opclose.open_stateid.other, client->stateid.other, 12);

        client->seqid++;
        
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = sizeof(op) / sizeof(nfs_argop4);
        args.argarray.argarray_val = op;

        if (rpc_nfs4_compound_async(rpc, cb, &args, private_data) != 0) {
                fprintf(stderr, "Failed to send nfs4 CLOSE request\n");
                exit(10);
        }
}

        
/*
 * Callbacks for completed requests.
 */
void close_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
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

void read_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to read file on server %s\n",
                        client->server);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to read file on server %s\n",
                        client->server);
		exit(10);
        }

        write(1, res->resarray.resarray_val[1].nfs_resop4_u.opread.READ4res_u.resok4.data.data_val, res->resarray.resarray_val[1].nfs_resop4_u.opread.READ4res_u.resok4.data.data_len);

        /*
         * Are we at end-of-file? If so we can close the file and exit.
         */
        if (res->resarray.resarray_val[1].nfs_resop4_u.opread.READ4res_u.resok4.eof) {
                send_close(rpc, client->fh, close_cb, client);
                return;
        }

        /*
         * We still have more data to read.
         */
        client->offset += res->resarray.resarray_val[1].nfs_resop4_u.opread.READ4res_u.resok4.data.data_len;

        send_read(rpc, client->fh, client->offset, 4096, read_cb, client);
}

void open_confirm_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to confirm open file on server %s\n",
                        client->server);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to confirm open file on server %s\n",
                        client->server);
		exit(10);
        }

        send_read(rpc, client->fh, client->offset, 4096, read_cb, client);
}

void open_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;
        int idx;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to open file on server %s\n",
                        client->server);
		exit(10);
        }

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to open file on server %s\n",
                        client->server);
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
		exit(10);
        }

        /* Store the open handle in the client structure */
        client->fh.nfs_fh4_len = res->resarray.resarray_val[idx+1].nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object.nfs_fh4_len;
        client->fh.nfs_fh4_val = malloc(client->fh.nfs_fh4_len);
        if (client->fh.nfs_fh4_val == NULL) {
                fprintf(stderr, "Failed to allocate data for nfs_fh4\n");
                exit(10);
        }
        memcpy(client->fh.nfs_fh4_val, res->resarray.resarray_val[idx+1].nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object.nfs_fh4_val, client->fh.nfs_fh4_len);

        /* Store stateid for the open handle in the client structure */
        client->stateid.seqid = res->resarray.resarray_val[idx].nfs_resop4_u.opopen.OPEN4res_u.resok4.stateid.seqid;
        memcpy(client->stateid.other, res->resarray.resarray_val[idx].nfs_resop4_u.opopen.OPEN4res_u.resok4.stateid.other, 12);

        /* Check if server wants us to confirm the open */
        if (res->resarray.resarray_val[idx].nfs_resop4_u.opopen.OPEN4res_u.resok4.rflags & OPEN4_RESULT_CONFIRM) {
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

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to get root filehandle of server %s\n",
                        client->server);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to get root filehandle of server %s\n",
                        client->server);
		exit(10);
        }

        send_open(rpc, res->resarray.resarray_val[1].nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object, client->path, open_cb, client);
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
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to set client id of server %s\n",
                        client->server);
		exit(10);
        }

        send_getrootfh(rpc, getrootfh_cb, client);
}

void setclientid_cb(struct rpc_context *rpc, int status, void *data,
                void *private_data)
{
	struct client *client = private_data;
        COMPOUND4res *res = data;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to set client id on server %s\n",
                        client->server);
		exit(10);
	}

        if (res->status != NFS4_OK) {
		fprintf(stderr, "Failed to set client id on server %s\n",
                        client->server);
		exit(10);
        }

        client->clientid = res->resarray.resarray_val[0].nfs_resop4_u.opsetclientid.SETCLIENTID4res_u.resok4.clientid;
        memcpy(client->setclientid_confirm, res->resarray.resarray_val[0].nfs_resop4_u.opsetclientid.SETCLIENTID4res_u.resok4.setclientid_confirm, NFS4_VERIFIER_SIZE);

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

/*
 * This callback is invoked when others (the nfsv4 server) initiates a
 * NFSv4 CALLBACK sessions to us.
 * We accept() the connection and create a local rpc server context
 * for the callback protocol.
 */
static void client_accept(evutil_socket_t s, short events, void *private_data)
{
	struct client *client = private_data;
        struct server *server;
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        int fd;
        
        server = malloc(sizeof(struct server));
        if (server == NULL) {
                fprintf(stderr, "failed to malloc server structure\n");
                exit(10);
        }
        memset(server, 0, sizeof(*server));
        server->next = server_list;
        server_list = server;

        if ((fd = accept(s, (struct sockaddr *)&ss, &len)) < 0) {
                free_server(server);
                fprintf(stderr, "accept failed\n");
                exit(10);
        }
        evutil_make_socket_nonblocking(fd);

        server->rpc = rpc_init_server_context(fd);
        if (server->rpc == NULL) {
                free_server(server);
                fprintf(stderr, "Failed to create server rpc context\n");
                exit(10);
        }

        rpc_register_service(server->rpc, NFS4_CALLBACK, NFS_CB,
                             pt, sizeof(pt) / sizeof(pt[0]));

        server->read_event = event_new(base, fd, EV_READ|EV_PERSIST,
                                       server_io, server);
        server->write_event = event_new(base, fd, EV_WRITE|EV_PERSIST,
                                        server_io, server);
        update_events(server->rpc, server->read_event, server->write_event);
}

/*
 * This callback is invoked when our async connect() to the server has
 * completed. At this point we know which IP address was used locally for
 * the connection and can bind our nfsv4 callback server instance to it.
 */
void connect_cb(struct rpc_context *rpc, int status, void *data _U_,
                void *private_data)
{
	struct client *client = private_data;
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        struct sockaddr_in *in;
        struct sockaddr_in6 *in6;

	if (status != RPC_STATUS_SUCCESS) {
		fprintf(stderr, "connection to NFSv4 server %s failed\n",
                        client->server);
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
		exit(10);
        }

        client->callback_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (client->callback_fd == -1) {
                fprintf(stderr, "Failed to create callback socket\n");
                exit(10);
        }
        evutil_make_socket_nonblocking(client->callback_fd);

        if (bind(client->callback_fd, (struct sockaddr *)&ss, sizeof(ss)) < 0) {
                fprintf(stderr, "Failed to bind callback socket\n");
                exit(10);
        }

        if (listen(client->callback_fd, 16) < 0) {
                fprintf(stderr, "failed to listen to callback socket\n");
                exit(10);
        }

        client->listen_event = event_new(base,
                                         client->callback_fd,
                                         EV_READ|EV_PERSIST,
                                         client_accept, private_data);
        event_add(client->listen_event, NULL);


        /*
         * Now that we are finished setting up the callback server port
         * we can proceed and negotiate the nfsv4 client id.
         */
        send_setclientid(rpc, setclientid_cb, client);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs;
        struct nfs_url *url;
	struct client client;
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

	if (argc < 2) {
		usage();
	}

        base = event_base_new();
        if (base == NULL) {
		fprintf(stderr, "Failed create event context\n");
		exit(10);
	}

	nfs = nfs_init_context();
	if (nfs == NULL) {
		fprintf(stderr, "failed to init context\n");
		exit(10);
	}
        url = nfs_parse_url_dir(nfs, argv[1]);
        if (url == NULL) {
		fprintf(stderr, "failed to parse url\n");
		exit(10);
	}

        memset(&client, 0, sizeof(client));
        client.rpc = nfs_get_rpc_context(nfs);
        client.is_finished = 0;
        client.server = url->server;
        client.path = &url->path[1];  // skip leading '/'
        srandom(time(NULL));
        for (i = 0; i < NFS4_VERIFIER_SIZE; i++) {
                client.verifier[i] = random() & 0xff;
        }
        asprintf(&client.id, "Libnfs %s tcp pid:%d", argv[1], getpid());
        asprintf(&client.owner, "open id:libnfs pid:%d", getpid());
        client.callback_fd = -1;

	if (rpc_connect_program_async(client.rpc, url->server,
                                      NFS4_PROGRAM, NFS_V4,
                                      connect_cb, &client) != 0) {
		fprintf(stderr, "Failed to start connection\n");
		exit(10);
	}

        /*
         * Set up the events we need for the outgoing client RPC channel.
         */
        fd = rpc_get_fd(client.rpc);
        client.read_event = event_new(base, fd, EV_READ|EV_PERSIST,
                                      client_io, &client);
        client.write_event = event_new(base, fd, EV_WRITE|EV_PERSIST,
                                       client_io, &client);
        update_events(client.rpc, client.read_event, client.write_event);

        /*
         * Main event loop.
         */
        event_base_dispatch(base);

        /*
         * Finished cleanly, lets deallocate all resrouces we were using.
         */
        /*
         * Close the listening socket.
         */
        close(client.callback_fd);

        /*
         * Destroy the client context.
         */
        free(client.id);
        free(client.owner);
        free(client.fh.nfs_fh4_val);

        /*
         * Destroy all server contexts
         */
        while (server_list) {
                struct server *server = server_list;

                server_list = server->next;
                free_server(server);
        }

        nfs_destroy_url(url);
        /*
         * This will implicitly close the rpc context and also destroy it.
         */
	nfs_destroy_context(nfs);

        event_base_free(base);

	return 0;
}
