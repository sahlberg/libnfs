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
 

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <talloc.h>
#include <tevent.h>
#include <unistd.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "../portmap/libnfs-raw-portmap.h"
#include "libnfs-server.h"

struct libnfs_server {
        struct rpc_context *rpc;
        struct tevent_fd *tfd;
};

struct libnfs_servers {
        struct tevent_context *tevent;
        struct libnfs_server_procs *server_procs;
        int listen_fd;
};

static int server_destructor(struct libnfs_server *server)
{
        if (server->rpc) {
                rpc_disconnect(server->rpc, NULL);
                rpc_destroy_context(server->rpc);
        }

        return 0;
}

static void update_events(struct libnfs_server *server);

/*
 * This callback is invoked from the event system when an event we are waiting
 * for has become active.
 */
static void libnfs_server_io(struct tevent_context *ev, struct tevent_fd *fde, uint16_t flags, void *private_data)
{
        struct libnfs_server *server = private_data;
        int revents = 0;

        /*
         * Translate the tevent read/write flags to the corresponding
         * flags that libnfs uses.
         */
        if (flags & TEVENT_FD_READ) {
                revents |= POLLIN;
        }
        if (flags & TEVENT_FD_WRITE) {
                revents |= POLLOUT;
        }

        /*
         * Let libnfs process the event.
         */
        if (rpc_service(server->rpc, revents) < 0) {
                talloc_free(server);
                return;
        }

        /*
         * Update which events we are interested in. It might have changed
         * for example if we no longer have any data pending to send
         * we no longer need to wait for the socket to become writeable.
         */
        update_events(server);
}


/*
 * Based on the state of libnfs and its context, update libevent
 * accordingly regarding which events we are interested in.
 */
static void update_events(struct libnfs_server *server)
{
        static int last_events = 0;
        int events = rpc_which_events(server->rpc);
        int flags = 0;
        struct libnfs_servers *servers;
        
        if (events == last_events) {
                return;
        }

        servers = talloc_find_parent_bytype(server, struct libnfs_servers);
        /*
         * Create events for read and write for this new server instance.
         */
        if (events & POLLIN) {
                flags |= TEVENT_FD_READ;
        }
        if (events & POLLOUT) {
                flags |= TEVENT_FD_WRITE;
        }
        talloc_free(server->tfd);
        server->tfd = tevent_add_fd(servers->tevent, server, rpc_get_fd(server->rpc), flags,
                                    libnfs_server_io, server);
}


/*
 * This callback is invoked when we have a client connecting to our TCP
 * port.
 */
static void do_accept(struct tevent_context *ev, struct tevent_fd *fde, uint16_t flags, void *private_data)
{
        struct libnfs_servers *servers = private_data;
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        struct libnfs_server *server;
        int i, fd;

        server = talloc(servers, struct libnfs_server);
        if (server == NULL) {
                return;
        }
        talloc_set_destructor(server, server_destructor);
        server->tfd = NULL;

        if ((fd = accept4(servers->listen_fd, (struct sockaddr *)&ss, &len, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
                printf("Failed to accept incoming connection\n");
                talloc_free(server);
                return;
        }

        server->rpc = rpc_init_server_context(fd);
        if (server->rpc == NULL) {
                close(fd);
                talloc_free(server);
                return;
        }

        for (i = 0; servers->server_procs[i].program; i++) {
                rpc_register_service(server->rpc,
                                     servers->server_procs[i].program,
                                     servers->server_procs[i].version,
                                     servers->server_procs[i].procs,
                                     servers->server_procs[i].num_procs);
        }

        update_events(server);
}

static char *_create_udp_server(struct libnfs_servers *servers,
                                struct sockaddr *sa, socklen_t sa_size)
{
        struct tevent_fd *tfd;
        int i, s = -1, opt;
        struct libnfs_server *server;
        struct sockaddr_in *in;
        struct sockaddr_in6 *in6;

        server = talloc(servers, struct libnfs_server);
        if (server == NULL) {
                return NULL;
        }

        server->tfd = NULL;
        
        /*
         * UDP: Create and bind to the socket we want to use for the UDP server.
         */
        s = socket(sa->sa_family, SOCK_DGRAM, 0);
        if (s == -1) {
                printf("Failed to create udp socket\n");
                return NULL;
        }
        
        if (sa->sa_family == AF_INET) {
                opt = 1;
                setsockopt(s, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt));
        } else {
                opt = 1;
                setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, &opt, sizeof(opt));
        }
        opt = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(s, sa, sa_size) < 0) {
                printf("Failed to bind udp socket\n");
                goto err;
        }

        /*
         * UDP: Create a libnfs server context for this socket.
         */
        server->rpc = rpc_init_server_context(s);
        if (server->rpc == NULL) {
                printf("Failed to init server.\n");
                goto err;
        }
                
        for (i = 0; servers->server_procs[i].program; i++) {
                rpc_register_service(server->rpc,
                                     servers->server_procs[i].program,
                                     servers->server_procs[i].version,
                                     servers->server_procs[i].procs,
                                     servers->server_procs[i].num_procs);
        }

        tfd = tevent_add_fd(servers->tevent, server, rpc_get_fd(server->rpc), TEVENT_FD_READ,
                            libnfs_server_io, server);
        tevent_fd_set_auto_close(tfd);

        switch (sa->sa_family) {
        case AF_INET:
                in = (struct sockaddr_in *)sa;
                if (getsockname(rpc_get_fd(server->rpc), (struct sockaddr *)in, &sa_size)) {
                        goto err;
                }
                return talloc_asprintf(server, "0.0.0.0.%d.%d", ntohs(in->sin_port) >> 8, ntohs(in->sin_port) & 0xff);
        case AF_INET6:
                in6 = (struct sockaddr_in6 *)sa;
                if (getsockname(rpc_get_fd(server->rpc), (struct sockaddr *)in6, &sa_size)) {
                        goto err;
                }
                return talloc_asprintf(server, "::.%d.%d", ntohs(in6->sin6_port) >> 8, ntohs(in6->sin6_port) & 0xff);
        }
 err:
        talloc_free(server);
        return NULL;
}


static char *_create_tcp_server(struct libnfs_servers *servers,
                                struct sockaddr *sa, socklen_t sa_size)
{
        struct tevent_fd *tfd;
        int i, opt;
        struct sockaddr_in *in;
        struct sockaddr_in6 *in6;

        if (sa->sa_family == AF_INET) {
                goto mkstr;
        }
        
        /*
         * TCP: Set up a listening socket for incoming TCP connections.
         * Once clients connect, inside do_accept() we will create a proper
         * libnfs server context for each connection.
         */
        servers->listen_fd = socket(sa->sa_family, SOCK_STREAM, 0);
        if (servers->listen_fd == -1) {
                printf("Failed to create listening socket\n");
                return NULL;
        }
        opt = 1;
        setsockopt(servers->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(servers->listen_fd, sa, sa_size) < 0) {
                printf("Failed to bind listening socket %s\n", strerror(errno));
                goto err;
        }
        if (listen(servers->listen_fd, 16) < 0) {
                printf("failed to listen to socket\n");
                goto err;
        }
        tfd = tevent_add_fd(servers->tevent, servers, servers->listen_fd, TEVENT_FD_READ,
                            do_accept, servers);
        if (tfd == NULL) {
                printf("failed to add listening fd\n");
                goto err;
        }
        tevent_fd_set_auto_close(tfd);
 mkstr:
        switch (sa->sa_family) {
        case AF_INET:
                in = (struct sockaddr_in *)sa;
                if (getsockname(servers->listen_fd, (struct sockaddr *)in, &sa_size)) {
                        goto err;
                }
                return talloc_asprintf(servers, "0.0.0.0.%d.%d", ntohs(in->sin_port) >> 8, ntohs(in->sin_port) & 0xff);
        case AF_INET6:
                in6 = (struct sockaddr_in6 *)sa;
                if (getsockname(servers->listen_fd, (struct sockaddr *)in6, &sa_size)) {
                        goto err;
                }
                return talloc_asprintf(servers, "::.%d.%d", ntohs(in6->sin6_port) >> 8, ntohs(in6->sin6_port) & 0xff);
        }

 err:
        return NULL;
}

struct ev_data {
        struct tevent_context *tevent;
        int stage;
        int status;
        int num_wait;
        struct timeval to;
};

static void _pmap4_set_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
        struct ev_data *evd = private_data;
	uint32_t res = *(uint32_t *)data;

        if (status != RPC_STATUS_SUCCESS) {
                evd->status = -1;
        }
        evd->num_wait--;
}

static void _timeout_cb(struct tevent_context *ev, struct tevent_timer *te,
                        struct timeval current_time, void *private_data)
{
        struct ev_data *evd = private_data;

        evd->status = -1;
        evd->num_wait = 0;
}

static void libnfs_client_io(struct tevent_context *ev, struct tevent_fd *fde, uint16_t flags, void *private_data)
{
        struct rpc_context *rpc = private_data;

        /*
         * Let libnfs process the event.
         */
        if (rpc_service(rpc, POLLIN) < 0) {
                return;
        }
}

static int servers_destructor(struct libnfs_servers *servers)
{
        return 0;
}
        
struct libnfs_servers *libnfs_create_server(TALLOC_CTX *ctx,
                                            struct tevent_context *tevent,
                                            int port, char *name, int transports,
                                            struct libnfs_server_procs *server_procs)
{
        struct sockaddr_in in;
        socklen_t in_len = sizeof(struct sockaddr_in);
        struct sockaddr_in6 in6;
        socklen_t in6_len = sizeof(struct sockaddr_in6);
        struct libnfs_servers *servers;
        struct rpc_context *rpc = NULL;
        char *udp4_str, *udp6_str, *tcp4_str, *tcp6_str;
        int i;
        struct ev_data *to;
        TALLOC_CTX *tmp_ctx = talloc_new(NULL);
        
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        in.sin_addr.s_addr = htonl (INADDR_ANY);

        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(port);
        in6.sin6_addr = in6addr_any;

        servers = talloc(ctx, struct libnfs_servers);
        if (servers == NULL) {
                return NULL;
        }
        servers->tevent = tevent;
        talloc_set_destructor(servers, servers_destructor);

        servers->server_procs = server_procs;

        if (transports & TRANSPORT_UDP) {
                udp4_str = _create_udp_server(servers, (struct sockaddr *)&in, sizeof(in));
                if (udp4_str == NULL) {
                        goto err;
                }
        }
        if (transports & TRANSPORT_UDP6) {
                udp6_str = _create_udp_server(servers, (struct sockaddr *)&in6, sizeof(in6));
                if (udp6_str == NULL) {
                        goto err;
                }
        }
        if (transports & TRANSPORT_TCP6) {
                tcp6_str = _create_tcp_server(servers, (struct sockaddr *)&in6, sizeof(in6));
                if (tcp6_str == NULL) {
                        goto err;
                }
        }
        if (transports & TRANSPORT_TCP) {
                tcp4_str = _create_tcp_server(servers, (struct sockaddr *)&in, sizeof(in));
                if (tcp4_str == NULL) {
                        goto err;
                }
        }

        rpc = rpc_init_udp_context();
        if (rpc == NULL) {
                printf("Failed to create RPC context\n");
                goto err;
        }
	if (rpc_bind_udp(rpc, "0.0.0.0", 0) < 0) {
                printf("Failed to bind RPC context\n");
                goto err;
	}
        if (rpc_set_udp_destination(rpc, "127.0.0.1", 111, 0) < 0) {
                printf("Failed to set udp destination\n");
                goto err;
        }
        to = talloc(tmp_ctx, struct ev_data);
        to->tevent = tevent;
        to->stage = 0;
        to->status = 0;
        to->num_wait = 0;
        gettimeofday(&to->to, NULL);
        to->to.tv_sec += 5;
        tevent_add_fd(servers->tevent, tmp_ctx, rpc_get_fd(rpc), TEVENT_FD_READ,
                      libnfs_client_io, rpc);

        for (i = 0; servers->server_procs[i].program; i++) {
                PMAP4SETargs set4args;

                set4args.prog = servers->server_procs[i].program;
                set4args.vers = servers->server_procs[i].version;
                if (transports & TRANSPORT_UDP) {
                        to->num_wait += 2;
                        set4args.netid = "udp";
                        set4args.addr  = "";
                        if (rpc_pmap4_unset_task(rpc, &set4args, _pmap4_set_cb, to) == NULL) {
                                printf("Failed to send UNSET4 request\n");
                                goto err;
                        }
                        set4args.addr  = udp4_str;
                        set4args.owner = name;
                        if (rpc_pmap4_set_task(rpc, &set4args, _pmap4_set_cb, to) == NULL) {
                                printf("Failed to send SET4 request\n");
                                goto err;
                        }
		}
                if (transports & TRANSPORT_UDP6) {
                        to->num_wait += 2;
                        set4args.netid = "udp6";
                        set4args.addr  = "";
                        if (rpc_pmap4_unset_task(rpc, &set4args, _pmap4_set_cb, to) == NULL) {
                                printf("Failed to send UNSET4 request\n");
                                goto err;
                        }
                        set4args.addr  = udp6_str;
                        if (rpc_pmap4_set_task(rpc, &set4args, _pmap4_set_cb, to) == NULL) {
                                printf("Failed to send SET4 request\n");
                                goto err;
                        }
                }
                if (transports & TRANSPORT_UDP) {
                        to->num_wait += 2;
                        set4args.netid = "tcp";
                        set4args.addr  = "";
                        if (rpc_pmap4_unset_task(rpc, &set4args, _pmap4_set_cb, to) == NULL) {
                                printf("Failed to send UNSET4 request\n");
                                goto err;
                        }
                        set4args.addr  = tcp4_str;
                        if (rpc_pmap4_set_task(rpc, &set4args, _pmap4_set_cb, to) == NULL) {
                                printf("Failed to send SET4 request\n");
                                goto err;
                        }
                }
                if (transports & TRANSPORT_UDP) {
                        to->num_wait += 2;
                        set4args.netid = "tcp6";
                        set4args.addr  = "";
                        if (rpc_pmap4_unset_task(rpc, &set4args, _pmap4_set_cb, to) == NULL) {
                                printf("Failed to send UNSET4 request\n");
                                goto err;
                        }
                        set4args.addr  = tcp6_str;
                        if (rpc_pmap4_set_task(rpc, &set4args, _pmap4_set_cb, to) == NULL) {
                                printf("Failed to send SET4 request\n");
                                goto err;
                        }
                }
        }
        tevent_add_timer(tevent, tmp_ctx, to->to, _timeout_cb, to);
        while (to->num_wait > 0) {
                tevent_loop_once(to->tevent);
        }
        if (to->status) {
                printf("timed out registering with portmapper\n");
                goto err;
        }

 out:
        if (rpc) {
                rpc_destroy_context(rpc);
        }
        talloc_free(tmp_ctx);
        return servers;
 err:
        talloc_free(servers);
        servers = NULL;
        goto out;
}
