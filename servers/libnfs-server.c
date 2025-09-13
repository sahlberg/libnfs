/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2026
   
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

#include <stdlib.h>
#include <talloc.h>
#include <event2/event.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-portmap.h"
#include "libnfs-server.h"


static int server_destructor(struct libnfs_server *server)
{
        if (server->rpc) {
                rpc_disconnect(server->rpc, NULL);
                rpc_destroy_context(server->rpc);
        }
        if (server->read_event) {
                event_free(server->read_event);
        }
        if (server->write_event) {
                event_free(server->write_event);
        }

        return 0;
}

/*
 * Based on the state of libnfs and its context, update libevent
 * accordingly regarding which events we are interested in.
 */
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

/*
 * This callback is invoked from the event system when an event we are waiting
 * for has become active.
 */
static void libnfs_server_io(evutil_socket_t fd, short events, void *private_data)
{
        struct libnfs_server *server = private_data;
        int revents = 0;

        /*
         * Translate the libevent read/write flags to the corresponding
         * flags that libnfs uses.
         */
        if (events & EV_READ) {
                revents |= POLLIN;
        }
        if (events & EV_WRITE) {
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
        update_events(server->rpc, server->read_event, server->write_event);
}



/*
 * This callback is invoked when we have a client connecting to our TCP
 * port.
 */
static void do_accept(evutil_socket_t s, short events, void *private_data)
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

        if ((fd = accept(s, (struct sockaddr *)&ss, &len)) < 0) {
                talloc_free(server);
                return;
        }
        evutil_make_socket_nonblocking(fd);

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

        /*
         * Create events for read and write for this new server instance.
         */
        server->read_event = event_new(servers->base, fd, EV_READ|EV_PERSIST,
                                       libnfs_server_io, server);
        server->write_event = event_new(servers->base, fd, EV_WRITE|EV_PERSIST,
                                        libnfs_server_io, server);
        update_events(server->rpc, server->read_event, server->write_event);
}

static char *_create_udp_server(struct event_base *base,
                                struct sockaddr *sa, socklen_t sa_size,
                                struct libnfs_servers *servers)
{
        int i, s = -1;
        struct libnfs_server *server;
        struct sockaddr_in *in;
        struct sockaddr_in6 *in6;

        server = talloc(servers, struct libnfs_server);
        if (server == NULL) {
                return NULL;
        }
        server->write_event = NULL;
        /*
         * UDP: Create and bind to the socket we want to use for the UDP server.
         */
        s = socket(sa->sa_family, SOCK_DGRAM, 0);
        if (s == -1) {
                printf("Failed to create udp socket\n");
                return NULL;
        }
#ifdef __linux__        
        int opt;
        if (sa->sa_family == AF_INET) {
                opt = 1;
                setsockopt(s, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt));
        } else {
                opt = 1;
                setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, &opt, sizeof(opt));
        }
#endif
        evutil_make_socket_nonblocking(s);
        evutil_make_listen_socket_reuseable(s);
        evutil_make_socket_closeonexec(s);

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

        server->read_event = event_new(base,
                                       s,
                                       EV_READ|EV_PERSIST,
                                       libnfs_server_io, server);
        event_add(server->read_event, NULL);

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
        if (s != -1) {
                close(s);
        }
        return NULL;
}


static int _create_tcp_server(struct event_base *base,
                              struct sockaddr *sa, int sa_size,
                              int *s, struct event **listen_event,
                              struct libnfs_servers *servers)
{
        int i;
        
        /*
         * TCP: Set up a listening socket for incoming TCP connections.
         * Once clients connect, inside do_accept() we will create a proper
         * libnfs server context for each connection.
         */
        *s = socket(sa->sa_family, SOCK_STREAM, 0);
        if (*s == -1) {
                printf("Failed to create listening socket\n");
                return -1;
        }
        evutil_make_socket_nonblocking(*s);
        evutil_make_listen_socket_reuseable(*s);
        evutil_make_socket_closeonexec(*s);

        if (bind(*s, sa, sa_size) < 0) {
                printf("Failed to bind listening socket %s\n", strerror(errno));
                goto err;
        }
        if (listen(*s, 16) < 0) {
                printf("failed to listen to socket\n");
                goto err;
        }
        *listen_event = event_new(base,
                                  *s,
                                  EV_READ|EV_PERSIST,
                                  do_accept, servers);
        event_add(*listen_event, NULL);
        
        return 0;
 err:
        if (*s != -1) {
                close(*s);
                *s = -1;
        }
        return -1;
}

struct ev_data {
        struct event_base *base;
        int stage;
        int status;
        int num_wait;
        struct timeval to;
        struct event *timer;
};

static void _pmap4_set_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
        struct ev_data *evd = private_data;
	uint32_t res = *(uint32_t *)data;

        if (status != RPC_STATUS_SUCCESS) {
                evd->status = -1;
        }
        if (--evd->num_wait == 0) {
                event_base_loopbreak(evd->base);
        }
}

static void _timeout_cb(evutil_socket_t fd, short what, void *arg)
{
        struct ev_data *evd = arg;

        if (evd->stage == 0) {
                evd->stage++;
                evd->to.tv_sec = 5;
                evd->to.tv_usec = 0;
                event_add(evd->timer, &evd->to);

                /* create rpc context to local pormapper and send SET */
                /* getsockname() to find which port was bound to */
                return;
        }
        evd->status = -1;
        event_base_loopbreak(evd->base);
}

static void libnfs_client_io(evutil_socket_t fd, short events, void *private_data)
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
        if (servers->listen_4 != -1) {
                close(servers->listen_4);
        }
        if (servers->listen_6 != -1) {
                close(servers->listen_6);
        }
        if (servers->listen_event4) {
                event_free(servers->listen_event4);
        }
        if (servers->listen_event6) {
                event_free(servers->listen_event6);
        }
        return 0;
}
        
struct libnfs_servers *libnfs_create_server(TALLOC_CTX *ctx,
                                            struct event_base *base,
                                            int port, char *name,
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
        struct ev_data to = { base, 0, 0, 0, {0, 0}, NULL};
        struct event *read_event = NULL;
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
        servers->listen_4 = -1;
        servers->listen_6 = -1;
        talloc_set_destructor(servers, servers_destructor);

        servers->base = base;
        servers->server_procs = server_procs;

        udp4_str = _create_udp_server(base, (struct sockaddr *)&in, sizeof(in), servers);
        if (udp4_str == NULL) {
                goto err;
        }
        udp6_str = _create_udp_server(base, (struct sockaddr *)&in6, sizeof(in6), servers);
        if (udp6_str == NULL) {
                goto err;
        }
        if (_create_tcp_server(base, (struct sockaddr *)&in6, sizeof(in6), &servers->listen_6, &servers->listen_event6, servers)) {
                goto err;
        }
#if 0
        /* Listening to in6addr_any above binds to both tcp and tcp6 on Linux so this will fail
         * TODO: only make this call if we either do not have ipv6 support or no Linux
         */
        if (_create_tcp_server(base, (struct sockaddr *)&in, sizeof(in), &servers->listen_4, servers)) {
                goto err;
        }
#endif

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
        read_event = event_new(base, rpc_get_fd(rpc), EV_READ|EV_PERSIST,
                               libnfs_client_io, rpc);
        event_add(read_event, NULL);
        
        if (getsockname(servers->listen_6, (struct sockaddr *)&in6, &in6_len)) {
                goto err;
        }
        tcp6_str = talloc_asprintf(tmp_ctx, "::.%d.%d", ntohs(in6.sin6_port) >> 8, ntohs(in6.sin6_port) & 0xff);
#if 0        
        if (getsockname(servers->listen_4, (struct sockaddr *)&in4, &in4_len)) {
                goto err;
        }
#endif        
        tcp4_str = talloc_asprintf(tmp_ctx, "0.0.0.0.%d.%d", ntohs(in6.sin6_port) >> 8, ntohs(in6.sin6_port) & 0xff);

        for (i = 0; servers->server_procs[i].program; i++) {
                PMAP4SETargs set4args;

                to.num_wait += 1;
                set4args.prog = servers->server_procs[i].program;
                set4args.vers = servers->server_procs[i].version;
                set4args.netid = "";
                set4args.addr  = "";
                set4args.owner = "";
                if (rpc_pmap4_unset_task(rpc, &set4args, _pmap4_set_cb, &to) == NULL) {
                        printf("Failed to send UNSET4 request\n");
                        goto err;
                }

                to.num_wait += 4;
                set4args.prog = servers->server_procs[i].program;
                set4args.vers = servers->server_procs[i].version;
                set4args.netid = "udp";
                set4args.addr  = udp4_str;
                set4args.owner = name;
		if (rpc_pmap4_set_task(rpc, &set4args, _pmap4_set_cb, &to) == NULL) {
			printf("Failed to send SET4 request\n");
                        goto err;
		}
                set4args.netid = "udp6";
                set4args.addr  = udp6_str;
		if (rpc_pmap4_set_task(rpc, &set4args, _pmap4_set_cb, &to) == NULL) {
			printf("Failed to send SET4 request\n");
                        goto err;
		}
                set4args.netid = "tcp";
                set4args.addr  = tcp4_str;
		if (rpc_pmap4_set_task(rpc, &set4args, _pmap4_set_cb, &to) == NULL) {
			printf("Failed to send SET4 request\n");
                        goto err;
		}
                set4args.netid = "tcp6";
                set4args.addr  = tcp6_str;
		if (rpc_pmap4_set_task(rpc, &set4args, _pmap4_set_cb, &to) == NULL) {
			printf("Failed to send SET4 request\n");
                        goto err;
		}
        }
        to.timer = event_new(base, -1, 0, _timeout_cb, &to);
        event_add(to.timer, &to.to);
        event_base_dispatch(base);
        if (to.status) {
                printf("timed out registering with portmapper\n");
                goto err;
        }

 out:
        if (to.timer) {
                event_del(to.timer);
                event_free(to.timer);
        }
        if (read_event) {
                event_del(read_event);
                event_free(read_event);
        }
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
