/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
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

/* This is a very incomplete portmapper that only implements
 * a subset of version 2 and threee of the protocol.
 * A proper portmapper needs to implement these two versions fully
 * as well as version 4.
 *
 * See this as an example of how to build a simple RPC service
 * that supports both UDP and TCP using libnfs.
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
#include "libnfs-raw-portmap.h"

#include <event2/event.h>

struct libnfs_server {
        struct rpc_context *rpc;
        struct event *read_event;
        struct event *write_event;
};

struct libnfs_servers {
        struct event_base *base;
        int listen_4;
        int listen_6;
        struct libnfs_server udp_server4;
        struct libnfs_server udp_server6;
        struct libnfs_server_procs *server_procs;
};

struct libnfs_server_procs {
        uint32_t program;
        uint32_t version;
        struct service_proc *procs;
        int num_procs;
};

static void free_server(struct libnfs_server *server)
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

        free(server);
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
                free_server(server);
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

        server = malloc(sizeof(struct libnfs_server));
        if (server == NULL) {
                return;
        }
        memset(server, 0, sizeof(*server));

        if ((fd = accept(s, (struct sockaddr *)&ss, &len)) < 0) {
                free_server(server);
                return;
        }
        evutil_make_socket_nonblocking(fd);

        server->rpc = rpc_init_server_context(fd);
        if (server->rpc == NULL) {
                close(fd);
                free_server(server);
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

static int _create_udp_server(struct event_base *base,
                              struct sockaddr *sa, int sa_size,
                              struct libnfs_server *server,
                              struct libnfs_servers *servers)
{
        int i, s;
        
        /*
         * UDP: Create and bind to the socket we want to use for the UDP server.
         */
        s = socket(sa->sa_family, SOCK_DGRAM, 0);
        if (s == -1) {
                printf("Failed to create udp socket\n");
                return -1;
        }
        evutil_make_socket_nonblocking(s);
        evutil_make_listen_socket_reuseable(s);
        evutil_make_socket_closeonexec(s);

        if (bind(s, sa, sa_size) < 0) {
                printf("Failed to bind udp socket\n");
                return -1;
        }

        /*
         * UDP: Create a libnfs server context for this socket.
         */
        server->rpc = rpc_init_server_context(s);
        
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

        return 0;
}


static int _create_tcp_server(struct event_base *base,
                              struct sockaddr *sa, int sa_size,
                              int *s,
                              struct libnfs_servers *servers)
{
        int i;
        struct event *listen_event;
        
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
                return -1;
        }
        if (listen(*s, 16) < 0) {
                printf("failed to listen to socket\n");
                return -1;
        }
        listen_event = event_new(base,
                                 *s,
                                 EV_READ|EV_PERSIST,
                                 do_accept, servers);
        event_add(listen_event, NULL);

        return 0;
}

struct libnfs_servers *libnfs_create_server(struct event_base *base,
                                            int port,
                                            struct libnfs_server_procs *server_procs)
{
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct libnfs_servers *servers;

        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        in.sin_addr.s_addr = htonl (INADDR_ANY);

        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(port);
        in6.sin6_addr = in6addr_any;

        servers = calloc(1, sizeof(struct libnfs_servers));
        if (servers == NULL) {
                return NULL;
        }

        servers->listen_4 = -1;
        servers->listen_6 = -1;
        servers->base = base;
        servers->server_procs = server_procs;

        if (_create_udp_server(base, (struct sockaddr *)&in, sizeof(in), &servers->udp_server4, servers)) {
                return NULL;
        }
        if (_create_udp_server(base, (struct sockaddr *)&in6, sizeof(in6), &servers->udp_server6, servers)) {
                return NULL;
        }
        if (_create_tcp_server(base, (struct sockaddr *)&in6, sizeof(in6), &servers->listen_6, servers)) {
                return NULL;
        }
#if 0
        /* Listening to in6addr_any above binds to both tcp and tcp6 on Linux so this will fail
         * TODO: only make this call if we either do not have ipv6 support or no Linux
         */
        if (_create_tcp_server(base, (struct sockaddr *)&in, sizeof(in), &servers->listen_4, servers)) {
                return NULL;
        }
#endif
        
        return servers;
}


/*
 * Portmapper implementation begins here
 */

struct mapping {
        struct mapping *next;
        u_int prog;
        u_int vers;
        int port;
        char *netid;
        char *addr;
        char *owner;
};
struct mapping *map;


void free_map_item(struct mapping *item)
{
        free(item->netid);
        free(item->addr);
        free(item->owner);
        free(item);
}

/*
 * Add a registration for program,version,netid.
 */
int pmap_register(int prog, int vers, char *netid, char *addr,
                  char *owner)
{
        struct mapping *item;
        char *str;
        int count = 0;

        item = malloc(sizeof(struct mapping));
        item->prog  = prog;
        item->vers  = vers;
        item->netid = netid;
        item->addr  = addr;
        item->owner = owner;

        /* The port are the last two dotted decimal fields in the address */
        for (str = item->addr + strlen(item->addr) - 1; str >= item->addr; str--) {
                if (*str != '.') {
                        if (*str < '0' || *str > '9') {
                                break;
                        }
                        continue;
                }

                count++;
                if (count == 2) {
                        int high, low;

                        sscanf(str, ".%d.%d", &high, &low);
                        item->port = high * 256 + low;
                        break;
                }
        }

        item->next  = map;
        map = item;
}

/*
 * Find and return a registration matching program,version,netid.
 */
struct mapping *map_lookup(int prog, int vers, char *netid)
{
        struct mapping *tmp;

        for (tmp = map; tmp; tmp = tmp->next) {
                if (tmp->prog != prog) {
                        continue;
                }
                if (tmp->vers != vers) {
                        continue;
                }
                if (strcmp(tmp->netid, netid)) {
                        continue;
                }

                return tmp;
        }

        return NULL;
}

/*
 * Remove a registration from our map or registrations.
 */
void map_remove(int prog, int vers, char *netid)
{
        struct mapping *prev = NULL;
        struct mapping *tmp;

        for (tmp = map; tmp; prev = tmp, tmp = tmp->next) {
                if (tmp->prog != prog) {
                        continue;
                }
                if (tmp->vers != vers) {
                        continue;
                }
                if (strcmp(tmp->netid, netid)) {
                        continue;
                }
                break;
        }
        if (tmp == NULL) {
                return;
        }
        if (prev) {
                prev->next = tmp->next;
        } else {
                map = tmp->next;
        }

        free_map_item(tmp);
        return;
}

/*
 * The NULL procedure. All protocols/versions must provide a NULL procedure
 * as index 0.
 * It is used by clients, and rpcinfo, to "ping" a service and verify that
 * the service is available and that it does support the indicated version.
 */
static int pmap2_null_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);

        return 0;
}

/*
 * v2 GETPORT.
 * This is the lookup function for portmapper version 2.
 * A client provides program, version and protocol (tcp or udp)
 * and portmapper returns which port that service is available on,
 * (or 0 if no such program is registered.)
 */
static int pmap2_getport_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP2GETPORTargs *args = call->body.cbody.args;
        struct mapping *tmp;
        char *netid;
        static uint32_t port = 0;

        if (args->prot == IPPROTO_TCP) {
                netid = "tcp";
        } else {
                netid = "udp";
        }

        tmp = map_lookup(args->prog, args->vers, netid);
        if (tmp) {
                port = tmp->port;
        }

        rpc_send_reply(rpc, call, &port, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));

        return 0;
}

/*
 * v2 DUMP.
 * This RPC returns a list of all endpoints that are registered with
 * portmapper.
 */
static int pmap2_dump_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP2DUMPres reply;
        struct mapping *tmp;

        reply.list = NULL;
        for (tmp = map; tmp; tmp = tmp->next) {
                struct pmap2_mapping_list *tmp_list;
                int proto;

                /* pmap2 only support ipv4 */
                if (!strcmp(tmp->netid, "tcp")) {
                        proto = IPPROTO_TCP;
                } else if (!strcmp(tmp->netid, "udp")) {
                        proto = IPPROTO_UDP;
                } else {
                        continue;
                }
                      
                tmp_list = malloc(sizeof(struct pmap2_mapping_list));
                tmp_list->map.prog  = tmp->prog;
                tmp_list->map.vers  = tmp->vers;
                tmp_list->map.prot  = proto;
                tmp_list->map.port  = tmp->port;
                
                tmp_list->next = reply.list;

                reply.list = tmp_list;
        }

        rpc_send_reply(rpc, call, &reply,
                       (zdrproc_t)zdr_PMAP2DUMPres, sizeof(PMAP2DUMPres));

        while (reply.list) {
                struct pmap2_mapping_list *tmp_list = reply.list->next;
                free(reply.list);
                reply.list = tmp_list;
        }
        
        return 0;
}

/*
 * v2 SET
 * This procedure is used to register and endpoint with portmapper.
 */
static int pmap2_set_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP2GETPORTargs *args = call->body.cbody.args;
        char *prot;
        char *addr;
        uint32_t response = 1;

        if (args->prot == IPPROTO_TCP) {
                prot = "tcp";
        } else {
                prot = "udp";
        }

        /* Don't update if we already have a mapping */
        if (map_lookup(args->prog, args->vers, prot)) {
                response = 0;
                rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
                return 0;
        }
        
        asprintf(&addr, "0.0.0.0.%d.%d", args->port >> 8, args->port & 0xff);
        pmap_register(args->prog, args->vers, strdup(prot), addr,
                      strdup("<unknown>"));

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        return 0;
}

/*
 * v2 UNSET
 * This procedure is used to remove a registration from portmappers
 * list of endpoints.
 */
static int pmap2_unset_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP2GETPORTargs *args = call->body.cbody.args;
        char *prot;
        char *addr;
        uint32_t response = 1;

        if (args->prot == IPPROTO_TCP) {
                prot = "tcp";
        } else {
                prot = "udp";
        }

        map_remove(args->prog, args->vers, prot);

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        return 0;
}

/*
 * Service table for portmapper v2.
 *
 * Service management is table driven in libnfsand this is the table
 * that defines which procedures we implement for portmapper v2.
 * If clients try to connect to the not-yet-implemented procedures here
 * libnfs will automatically respond with an RPC layer error that flags
 * PROCEDURE UNAVAILABLE.
 *
 * This table contains the procedure number, the callback function to implement
 * this procedure, the unmarshalling function that libnfs should use to unppack
 * the client payload as well as its size.
 *
 * Version 2 does not support ipv6 so this version of portmapper is
 * not too commonly used any more.
 */
struct service_proc pmap2_pt[] = {
        {PMAP2_NULL, pmap2_null_proc,
            (zdrproc_t)zdr_void, 0},
        {PMAP2_SET, pmap2_set_proc,
            (zdrproc_t)zdr_PMAP2SETargs, sizeof(PMAP2SETargs)},
        {PMAP2_UNSET, pmap2_unset_proc,
            (zdrproc_t)zdr_PMAP2UNSETargs, sizeof(PMAP2UNSETargs)},
        {PMAP2_GETPORT, pmap2_getport_proc,
            (zdrproc_t)zdr_PMAP2GETPORTargs, sizeof(PMAP2GETPORTargs)},
        {PMAP2_DUMP, pmap2_dump_proc,
            (zdrproc_t)zdr_void, 0},
        //{PMAP2_CALLIT, pmap2_...},
};

/*
 * The NULL procedure. All protocols/versions must provide a NULL procedure
 * as index 0.
 * It is used by clients, and rpcinfo, to "ping" a service and verify that
 * the service is available and that it does support the indicated version.
 */
static int pmap3_null_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);

        return 0;
}

/*
 * v3 DUMP.
 * This RPC returns a list of all endpoints that are registered with
 * portmapper.
 */
static int pmap3_dump_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP3DUMPres reply;
        struct mapping *tmp;

        reply.list = NULL;
        for (tmp = map; tmp; tmp = tmp->next) {
                struct pmap3_mapping_list *tmp_list;
                
                tmp_list = malloc(sizeof(struct pmap3_mapping_list));
                tmp_list->map.prog  = tmp->prog;
                tmp_list->map.vers  = tmp->vers;
                tmp_list->map.netid = tmp->netid;
                tmp_list->map.addr  = tmp->addr;
                tmp_list->map.owner = tmp->owner;
                
                tmp_list->next = reply.list;

                reply.list = tmp_list;
        }

        rpc_send_reply(rpc, call, &reply,
                       (zdrproc_t)zdr_PMAP3DUMPres, sizeof(PMAP3DUMPres));

        while (reply.list) {
                struct pmap3_mapping_list *tmp_list = reply.list->next;
                free(reply.list);
                reply.list = tmp_list;
        }
        
        return 0;
}


/*
 * Service table for portmapper v3.
 *
 * Service management is table driven in libnfsand this is the table
 * that defines which procedures we implement for portmapper v3.
 * If clients try to connect to the not-yet-implemented procedures here
 * libnfs will automatically respond with an RPC layer error that flags
 * PROCEDURE UNAVAILABLE.
 *
 * This table contains the procedure number, the callback function to implement
 * this procedure, the unmarshalling function that libnfs should use to unppack
 * the client payload as well as its size.
 */
struct service_proc pmap3_pt[] = {
        {PMAP3_NULL, pmap3_null_proc,
            (zdrproc_t)zdr_void, 0},
        //{PMAP3_SET, pmap3_...},
        //{PMAP3_UNSET, pmap3_...},
        //{PMAP3_GETADDR, pmap3_...},
        {PMAP3_DUMP, pmap3_dump_proc,
            (zdrproc_t)zdr_void, 0},
        //{PMAP3_CALLIT, pmap3_...},
        //{PMAP3_GETTIME, pmap3_...},
        //{PMAP3_UADDR2TADDR, pmap3_...},
        //{PMAP3_TADDR2UADDR, pmap3_...},
};



int main(int argc, char *argv[])
{
        struct event_base *base;
        struct libnfs_servers *servers;

        struct libnfs_server_procs server_procs[] = {
                { PMAP_PROGRAM, PMAP_V2, pmap2_pt, sizeof(pmap2_pt) / sizeof(pmap2_pt[0]) },
                { PMAP_PROGRAM, PMAP_V3, pmap3_pt, sizeof(pmap3_pt) / sizeof(pmap3_pt[0]) },
                { 0, 0, 0, 0}
        };
        
#ifdef WIN32
        if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
                printf("Failed to start Winsock2\n");
                return 10;
        }
#endif

#ifdef AROS
        aros_init_socket();
#endif


        /* This is the portmapper protocol itself which we obviously
         * support.
         */
        pmap_register(100000, 2, strdup("tcp"), strdup("0.0.0.0.0.111"),
                      strdup("portmapper-service"));
        pmap_register(100000, 2, strdup("udp"), strdup("0.0.0.0.0.111"),
                      strdup("portmapper-service"));
        pmap_register(100000, 3, strdup("tcp"), strdup("0.0.0.0.0.111"),
                      strdup("portmapper-service"));
        pmap_register(100000, 3, strdup("udp"), strdup("0.0.0.0.0.111"),
                      strdup("portmapper-service"));

        
        base = event_base_new();
        if (base == NULL) {
                printf("Failed create event context\n");
                exit(10);
        }

        servers = libnfs_create_server(base, 111, &server_procs[0]);
        
        /*
         * Everything is now set up. Start the event loop.
         */
        event_base_dispatch(base);
        
        return 0;
}
