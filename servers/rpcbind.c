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
/*
 * A non-blocking and eventdriven implementation of rpcbind using libnfs.
 * TODO: Call NULL periodically and reap dead services from the database.
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
 
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#include <arpa/inet.h>
#include <event2/event.h>
#include <stdlib.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-portmap.h"
#include "libnfs-server.h"


#define DBFILE "/var/run/rpcbind/rpcbind.libnfs"

/*
 * Portmapper implementation begins here
 */

struct pmap_state {
        struct event_base *base;
        struct rpc_context *rpc;
        struct event *read_event;
};

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


static void write_db(void)
{
        FILE *fd;
        struct mapping *m;

        fd = fopen(DBFILE, "w");
        if (fd == NULL) {
                printf("Failed to open DB file %s\n", DBFILE);
                return;
        }
        for (m = map; m; m = m->next) {
                fprintf(fd, "%d,%d,%d,%s,%s,%s\n",
                        m->prog,
                        m->vers,
                        m->port,
                        m->netid,
                        m->addr,
                        m->owner);
        }
        fclose(fd);
}

static void read_db(void)
{
        FILE *fd;
        struct mapping *m;
        char buf[256];
        
        fd = fopen(DBFILE, "r");
        if (fd == NULL) {
                printf("Failed to open DB file %s\n", DBFILE);
                return;
        }
        while(fgets(buf, sizeof(buf), fd)) {
                struct mapping *item;
                char *ptr, *next;
                int prog, vers, port;
                char *netid, *addr, *owner;
                
                ptr = buf;
                
                next = index(ptr, ',');
                if (next == NULL) {
                        continue;
                }
                *next++ = 0;
                prog = atoi(ptr);
                ptr = next;
                if (prog == 100000) {
                        continue;
                }
                next = index(ptr, ',');
                if (next == NULL) {
                        continue;
                }
                *next++ = 0;
                vers = atoi(ptr);
                ptr = next;
                
                next = index(ptr, ',');
                if (next == NULL) {
                        continue;
                }
                *next++ = 0;
                port = atoi(ptr);
                ptr = next;

                netid = next;
                addr = index(netid, ',');
                if (addr == NULL) {
                        continue;
                }
                *addr++ = 0;
                owner = index(addr, ',');
                if (owner == NULL) {
                        continue;
                }
                *owner++ = 0;
                owner[strlen(owner) - 1] = 0;


                item = malloc(sizeof(struct mapping));
                if (item == NULL) {
                        continue;
                }
                item->prog  = prog;
                item->vers  = vers;
                item->port  = port;
                item->netid = strdup(netid);
                item->addr  = strdup(addr);
                item->owner = strdup(owner);
                item->next = map;
                map = item;
        }
        fclose(fd);
}


void free_map_item(struct mapping *item)
{
        free(item->netid);
        free(item->addr);
        free(item->owner);
        free(item);
}

static char *socket_to_str(struct rpc_context *rpc, char *netid)
{
        static char addr[64] = {0}, *ptr;

        if (rpc_is_udp_socket(rpc)) {
                struct sockaddr *sa;

                sa = rpc_get_udp_dst_sockaddr(rpc);
                inet_ntop(sa->sa_family, &((struct sockaddr_in *)sa)->sin_addr, addr, sizeof(addr));
        } else {
                struct sockaddr_storage ss;
                socklen_t ss_len = sizeof(struct sockaddr_storage);

                /*
                 * Came in through TCP so whatever is the local address we accept()ed on
                 * should be good enough.
                 */
                if (getsockname(rpc_get_fd(rpc), (struct sockaddr *)&ss, &ss_len)) {
                        return 0;
                }
                inet_ntop(ss.ss_family, &((struct sockaddr_in6 *)&ss)->sin6_addr, addr, sizeof(addr));
        }
        ptr = &addr[0];
        /*
         * Linux TCP sockets listen to both tcp and tcp6 in this case and the address is either
         * 1.2.3.4 got ipv4 or ::FFFF:1.2.3.4 for ipv6.
         * If the client asked for tcp then we need to skip the IPV6-toIPV4 prefix in the address
         * string.
         */
        if (!strcmp(netid, "tcp") || !strcmp(netid, "udp")) {
                ptr = rindex(ptr, ':');
                if (ptr) {
                        ptr++;
                } else {
                        ptr = &addr[0];
                }
        }

        return ptr;
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
        struct mapping *new_map = NULL;
        struct mapping *tmp, *next;

        for (tmp = map; tmp; tmp = next) {
                next = tmp->next;
                if (tmp->prog != prog |
                    tmp->vers != vers ||
                    (netid && netid[0] && strcmp(tmp->netid, netid))) {
                            tmp->next = new_map;
                            new_map = tmp;
                            continue;
                }
                free_map_item(tmp);
        }
        map = new_map;
        return;
}


struct callit_data {
        struct rpc_context *rpc;
        struct rpc_msg *call;
        struct event *timeout_event;
        int pmap_vers;
        int port;
        char *addr;
};

void free_callit_cb_data(struct callit_data *cb_data)
{
        if (cb_data == NULL) {
                return;
        }
        if (cb_data->call) {
                rpc_free_deferred_call(cb_data->rpc, cb_data->call);
        }
        if (cb_data->addr) {
                free(cb_data->addr);
        }
        if (cb_data->timeout_event) {
                event_free(cb_data->timeout_event);
        }
        free(cb_data);
}

static void _timeout_cb(evutil_socket_t fd, short what, void *arg)
{
        struct callit_data *cb_data = arg;

        free_callit_cb_data(cb_data);
}

static void _callit_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
        struct callit_data *cb_data = private_data;
        uint32_t response = status;

        /* No reply on error */
        /* TODO: v4 indirect do return error */
        if (status != RPC_STATUS_SUCCESS) {
                free_callit_cb_data(cb_data);
                return;
        }

        if (cb_data->pmap_vers == 2) {
                PMAP2CALLITres res2;

                res2.port = cb_data->port;
                res2.res.res_len = 0;
                res2.res.res_val = NULL;
                rpc_send_reply(cb_data->rpc, cb_data->call, &res2, (zdrproc_t)zdr_PMAP2CALLITres, sizeof(PMAP2CALLITres));
        } else {
                PMAP3CALLITres res3;
                
                res3.addr = cb_data->addr;
                res3.results.results_len = 0;
                res3.results.results_val = NULL;
                rpc_send_reply(cb_data->rpc, cb_data->call, &res3, (zdrproc_t)zdr_PMAP3CALLITres, sizeof(PMAP3CALLITres));
        }
        
        free_callit_cb_data(cb_data);
}

/*
 * This is an example on how to make a temp copy of struct rpc_msg *call
 * that we can use later to invoke rpc_send_reply() from a different context.
 */
static int pmapX_callit_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque, int pmap_vers)
{
        struct pmap_state *pmap = opaque;
        PMAP3CALLITargs *args = call->body.cbody.args;
        struct callit_data *cb_data = NULL;
        struct mapping *map;
        struct timeval to = {3, 0};

        /* Only support callit for NULL procedure. */
        if (args->proc != 0) {
                return 0;
        }

        map = map_lookup(args->prog, args->vers, "udp");
        if (map == NULL) {
                goto err;
        }

        if (rpc_set_udp_destination(pmap->rpc, "127.0.0.1", map->port, 0) < 0) {
                printf("Failed to set udp destination\n");
                goto err;
        }
        cb_data = calloc(1, sizeof(*cb_data));
        if (cb_data == NULL) {
                goto err;
        }
        cb_data->rpc = rpc;
        cb_data->pmap_vers = pmap_vers;
        cb_data->call = rpc_copy_deferred_call(rpc, call);
        if (cb_data->call == NULL) {
                goto err;
        }
        cb_data->port = map->port;
        cb_data->addr = strdup(socket_to_str(rpc, "udp"));
        if (cb_data->addr == NULL) {
                goto err;
        }
        
        cb_data->timeout_event = event_new(pmap->base, -1, 0, _timeout_cb, cb_data);
        if (cb_data->timeout_event == NULL) {
                goto err;
        }
        event_add(cb_data->timeout_event, &to);

        if (rpc_null_task(pmap->rpc, args->prog, args->vers,
                          _callit_cb, cb_data)) {
                return 0;
        }

        return 0;
 err:
        free_callit_cb_data(cb_data);
        return 0;
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
        PMAP2SETargs *args = call->body.cbody.args;
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
        write_db();
        return 0;
}

/*
 * v2 UNSET
 * This procedure is used to remove a registration from portmappers
 * list of endpoints.
 */
static int pmap2_unset_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP2UNSETargs *args = call->body.cbody.args;
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
        write_db();
        return 0;
}

/*
 * v2 CALLIT
 */
static int pmap2_callit_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        return pmapX_callit_proc(rpc, call, opaque, 2);
}

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
 * v3 SET
 */
static int pmap3_set_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP3UNSETargs *args = call->body.cbody.args;
        uint32_t response = 1;

        /* Don't update if we already have a mapping */
        if (map_lookup(args->prog, args->vers, args->netid)) {
                response = 0;
                rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
                return 0;
        }
        
        pmap_register(args->prog, args->vers, strdup(args->netid), strdup(args->addr),
                      strdup(args->owner));

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        write_db();
        return 0;
}

/*
 * v3 UNSET
 */
static int pmap3_unset_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP3UNSETargs *args = call->body.cbody.args;
        uint32_t response = 1;

        map_remove(args->prog, args->vers, args->netid);

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        write_db();
        return 0;
}

/*
 * v3 GETADDR
 */
static int pmap3_getaddr_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        PMAP3GETADDRargs *args = call->body.cbody.args;
        PMAP3GETADDRres res;
        struct mapping *map;

        res.addr = socket_to_str(rpc, args->netid);
        
        map = map_lookup(args->prog, args->vers, args->netid);
        if (map != NULL) {
                sprintf(res.addr + strlen(res.addr), ".%d.%d", map->port >> 8, map->port & 0xff);
        } else {
                return 0;
        }

        rpc_send_reply(rpc, call, &res, (zdrproc_t)zdr_PMAP3GETADDRres, sizeof(PMAP3GETADDRres));
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
                tmp_list->map.owner = tmp->owner;
                tmp_list->map.addr  = tmp->addr;
                
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
 * v3 CALLIT
 */
static int pmap3_callit_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        return pmapX_callit_proc(rpc, call, opaque, 3);
}


/*
 * v3 GETTIME
 */
static int pmap3_gettime_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        uint32_t response = time(NULL);

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        return 0;
}

/*
 * v3 U2T
 */
static int pmap3_u2t_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        PMAP3UADDR2TADDRargs *args = call->body.cbody.args;
        PMAP3UADDR2TADDRres res;
        char *ptr;
        int port = 0;

        ptr = rindex(args->addr, '.');
        if (ptr == 0) {
                return 0;
        }
        *ptr++ = 0;
        port = atoi(ptr);
        
        ptr = rindex(args->addr, '.');
        if (ptr == 0) {
                return 0;
        }
        *ptr++ = 0;
        port |= atoi(ptr) << 8;

        if (index(args->addr, ':')) {
                memset(&sin6, 0, sizeof(sin6));
                sin6.sin6_family = AF_INET6;
                sin6.sin6_port = htons(port);
                inet_pton(sin6.sin6_family, args->addr, &sin6.sin6_addr);
                res.maxlen = sizeof(struct sockaddr_in6);
                res.buf.buf_len = sizeof(struct sockaddr_in6);
                res.buf.buf_val = (char *)&sin6;
        } else {
                memset(&sin, 0, sizeof(sin));
                sin.sin_family = AF_INET;
                sin.sin_port = htons(port);
                inet_pton(sin.sin_family, args->addr, &sin.sin_addr);
                res.maxlen = sizeof(struct sockaddr_in);
                res.buf.buf_len = sizeof(struct sockaddr_in);
                res.buf.buf_val = (char *)&sin;
        }

        rpc_send_reply(rpc, call, &res, (zdrproc_t)zdr_PMAP3UADDR2TADDRres, sizeof(PMAP3UADDR2TADDRres));

        return 0;
}

/*
 * v3 T2U
 */
static int pmap3_t2u_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct sockaddr *sa;
        PMAP3TADDR2UADDRargs *args = call->body.cbody.args;
        PMAP3TADDR2UADDRres res;
        char addr[64] = {0}, *ptr;
        int port;
        
        sa = (struct sockaddr *)args->buf.buf_val;
        switch (sa->sa_family) {
        case AF_INET:
                inet_ntop(sa->sa_family, &((struct sockaddr_in *)sa)->sin_addr, addr, sizeof(addr));
                port = ((struct sockaddr_in *)sa)->sin_port;
                break;
        case AF_INET6:
                inet_ntop(sa->sa_family, &((struct sockaddr_in6 *)sa)->sin6_addr, addr, sizeof(addr));
                port = ((struct sockaddr_in6 *)sa)->sin6_port;
                break;
        }
        sprintf(&addr[strlen(addr)], ".%d.%d", port >> 8, port & 0xff); 

        res.addr = &addr[0];
        rpc_send_reply(rpc, call, &res, (zdrproc_t)zdr_PMAP3TADDR2UADDRres, sizeof(PMAP3TADDR2UADDRres));
        return 0;
}

/*
 * v4 CALLIT
 */
static int pmap4_callit_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        return pmapX_callit_proc(rpc, call, opaque, 4);
}


static void _callit_io(evutil_socket_t fd, short events, void *private_data)
{
        struct rpc_context *rpc = private_data;

        if (rpc_service(rpc, POLLIN) < 0) {
                return;
        }
}

int main(int argc, char *argv[])
{
        struct pmap_state pmap;
        struct libnfs_servers *servers;
        int rc = 1;

        struct service_proc pmap2_pt[] = {
                {PMAP2_NULL, pmap2_null_proc,
                 (zdrproc_t)zdr_void, 0, &pmap},
                {PMAP2_SET, pmap2_set_proc,
                 (zdrproc_t)zdr_PMAP2SETargs, sizeof(PMAP2SETargs), &pmap},
                {PMAP2_UNSET, pmap2_unset_proc,
                 (zdrproc_t)zdr_PMAP2UNSETargs, sizeof(PMAP2UNSETargs), &pmap},
                {PMAP2_GETPORT, pmap2_getport_proc,
                 (zdrproc_t)zdr_PMAP2GETPORTargs, sizeof(PMAP2GETPORTargs), &pmap},
                {PMAP2_DUMP, pmap2_dump_proc,
                 (zdrproc_t)zdr_void, 0, &pmap},
                {PMAP2_CALLIT, pmap2_callit_proc,
                 (zdrproc_t)zdr_PMAP2CALLITargs, sizeof(PMAP2CALLITargs), &pmap},
        };
        struct service_proc pmap3_pt[] = {
                {PMAP3_NULL, pmap3_null_proc,
                 (zdrproc_t)zdr_void, 0, &pmap},
                {PMAP3_SET, pmap3_set_proc,
                 (zdrproc_t)zdr_PMAP3SETargs, sizeof(PMAP3SETargs), &pmap},
                {PMAP3_UNSET, pmap3_unset_proc,
                 (zdrproc_t)zdr_PMAP3UNSETargs, sizeof(PMAP3UNSETargs), &pmap},
                {PMAP3_GETADDR, pmap3_getaddr_proc,
                 (zdrproc_t)zdr_PMAP3GETADDRargs, sizeof(PMAP3GETADDRargs), &pmap},
                {PMAP3_DUMP, pmap3_dump_proc,
                 (zdrproc_t)zdr_void, 0, &pmap},
                {PMAP3_CALLIT, pmap3_callit_proc,
                 (zdrproc_t)zdr_PMAP3CALLITargs, sizeof(PMAP3CALLITargs), &pmap},
                {PMAP3_GETTIME, pmap3_gettime_proc,
                 (zdrproc_t)zdr_void, 0, &pmap},
                {PMAP3_UADDR2TADDR, pmap3_u2t_proc,
                 (zdrproc_t)zdr_pmap3_string_result, sizeof(pmap3_string_result), &pmap},
                {PMAP3_TADDR2UADDR, pmap3_t2u_proc,
                 (zdrproc_t)zdr_PMAP3TADDR2UADDRargs, sizeof(PMAP3TADDR2UADDRargs), &pmap},
        };
        struct service_proc pmap4_pt[] = {
                {PMAP3_NULL, pmap3_null_proc,
                 (zdrproc_t)zdr_void, 0, &pmap},
                {PMAP3_SET, pmap3_set_proc,
                 (zdrproc_t)zdr_PMAP3SETargs, sizeof(PMAP3SETargs), &pmap},
                {PMAP3_UNSET, pmap3_unset_proc,
                 (zdrproc_t)zdr_PMAP3UNSETargs, sizeof(PMAP3UNSETargs), &pmap},
                {PMAP3_GETADDR, pmap3_getaddr_proc,
                 (zdrproc_t)zdr_PMAP3GETADDRargs, sizeof(PMAP3GETADDRargs), &pmap},
                {PMAP3_DUMP, pmap3_dump_proc,
                 (zdrproc_t)zdr_void, 0, &pmap},
                {PMAP4_BCAST, pmap4_callit_proc,
                 (zdrproc_t)zdr_PMAP3CALLITargs, sizeof(PMAP3CALLITargs), &pmap},
                {PMAP3_GETTIME, pmap3_gettime_proc,
                 (zdrproc_t)zdr_void, 0, &pmap},
                {PMAP3_UADDR2TADDR, pmap3_u2t_proc,
                 (zdrproc_t)zdr_pmap3_string_result, sizeof(pmap3_string_result), &pmap},
                {PMAP3_TADDR2UADDR, pmap3_t2u_proc,
                 (zdrproc_t)zdr_PMAP3TADDR2UADDRargs, sizeof(PMAP3TADDR2UADDRargs), &pmap},
                //{PMAP3_GETVERSADDR, pmap3_...},
                //{PMAP4_INDIRECT, pmap3_callit_proc,
                // (zdrproc_t)zdr_PMAP3CALLITargs, sizeof(PMAP3CALLITargs), &pmap},
                //{PMAP3_GETADDRLIST, pmap3_...},
                //{PMAP3_GETSTAT, pmap3_...},
        };
        struct libnfs_server_procs server_procs[] = {
                { PMAP_PROGRAM, PMAP_V2, pmap2_pt, sizeof(pmap2_pt) / sizeof(pmap2_pt[0]) },
                { PMAP_PROGRAM, PMAP_V3, pmap3_pt, sizeof(pmap3_pt) / sizeof(pmap3_pt[0]) },
                { PMAP_PROGRAM, PMAP_V4, pmap4_pt, sizeof(pmap4_pt) / sizeof(pmap4_pt[0]) },
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

        read_db();
        memset(&pmap, 0, sizeof(pmap));
        pmap.base = event_base_new();
        if (pmap.base == NULL) {
                printf("Failed create event context\n");
                goto out;
        }

        pmap.rpc = rpc_init_udp_context();
        if (pmap.rpc == NULL) {
                printf("Failed to create RPC context for outgoing callit calls\n");
                goto out;
        }
	if (rpc_bind_udp(pmap.rpc, "0.0.0.0", 0) < 0) {
                printf("Failed to bind RPC context\n");
                goto out;
	}
        pmap.read_event = event_new(pmap.base, rpc_get_fd(pmap.rpc), EV_READ|EV_PERSIST,
                               _callit_io, pmap.rpc);
        if (pmap.read_event == NULL) {
                printf("Failed to create read event for the callit socket\n");
                goto out;
	}
        event_add(pmap.read_event, NULL);


        servers = libnfs_create_server(pmap.base, 111, "libnfs rpcbind", &server_procs[0]);
        if (servers == NULL) {
                printf("Failed to set set up server\n");
                goto out;
        }
        printf("Ready to serve\n");
        daemon(0, 0);

        /*
         * Everything is now set up. Start the event loop.
         */
        event_base_dispatch(pmap.base);

        rc = 0;
 out:
        if (pmap.rpc) {
                rpc_destroy_context(pmap.rpc);
        }
        if (pmap.read_event) {
                event_free(pmap.read_event);
        }
        if (pmap.base) {
                event_base_free(pmap.base);
        }
        return rc;
}
