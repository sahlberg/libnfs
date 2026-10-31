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

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-portmap.h"
#include "../libnfs-server.h"

#include "rpcbind_data.h"

#define DBDIR "/var/run/rpcbind"
#define DBFILE DBDIR "/rpcbind.libnfs"
#define DBTMPFILE DBFILE ".tmp"
#define DBMAXSIZE (64 * 1024 * 1024)

/*
 * Portmapper implementation begins here
 */

struct pmap_state {
        struct tevent_context *tevent;
        struct rpc_context *rpc;
};

mapping_ptr map;


/*
 * Add a registration for program,version,netid.
 */
struct mapping *pmap_register(TALLOC_CTX *ctx,
                              int prog, int vers, char *netid, char *addr,
                              char *owner)
{
        struct mapping *item;
        char *str;
        int count = 0;

        item = talloc(ctx, struct mapping);
        if (item == NULL) {
                return NULL;
        }
        item->prog  = prog;
        item->vers  = vers;
        item->port  = 0;
        item->netid = talloc_strdup(item, netid);
        item->addr  = talloc_strdup(item, addr);
        item->owner = talloc_strdup(item, owner);
        if (item->netid == NULL || item->addr == NULL || item->owner == NULL) {
                talloc_free(item);
                return NULL;
        }

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

                        if (sscanf(str, ".%d.%d", &high, &low) == 2 &&
                            high >= 0 && high <= 255 &&
                            low >= 0 && low <= 255) {
                                item->port = high * 256 + low;
                        }
                        break;
                }
        }

        item->next  = map;
        map = item;

        return item;
}

/* Encoded size of a ZDR string */
static uint32_t zdr_string_size(const char *str)
{
        return 4 + ((strlen(str) + 3) & ~3);
}

struct rw_data {
        int f;
        char *buf;
        ZDR zdr;
};

static int rw_data_destructor(struct rw_data *rd)
{
        if (rd->f != -1) {
                close(rd->f);
        }
        zdr_destroy(&rd->zdr);
        return 0;
}

static void write_db(TALLOC_CTX *ctx)
{
        struct rw_data *rd;
        struct mapping *tmp;
        uint32_t size = 4;
        char *ptr;
        uint32_t len;

        for (tmp = map; tmp; tmp = tmp->next) {
                size += 16 + zdr_string_size(tmp->netid) +
                        zdr_string_size(tmp->addr) +
                        zdr_string_size(tmp->owner);
        }

        rd = talloc_zero(ctx, struct rw_data);
        if (rd == NULL) {
                return;
        }
        rd->f = -1;
        talloc_set_destructor(rd, rw_data_destructor);
        rd->buf = talloc_size(rd, size);
        if (rd->buf == NULL) {
                goto out;
        }
	zdrmem_create(&rd->zdr, rd->buf, size, ZDR_ENCODE);
        if (zdr_mapping_ptr(&rd->zdr, &map) == 0) {
                goto out;
        }

        /* Write a new file and rename it so the db is never truncated */
        rd->f = open(DBTMPFILE, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (rd->f == -1) {
                goto out;
        }
        ptr = zdr_getptr(&rd->zdr);
        len = zdr_getpos(&rd->zdr);
        while (len > 0) {
                ssize_t count = write(rd->f, ptr, len);

                if (count < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        goto err;
                }
                ptr += count;
                len -= count;
        }
        if (fsync(rd->f)) {
                goto err;
        }
        if (close(rd->f)) {
                rd->f = -1;
                goto err;
        }
        rd->f = -1;
        if (rename(DBTMPFILE, DBFILE)) {
                goto err;
        }
        goto out;

 err:
        unlink(DBTMPFILE);
 out:
        talloc_free(rd);
}

static void read_db(TALLOC_CTX *ctx)
{
        struct rw_data *rd;
        struct stat st;
        mapping_ptr tmpmap;
        off_t pos = 0;

        rd = talloc_zero(ctx, struct rw_data);
        if (rd == NULL) {
                return;
        }
        rd->f = -1;
        talloc_set_destructor(rd, rw_data_destructor);
        rd->f = open(DBFILE, O_RDONLY);
        if (rd->f == -1) {
                goto out;
        }
        if (fstat(rd->f, &st)) {
                goto out;
        }
        if (st.st_size == 0 || st.st_size > DBMAXSIZE) {
                goto out;
        }
        rd->buf = talloc_size(rd, st.st_size);
        if (rd->buf == NULL) {
                goto out;
        }
        while (pos < st.st_size) {
                ssize_t count = read(rd->f, rd->buf + pos, st.st_size - pos);

                if (count < 0 && errno == EINTR) {
                        continue;
                }
                if (count <= 0) {
                        goto out;
                }
                pos += count;
        }

	zdrmem_create(&rd->zdr, rd->buf, st.st_size, ZDR_DECODE);
        if (zdr_mapping_ptr(&rd->zdr, &tmpmap) == 0) {
                goto out;
        }
        while(tmpmap) {
                pmap_register(ctx,
                              tmpmap->prog,
                              tmpmap->vers,
                              tmpmap->netid,
                              tmpmap->addr,
                              tmpmap->owner);
                tmpmap = tmpmap->next;
        }
 out:
        talloc_free(rd);
}

static char *socket_to_str(struct rpc_context *rpc, char *netid)
{
        static char addr[64] = {0}, *ptr;
        struct sockaddr_storage ss;
        struct sockaddr *sa;
        const void *in;

        if (rpc_is_udp_socket(rpc)) {
                sa = rpc_get_udp_dst_sockaddr(rpc);
        } else {
                socklen_t ss_len = sizeof(struct sockaddr_storage);

                /*
                 * Came in through TCP so whatever is the local address we accept()ed on
                 * should be good enough.
                 */
                if (getsockname(rpc_get_fd(rpc), (struct sockaddr *)&ss, &ss_len)) {
                        return NULL;
                }
                sa = (struct sockaddr *)&ss;
        }
        switch (sa->sa_family) {
        case AF_INET:
                in = &((struct sockaddr_in *)sa)->sin_addr;
                break;
        case AF_INET6:
                in = &((struct sockaddr_in6 *)sa)->sin6_addr;
                break;
        default:
                return NULL;
        }
        if (inet_ntop(sa->sa_family, in, addr, sizeof(addr)) == NULL) {
                return NULL;
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
 * Find and return a registration matching program,version,netid.
 */
struct mapping *map_lookup(struct pmap_state *pmap, int prog, int vers, char *netid)
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
void map_remove(struct pmap_state *pmap, int prog, int vers, char *netid)
{
        struct mapping *new_map = NULL;
        struct mapping *tmp, *next;

        for (tmp = map; tmp; tmp = next) {
                next = tmp->next;
                if (tmp->prog != prog ||
                    tmp->vers != vers ||
                    (netid && netid[0] && strcmp(tmp->netid, netid))) {
                            tmp->next = new_map;
                            new_map = tmp;
                            continue;
                }
                talloc_free(tmp);
        }
        map = new_map;
        return;
}


struct callit_data {
        struct rpc_context *rpc;
        struct rpc_context *client_rpc;
        struct rpc_msg *call;
        struct rpc_pdu *pdu;
        struct tevent_timer *timeout_event;
        int pmap_vers;
        int port;
        char *addr;
};

static int callit_destructor(struct callit_data *cb_data)
{
        if (cb_data->call) {
                rpc_free_deferred_call(cb_data->rpc, cb_data->call);
        }
        return 0;
}

static void _timeout_cb(struct tevent_context *ev, struct tevent_timer *te,
                        struct timeval current_time, void *private_data)
{
        struct callit_data *cb_data = private_data;

        rpc_cancel_pdu(cb_data->client_rpc, cb_data->pdu);
        talloc_free(cb_data);
}

static void _callit_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
        struct callit_data *cb_data = private_data;
        uint32_t response = status;

        /* No reply on error */
        /* TODO: v4 indirect do return error */
        if (status != RPC_STATUS_SUCCESS) {
                talloc_free(cb_data);
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
        
        talloc_free(cb_data);
}

/*
 * This is an example on how to make a temp copy of struct rpc_msg *call
 * that we can use later to invoke rpc_send_reply() from a different context.
 */
static int pmapX_callit_proc(struct pmap_state *pmap, struct rpc_context *rpc, struct rpc_msg *call, int pmap_vers)
{
        PMAP3CALLITargs *args = call->body.cbody.args;
        struct callit_data *cb_data = NULL;
        struct mapping *map;
        struct timeval to = tevent_timeval_current_ofs(3, 0);

        /* Only support callit for NULL procedure. */
        if (args->proc != 0) {
                return 0;
        }
        /* The deferred reply must not outlive a TCP connection */
        if (!rpc_is_udp_socket(rpc)) {
                return 0;
        }

        map = map_lookup(pmap, args->prog, args->vers, "udp");
        if (map == NULL) {
                goto err;
        }

        if (rpc_set_udp_destination(pmap->rpc, "127.0.0.1", map->port, 0) < 0) {
                printf("Failed to set udp destination\n");
                goto err;
        }
        cb_data = talloc(pmap, struct callit_data);
        if (cb_data == NULL) {
                goto err;
        }
        talloc_set_destructor(cb_data, callit_destructor);
        cb_data->rpc = rpc;
        cb_data->client_rpc = pmap->rpc;
        cb_data->pmap_vers = pmap_vers;
        cb_data->call = rpc_copy_deferred_call(rpc, call);
        if (cb_data->call == NULL) {
                goto err;
        }
        cb_data->port = map->port;
        cb_data->addr = talloc_strdup(cb_data, socket_to_str(rpc, "udp"));
        if (cb_data->addr == NULL) {
                goto err;
        }
        
        cb_data->timeout_event = tevent_add_timer(pmap->tevent, cb_data, to, _timeout_cb, cb_data);
        if (cb_data->timeout_event == NULL) {
                goto err;
        }

        cb_data->pdu = rpc_null_task(pmap->rpc, args->prog, args->vers,
                                     _callit_cb, cb_data);
        if (cb_data->pdu == NULL) {
                goto err;
        }

        return 0;
 err:
        talloc_free(cb_data);
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
        struct pmap_state *pmap = opaque;
        PMAP2GETPORTargs *args = call->body.cbody.args;
        struct mapping *tmp;
        char *netid;
        uint32_t port = 0;

        if (args->prot == IPPROTO_TCP) {
                netid = "tcp";
        } else {
                netid = "udp";
        }

        tmp = map_lookup(pmap, args->prog, args->vers, netid);
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
        TALLOC_CTX *tmp_ctx = talloc_new(NULL);
        int size = 4;

        if (tmp_ctx == NULL) {
                return 0;
        }
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
                      
                tmp_list = talloc(tmp_ctx, struct pmap2_mapping_list);
                if (tmp_list == NULL) {
                        goto out;
                }
                tmp_list->map.prog  = tmp->prog;
                tmp_list->map.vers  = tmp->vers;
                tmp_list->map.prot  = proto;
                tmp_list->map.port  = tmp->port;

                tmp_list->next = reply.list;

                reply.list = tmp_list;
                size += 20;
        }

        rpc_send_reply(rpc, call, &reply,
                       (zdrproc_t)zdr_PMAP2DUMPres, size);
 out:

        talloc_free(tmp_ctx);
        return 0;
}


/*
 * v2 SET
 * This procedure is used to register and endpoint with portmapper.
 */
static int pmap2_set_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct pmap_state *pmap = opaque;
        PMAP2SETargs *args = call->body.cbody.args;
        char *prot;
        char addr[24];
        uint32_t response = 1;

        if (args->prot == IPPROTO_TCP) {
                prot = "tcp";
        } else {
                prot = "udp";
        }

        /* Don't update if we already have a mapping */
        if (map_lookup(pmap, args->prog, args->vers, prot)) {
                response = 0;
                rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
                return 0;
        }
        
        snprintf(addr, sizeof(addr), "0.0.0.0.%d.%d",
                 args->port >> 8, args->port & 0xff);
        if (args->port > 65535 ||
            pmap_register(pmap, args->prog, args->vers, prot, addr,
                          "<unknown>") == NULL) {
                response = 0;
                rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
                return 0;
        }

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        write_db(pmap);
        return 0;
}

/*
 * v2 UNSET
 * This procedure is used to remove a registration from portmappers
 * list of endpoints.
 */
static int pmap2_unset_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct pmap_state *pmap = opaque;
        PMAP2UNSETargs *args = call->body.cbody.args;
        char *prot;
        char *addr;
        uint32_t response = 1;

        if (args->prot == IPPROTO_TCP) {
                prot = "tcp";
        } else {
                prot = "udp";
        }

        map_remove(pmap, args->prog, args->vers, prot);

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        write_db(pmap);
        return 0;
}

/*
 * v2 CALLIT
 */
static int pmap2_callit_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct pmap_state *pmap = opaque;
        return pmapX_callit_proc(pmap, rpc, call, 2);
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
        struct pmap_state *pmap = opaque;
        PMAP3UNSETargs *args = call->body.cbody.args;
        uint32_t response = 1;

        /* Don't update if we already have a mapping */
        if (map_lookup(pmap, args->prog, args->vers, args->netid)) {
                response = 0;
                rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
                return 0;
        }
        
        if (pmap_register(pmap, args->prog, args->vers, args->netid,
                          args->addr, args->owner) == NULL) {
                response = 0;
                rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
                return 0;
        }

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        write_db(pmap);
        return 0;
}

/*
 * v3 UNSET
 */
static int pmap3_unset_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct pmap_state *pmap = opaque;
        PMAP3UNSETargs *args = call->body.cbody.args;
        uint32_t response = 1;

        map_remove(pmap, args->prog, args->vers, args->netid);

        rpc_send_reply(rpc, call, &response, (zdrproc_t)zdr_uint32_t, sizeof(uint32_t));
        write_db(pmap);
        return 0;
}

/*
 * v3 GETADDR
 */
static int pmap3_getaddr_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct pmap_state *pmap = opaque;
        PMAP3GETADDRargs *args = call->body.cbody.args;
        PMAP3GETADDRres res;
        struct mapping *map;
        char addr[64] = {0};
        char *str;

        /* An empty address means the program is not registered */
        map = map_lookup(pmap, args->prog, args->vers, args->netid);
        str = socket_to_str(rpc, args->netid);
        if (map != NULL && str != NULL) {
                snprintf(addr, sizeof(addr), "%s.%d.%d", str,
                         map->port >> 8, map->port & 0xff);
        }
        res.addr = addr;

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
        TALLOC_CTX *tmp_ctx = talloc_new(NULL);
        int size = 4;

        if (tmp_ctx == NULL) {
                return 0;
        }
        reply.list = NULL;
        for (tmp = map; tmp; tmp = tmp->next) {
                struct pmap3_mapping_list *tmp_list;

                tmp_list = talloc(tmp_ctx, struct pmap3_mapping_list);
                if (tmp_list == NULL) {
                        goto out;
                }
                size += 12 + zdr_string_size(tmp->netid) +
                        zdr_string_size(tmp->addr) +
                        zdr_string_size(tmp->owner);
                tmp_list->map.prog  = tmp->prog;
                tmp_list->map.vers  = tmp->vers;
                tmp_list->map.netid = tmp->netid;
                tmp_list->map.owner = tmp->owner;
                tmp_list->map.addr  = tmp->addr;
                
                tmp_list->next = reply.list;

                reply.list = tmp_list;
        }

        rpc_send_reply(rpc, call, &reply,
                       (zdrproc_t)zdr_PMAP3DUMPres, size);
 out:
        talloc_free(tmp_ctx);
        return 0;
}

/*
 * v3 CALLIT
 */
static int pmap3_callit_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct pmap_state *pmap = opaque;
        return pmapX_callit_proc(pmap, rpc, call, 3);
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
        PMAP3TADDR2UADDRargs *args = call->body.cbody.args;
        PMAP3TADDR2UADDRres res;
        struct sockaddr_storage ss;
        char addr[64] = {0};
        const void *in = NULL;
        int port = 0;

        /* Copy so a short netbuf can not be read past its end */
        memset(&ss, 0, sizeof(ss));
        if (args->buf.buf_len > 0 && args->buf.buf_len <= sizeof(ss)) {
                memcpy(&ss, args->buf.buf_val, args->buf.buf_len);
        }
        switch (ss.ss_family) {
        case AF_INET:
                if (args->buf.buf_len >= sizeof(struct sockaddr_in)) {
                        in = &((struct sockaddr_in *)&ss)->sin_addr;
                        port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
                }
                break;
        case AF_INET6:
                if (args->buf.buf_len >= sizeof(struct sockaddr_in6)) {
                        in = &((struct sockaddr_in6 *)&ss)->sin6_addr;
                        port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
                }
                break;
        }
        if (in && inet_ntop(ss.ss_family, in, addr, sizeof(addr))) {
                size_t len = strlen(addr);

                snprintf(&addr[len], sizeof(addr) - len, ".%d.%d",
                         port >> 8, port & 0xff);
        } else {
                addr[0] = 0;
        }

        res.addr = &addr[0];
        rpc_send_reply(rpc, call, &res, (zdrproc_t)zdr_PMAP3TADDR2UADDRres, sizeof(PMAP3TADDR2UADDRres));
        return 0;
}

/*
 * v4 CALLIT
 */
static int pmap4_callit_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        struct pmap_state *pmap = opaque;
        return pmapX_callit_proc(pmap, rpc, call, 4);
}


static void _callit_io(struct tevent_context *ev, struct tevent_fd *fde, uint16_t flags, void *private_data)
{
        struct rpc_context *rpc = private_data;

        if (rpc_service(rpc, POLLIN) < 0) {
                return;
        }
}

static int pmap_destructor(struct pmap_state *pmap)
{
        if (pmap->rpc) {
                rpc_destroy_context(pmap->rpc);
        }
        return 0;
}

int main(int argc, char *argv[])
{
        struct pmap_state *pmap = talloc(NULL, struct pmap_state);
        struct libnfs_servers *servers;
        int rc = 1;

        struct service_proc pmap2_pt[] = {
                {PMAP2_NULL, pmap2_null_proc,
                 (zdrproc_t)zdr_void, 0, pmap},
                {PMAP2_SET, pmap2_set_proc,
                 (zdrproc_t)zdr_PMAP2SETargs, sizeof(PMAP2SETargs), pmap},
                {PMAP2_UNSET, pmap2_unset_proc,
                 (zdrproc_t)zdr_PMAP2UNSETargs, sizeof(PMAP2UNSETargs), pmap},
                {PMAP2_GETPORT, pmap2_getport_proc,
                 (zdrproc_t)zdr_PMAP2GETPORTargs, sizeof(PMAP2GETPORTargs), pmap},
                {PMAP2_DUMP, pmap2_dump_proc,
                 (zdrproc_t)zdr_void, 0, pmap},
                {PMAP2_CALLIT, pmap2_callit_proc,
                 (zdrproc_t)zdr_PMAP2CALLITargs, sizeof(PMAP2CALLITargs), pmap},
        };
        struct service_proc pmap3_pt[] = {
                {PMAP3_NULL, pmap3_null_proc,
                 (zdrproc_t)zdr_void, 0, pmap},
                {PMAP3_SET, pmap3_set_proc,
                 (zdrproc_t)zdr_PMAP3SETargs, sizeof(PMAP3SETargs), pmap},
                {PMAP3_UNSET, pmap3_unset_proc,
                 (zdrproc_t)zdr_PMAP3UNSETargs, sizeof(PMAP3UNSETargs), pmap},
                {PMAP3_GETADDR, pmap3_getaddr_proc,
                 (zdrproc_t)zdr_PMAP3GETADDRargs, sizeof(PMAP3GETADDRargs), pmap},
                {PMAP3_DUMP, pmap3_dump_proc,
                 (zdrproc_t)zdr_void, 0, pmap},
                {PMAP3_CALLIT, pmap3_callit_proc,
                 (zdrproc_t)zdr_PMAP3CALLITargs, sizeof(PMAP3CALLITargs), pmap},
                {PMAP3_GETTIME, pmap3_gettime_proc,
                 (zdrproc_t)zdr_void, 0, pmap},
                {PMAP3_UADDR2TADDR, pmap3_u2t_proc,
                 (zdrproc_t)zdr_pmap3_string_result, sizeof(pmap3_string_result), pmap},
                {PMAP3_TADDR2UADDR, pmap3_t2u_proc,
                 (zdrproc_t)zdr_PMAP3TADDR2UADDRargs, sizeof(PMAP3TADDR2UADDRargs), pmap},
        };
        struct service_proc pmap4_pt[] = {
                {PMAP3_NULL, pmap3_null_proc,
                 (zdrproc_t)zdr_void, 0, pmap},
                {PMAP3_SET, pmap3_set_proc,
                 (zdrproc_t)zdr_PMAP3SETargs, sizeof(PMAP3SETargs), pmap},
                {PMAP3_UNSET, pmap3_unset_proc,
                 (zdrproc_t)zdr_PMAP3UNSETargs, sizeof(PMAP3UNSETargs), pmap},
                {PMAP3_GETADDR, pmap3_getaddr_proc,
                 (zdrproc_t)zdr_PMAP3GETADDRargs, sizeof(PMAP3GETADDRargs), pmap},
                {PMAP3_DUMP, pmap3_dump_proc,
                 (zdrproc_t)zdr_void, 0, pmap},
                {PMAP4_BCAST, pmap4_callit_proc,
                 (zdrproc_t)zdr_PMAP3CALLITargs, sizeof(PMAP3CALLITargs), pmap},
                {PMAP3_GETTIME, pmap3_gettime_proc,
                 (zdrproc_t)zdr_void, 0, pmap},
                {PMAP3_UADDR2TADDR, pmap3_u2t_proc,
                 (zdrproc_t)zdr_pmap3_string_result, sizeof(pmap3_string_result), pmap},
                {PMAP3_TADDR2UADDR, pmap3_t2u_proc,
                 (zdrproc_t)zdr_PMAP3TADDR2UADDRargs, sizeof(PMAP3TADDR2UADDRargs), pmap},
                //{PMAP3_GETVERSADDR, pmap3_...},
                //{PMAP4_INDIRECT, pmap3_callit_proc,
                // (zdrproc_t)zdr_PMAP3CALLITargs, sizeof(PMAP3CALLITargs), pmap},
                //{PMAP3_GETADDRLIST, pmap3_...},
                //{PMAP3_GETSTAT, pmap3_...},
        };
        struct libnfs_server_procs server_procs[] = {
                { PMAP_PROGRAM, PMAP_V2, pmap2_pt, sizeof(pmap2_pt) / sizeof(pmap2_pt[0]) },
                { PMAP_PROGRAM, PMAP_V3, pmap3_pt, sizeof(pmap3_pt) / sizeof(pmap3_pt[0]) },
                { PMAP_PROGRAM, PMAP_V4, pmap4_pt, sizeof(pmap4_pt) / sizeof(pmap4_pt[0]) },
                { 0, 0, 0, 0}
        };
        
        if (pmap == NULL) {
                printf("Failed to talloc pmap\n");
                goto out;
        }
        pmap->rpc = NULL;

        mkdir(DBDIR, 0700);
        read_db(pmap);

        pmap->tevent = tevent_context_init(pmap);
        if (pmap->tevent == NULL) {
                printf("Failed create tevent context\n");
                goto out;
        }
        talloc_set_destructor(pmap, pmap_destructor);

        pmap->rpc = rpc_init_udp_context();
        if (pmap->rpc == NULL) {
                printf("Failed to create RPC context for outgoing callit calls\n");
                goto out;
        }
	if (rpc_bind_udp(pmap->rpc, "0.0.0.0", 0) < 0) {
                printf("Failed to bind RPC context\n");
                goto out;
	}

        if (tevent_add_fd(pmap->tevent, pmap, rpc_get_fd(pmap->rpc), TEVENT_FD_READ,
                          _callit_io, pmap->rpc) == NULL) {
                printf("Failed to create read event for the callit socket\n");
                goto out;
	}

        servers = libnfs_create_server(pmap, pmap->tevent, 111, "libnfs rpcbind",
                                       TRANSPORT_TCP | TRANSPORT_TCP6 | TRANSPORT_UDP | TRANSPORT_UDP6,
                                       &server_procs[0]);
        if (servers == NULL) {
                printf("Failed to set set up server\n");
                goto out;
        }
        printf("Ready to serve\n");
        //qqq daemon(0, 1);

        /*
         * Everything is now set up. Start the event loop.
         */
        tevent_loop_wait(pmap->tevent);

        rc = 0;
 out:
        talloc_free(pmap);
        return rc;
}
