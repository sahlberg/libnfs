/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
/* RPC-over-RDMA version 1 (RFC 8166) client, inline sizes from RFC 8797 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define RPCRDMA_VERSION         1

#define RDMA_MSG                0
#define RDMA_NOMSG              1
#define RDMA_ERROR              4

#define ERR_VERS                1
#define ERR_CHUNK               2

/* Requests in flight, also the credits we ask the server for */
#define RPCRDMA_SLOTS           32
/* Spare receives so a reply can be processed before its buffer is reposted */
#define RPCRDMA_RECVS           (RPCRDMA_SLOTS + 2)
#define RPCRDMA_MIN_INLINE      1024
#define RPCRDMA_INLINE          4096
/* Coalesces the small pieces of a long call */
#define RPCRDMA_CALL_SIZE       4096
/* Reply chunk for everything except READ data */
#define RPCRDMA_REPLY_SIZE      (64 * 1024)
#define RPCRDMA_MAX_SEGS        16
#define RPCRDMA_TIMEOUT_MS      5000

#define RPCRDMA_CMP_MAGIC       0xf6ab0e18
#define RPCRDMA_CMP_VERSION     1

enum rdma_state {
        RDMA_ST_ADDR = 0,
        RDMA_ST_ROUTE,
        RDMA_ST_CONNECTING,
        RDMA_ST_CONNECTED,
        RDMA_ST_DEAD,
};

struct rpc_rdma_slot {
        struct rpc_pdu *pdu;
        int in_use;
        int send_pending;
        char *send_buf;
        char *call_buf;
        char *reply_buf;
        struct ibv_mr *call_mr;
        struct ibv_mr *reply_mr;
        /* Reply buffer for a READ that can not use a Write chunk */
        char *big_reply;
        struct ibv_mr *big_reply_mr;
        uint32_t reply_size;
        /* A long call with too many pieces to list, as one buffer */
        char *flat_call;
        /* Caller memory registered for this call */
        struct ibv_mr *mrs[RPCRDMA_MAX_SEGS * 2];
        int nmrs;
};

struct rpc_rdma {
        enum rdma_state state;
        struct rdma_event_channel *ch;
        struct rdma_cm_id *id;
        struct ibv_pd *pd;
        struct ibv_comp_channel *cc;
        struct ibv_cq *cq;
        int has_qp;
        char *pool;
        struct ibv_mr *pool_mr;
        char *recv_bufs;
        uint32_t credits;
        uint32_t outstanding;
        uint32_t inline_send;
        struct rpc_rdma_slot slots[RPCRDMA_SLOTS];
};

static void
rpc_lock(struct rpc_context *rpc)
{
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
}

static void
rpc_unlock(struct rpc_context *rpc)
{
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
}

static void
rdma_lock(struct rpc_context *rpc)
{
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rdma_mutex);
        }
#endif /* HAVE_MULTITHREADING */
}

static void
rdma_unlock(struct rpc_context *rpc)
{
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rdma_mutex);
        }
#endif /* HAVE_MULTITHREADING */
}

static int
rdma_epoll_add(struct rpc_context *rpc, int fd)
{
        struct epoll_event ev;
        int flags;

        flags = fcntl(fd, F_GETFL);
        if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
                return -1;
        }
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        return epoll_ctl(rpc->fd, EPOLL_CTL_ADD, fd, &ev);
}

static void
rdma_epoll_del(struct rpc_context *rpc, int fd)
{
        if (rpc->fd != -1) {
                epoll_ctl(rpc->fd, EPOLL_CTL_DEL, fd, NULL);
        }
}

/* Called with rdma_mutex held */
static void
slot_unregister(struct rpc_rdma_slot *slot)
{
        int i;

        for (i = 0; i < slot->nmrs; i++) {
                ibv_dereg_mr(slot->mrs[i]);
        }
        slot->nmrs = 0;
}

/* Called with rdma_mutex held */
static void
slot_release(struct rpc_rdma_slot *slot)
{
        slot_unregister(slot);
        if (slot->big_reply_mr) {
                ibv_dereg_mr(slot->big_reply_mr);
                slot->big_reply_mr = NULL;
        }
        free(slot->big_reply);
        slot->big_reply = NULL;
        free(slot->flat_call);
        slot->flat_call = NULL;
        if (slot->pdu) {
                slot->pdu->rdma_slot = NULL;
                slot->pdu = NULL;
        }
        slot->in_use = 0;
}

void
rpc_rdma_release_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        rdma_lock(rpc);
        if (pdu->rdma_slot) {
                slot_release(pdu->rdma_slot);
        }
        pdu->rdma_slot = NULL;
        rdma_unlock(rpc);
}

static int
rdma_post_recv(struct rpc_rdma *r, uint32_t idx)
{
        struct ibv_recv_wr wr, *bad;
        struct ibv_sge sge;

        sge.addr = (uintptr_t)(r->recv_bufs + idx * RPCRDMA_INLINE);
        sge.length = RPCRDMA_INLINE;
        sge.lkey = r->pool_mr->lkey;
        memset(&wr, 0, sizeof(wr));
        wr.wr_id = RPCRDMA_SLOTS + idx;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        return ibv_post_recv(r->id->qp, &wr, &bad);
}

void
rpc_rdma_teardown(struct rpc_context *rpc)
{
        struct rpc_rdma *r;
        int i;

        rdma_lock(rpc);
        r = rpc->rdma;
        if (r == NULL) {
                rdma_unlock(rpc);
                return;
        }
        rpc->rdma = NULL;
        rpc->rdma_gen++;
        for (i = 0; i < RPCRDMA_SLOTS; i++) {
                slot_release(&r->slots[i]);
        }
        rdma_unlock(rpc);

        if (r->state == RDMA_ST_CONNECTED) {
                rdma_disconnect(r->id);
        }
        if (r->has_qp) {
                rdma_destroy_qp(r->id);
        }
        for (i = 0; i < RPCRDMA_SLOTS; i++) {
                if (r->slots[i].call_mr) {
                        ibv_dereg_mr(r->slots[i].call_mr);
                }
                if (r->slots[i].reply_mr) {
                        ibv_dereg_mr(r->slots[i].reply_mr);
                }
        }
        if (r->pool_mr) {
                ibv_dereg_mr(r->pool_mr);
        }
        free(r->pool);
        if (r->cq) {
                ibv_destroy_cq(r->cq);
        }
        if (r->cc) {
                rdma_epoll_del(rpc, r->cc->fd);
                ibv_destroy_comp_channel(r->cc);
        }
        if (r->pd) {
                ibv_dealloc_pd(r->pd);
        }
        if (r->id) {
                rdma_destroy_id(r->id);
        }
        if (r->ch) {
                rdma_epoll_del(rpc, r->ch->fd);
                rdma_destroy_event_channel(r->ch);
        }
        free(r);
}

int
rpc_rdma_connect(struct rpc_context *rpc)
{
        struct rpc_rdma *r;
        int err;

        rpc_rdma_teardown(rpc);

        if (rpc->fd == -1) {
                rpc->fd = epoll_create1(EPOLL_CLOEXEC);
                if (rpc->fd == -1) {
                        rpc->connect_errno = errno;
                        rpc_set_error(rpc, "epoll_create1() failed: %s",
                                      strerror(errno));
                        return -1;
                }
        }
        if (rpc->ifname[0]) {
                RPC_LOG(rpc, 1, "if=%s is ignored for RDMA", rpc->ifname);
        }

        r = calloc(1, sizeof(*r));
        if (r == NULL) {
                rpc_set_error(rpc, "Failed to allocate RDMA transport");
                return -1;
        }
        r->state = RDMA_ST_ADDR;
        r->credits = 1;
        r->inline_send = RPCRDMA_MIN_INLINE;
        rdma_lock(rpc);
        rpc->rdma = r;
        rdma_unlock(rpc);

        r->ch = rdma_create_event_channel();
        if (r->ch == NULL || rdma_epoll_add(rpc, r->ch->fd) != 0 ||
            rdma_create_id(r->ch, &r->id, rpc, RDMA_PS_TCP) != 0 ||
            rdma_resolve_addr(r->id, NULL, (struct sockaddr *)&rpc->s,
                              RPCRDMA_TIMEOUT_MS) != 0) {
                err = errno;
                rpc_rdma_teardown(rpc);
                rpc->connect_errno = err;
                rpc_set_error(rpc, "RDMA connect to %s failed: %s",
                              rpc->server ? rpc->server : "server",
                              strerror(err));
                return -1;
        }
        return 0;
}

static enum rpc_rdma_event
rdma_dead(struct rpc_context *rpc, int e, int *err)
{
        struct rpc_rdma *r = rpc->rdma;
        int was_connected = r->state == RDMA_ST_CONNECTED;

        r->state = RDMA_ST_DEAD;
        if (r->cc) {
                rdma_epoll_del(rpc, r->cc->fd);
        }
        rdma_epoll_del(rpc, r->ch->fd);
        *err = e;
        return was_connected ? RPC_RDMA_EV_DISCONNECTED :
                RPC_RDMA_EV_CONNECT_FAILED;
}

static int
setup_failed(struct rpc_context *rpc, const char *what)
{
        int e = errno;

        rpc_set_error(rpc, "%s failed: %s", what, strerror(e));
        return e ? e : EIO;
}

/* Returns 0 or the errno of the step that failed */
static int
rdma_setup(struct rpc_context *rpc, struct rpc_rdma *r)
{
        struct ibv_qp_init_attr attr;
        struct rdma_conn_param param;
        struct ibv_device_attr dattr;
        uint8_t pdata[8];
        uint32_t magic = htonl(RPCRDMA_CMP_MAGIC);
        size_t local_size, remote_size;
        char *remote;
        int i, e;

        r->pd = ibv_alloc_pd(r->id->verbs);
        if (r->pd == NULL) {
                return setup_failed(rpc, "ibv_alloc_pd()");
        }
        r->cc = ibv_create_comp_channel(r->id->verbs);
        if (r->cc == NULL || rdma_epoll_add(rpc, r->cc->fd) != 0) {
                return setup_failed(rpc, "Setting up the completion channel");
        }
        r->cq = ibv_create_cq(r->id->verbs, RPCRDMA_SLOTS + RPCRDMA_RECVS,
                              NULL, r->cc, 0);
        if (r->cq == NULL || ibv_req_notify_cq(r->cq, 0) != 0) {
                return setup_failed(rpc, "Setting up the completion queue");
        }

        memset(&attr, 0, sizeof(attr));
        attr.send_cq = r->cq;
        attr.recv_cq = r->cq;
        attr.qp_type = IBV_QPT_RC;
        attr.cap.max_send_wr = RPCRDMA_SLOTS;
        attr.cap.max_recv_wr = RPCRDMA_RECVS;
        attr.cap.max_send_sge = 1;
        attr.cap.max_recv_sge = 1;
        if (rdma_create_qp(r->id, r->pd, &attr) != 0) {
                return setup_failed(rpc, "rdma_create_qp()");
        }
        r->has_qp = 1;

        local_size = (RPCRDMA_SLOTS + RPCRDMA_RECVS) * RPCRDMA_INLINE;
        remote_size = RPCRDMA_SLOTS * (RPCRDMA_CALL_SIZE + RPCRDMA_REPLY_SIZE);
        if (posix_memalign((void **)&r->pool, 4096, local_size + remote_size) != 0) {
                r->pool = NULL;
                rpc_set_error(rpc, "Failed to allocate RDMA buffers");
                return ENOMEM;
        }
        r->pool_mr = ibv_reg_mr(r->pd, r->pool, local_size,
                                IBV_ACCESS_LOCAL_WRITE);
        if (r->pool_mr == NULL) {
                goto reg_failed;
        }
        r->recv_bufs = r->pool + RPCRDMA_SLOTS * RPCRDMA_INLINE;
        remote = r->pool + local_size;
        for (i = 0; i < RPCRDMA_SLOTS; i++) {
                struct rpc_rdma_slot *slot = &r->slots[i];

                slot->send_buf = r->pool + i * RPCRDMA_INLINE;
                slot->call_buf = remote + i * (RPCRDMA_CALL_SIZE + RPCRDMA_REPLY_SIZE);
                slot->reply_buf = slot->call_buf + RPCRDMA_CALL_SIZE;
                slot->call_mr = ibv_reg_mr(r->pd, slot->call_buf,
                                           RPCRDMA_CALL_SIZE,
                                           IBV_ACCESS_REMOTE_READ);
                slot->reply_mr = ibv_reg_mr(r->pd, slot->reply_buf,
                                            RPCRDMA_REPLY_SIZE,
                                            IBV_ACCESS_LOCAL_WRITE |
                                            IBV_ACCESS_REMOTE_WRITE);
                if (slot->call_mr == NULL || slot->reply_mr == NULL) {
                        goto reg_failed;
                }
        }
        for (i = 0; i < RPCRDMA_RECVS; i++) {
                if (rdma_post_recv(r, i) != 0) {
                        return setup_failed(rpc, "ibv_post_recv()");
                }
        }

        memcpy(pdata, &magic, 4);
        pdata[4] = RPCRDMA_CMP_VERSION;
        pdata[5] = 0;
        pdata[6] = (RPCRDMA_INLINE >> 10) - 1;
        pdata[7] = (RPCRDMA_INLINE >> 10) - 1;

        memset(&param, 0, sizeof(param));
        param.private_data = pdata;
        param.private_data_len = sizeof(pdata);
        /* The server RDMA Reads our long calls */
        if (ibv_query_device(r->id->verbs, &dattr) == 0) {
                param.responder_resources = dattr.max_qp_rd_atom > 255 ?
                        255 : dattr.max_qp_rd_atom;
        }
        param.initiator_depth = 0;
        param.retry_count = 6;
        if (rdma_connect(r->id, &param) != 0) {
                return setup_failed(rpc, "rdma_connect()");
        }
        r->state = RDMA_ST_CONNECTING;
        return 0;

 reg_failed:
        e = errno;
        rpc_set_error(rpc, "Failed to register RDMA buffers: %s. "
                      "RLIMIT_MEMLOCK may be too low", strerror(e));
        return e ? e : ENOMEM;
}

static void
rdma_established(struct rpc_context *rpc, struct rpc_rdma *r,
                 const uint8_t *pdata, int plen)
{
        uint32_t magic;

        if (plen >= 8) {
                memcpy(&magic, pdata, 4);
                if (ntohl(magic) == RPCRDMA_CMP_MAGIC &&
                    pdata[4] == RPCRDMA_CMP_VERSION) {
                        uint32_t server_recv = (pdata[7] + 1) << 10;

                        r->inline_send = server_recv < RPCRDMA_INLINE ?
                                server_recv : RPCRDMA_INLINE;
                }
        }
        r->state = RDMA_ST_CONNECTED;
        r->credits = 1;
        r->outstanding = 0;
        RPC_LOG(rpc, 2, "RDMA connected, inline send size %u",
                r->inline_send);
}

static enum rpc_rdma_event
rdma_service_cm(struct rpc_context *rpc, int *err)
{
        struct rpc_rdma *r = rpc->rdma;
        struct rdma_cm_event *event;
        enum rdma_cm_event_type type;
        uint8_t pdata[8];
        int status, plen, e;

        while (rdma_get_cm_event(r->ch, &event) == 0) {
                type = event->event;
                status = event->status;
                plen = 0;
                if (type == RDMA_CM_EVENT_ESTABLISHED &&
                    event->param.conn.private_data &&
                    event->param.conn.private_data_len >= sizeof(pdata)) {
                        memcpy(pdata, event->param.conn.private_data,
                               sizeof(pdata));
                        plen = sizeof(pdata);
                }
                rdma_ack_cm_event(event);
                RPC_LOG(rpc, 3, "RDMA CM event %s, status %d",
                        rdma_event_str(type), status);

                switch (type) {
                case RDMA_CM_EVENT_ADDR_RESOLVED:
                        if (rdma_resolve_route(r->id, RPCRDMA_TIMEOUT_MS) != 0) {
                                e = errno;
                                rpc_set_error(rpc, "rdma_resolve_route() failed: %s",
                                              strerror(e));
                                return rdma_dead(rpc, e, err);
                        }
                        r->state = RDMA_ST_ROUTE;
                        break;
                case RDMA_CM_EVENT_ROUTE_RESOLVED:
                        e = rdma_setup(rpc, r);
                        if (e) {
                                return rdma_dead(rpc, e, err);
                        }
                        break;
                case RDMA_CM_EVENT_ESTABLISHED:
                        rdma_established(rpc, r, pdata, plen);
                        return RPC_RDMA_EV_CONNECTED;
                case RDMA_CM_EVENT_ADDR_ERROR:
                case RDMA_CM_EVENT_ROUTE_ERROR:
                case RDMA_CM_EVENT_UNREACHABLE:
                case RDMA_CM_EVENT_CONNECT_ERROR:
                case RDMA_CM_EVENT_REJECTED:
                        if (type == RDMA_CM_EVENT_REJECTED) {
                                e = ECONNREFUSED;
                        } else if (status < 0) {
                                e = -status;
                        } else if (type == RDMA_CM_EVENT_UNREACHABLE) {
                                e = ETIMEDOUT;
                        } else {
                                e = EHOSTUNREACH;
                        }
                        rpc_set_error(rpc, "RDMA connect to %s failed: %s (%s)",
                                      rpc->server ? rpc->server : "server",
                                      rdma_event_str(type), strerror(e));
                        return rdma_dead(rpc, e, err);
                case RDMA_CM_EVENT_DISCONNECTED:
                case RDMA_CM_EVENT_DEVICE_REMOVAL:
                        rpc_set_error(rpc, "RDMA connection to %s lost: %s",
                                      rpc->server ? rpc->server : "server",
                                      rdma_event_str(type));
                        return rdma_dead(rpc, ECONNRESET, err);
                default:
                        break;
                }
        }
        return RPC_RDMA_EV_NONE;
}

static int
rdma_can_ddp(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        if (pdu->in.base == NULL || pdu->in.iovcnt > RPCRDMA_MAX_SEGS) {
                return 0;
        }
#ifdef HAVE_LIBKRB5
        /* The checksum or the wrap covers the data, so it has to come inline */
        if (rpc->sec == RPC_SEC_KRB5I || rpc->sec == RPC_SEC_KRB5P) {
                return 0;
        }
#else
        (void)rpc;
#endif /* HAVE_LIBKRB5 */
        return 1;
}

static struct ibv_mr *
slot_reg(struct rpc_rdma *r, struct rpc_rdma_slot *slot, void *buf,
         size_t len, int access)
{
        struct ibv_mr *mr;

        if (slot->nmrs >= (int)(sizeof(slot->mrs) / sizeof(slot->mrs[0]))) {
                errno = E2BIG;
                return NULL;
        }
        mr = ibv_reg_mr(r->pd, buf, len, access);
        if (mr) {
                slot->mrs[slot->nmrs++] = mr;
        }
        return mr;
}

static uint32_t *
encode_seg(uint32_t *p, uint32_t handle, uint32_t len, const void *addr)
{
        uint64_t off = (uintptr_t)addr;

        *p++ = htonl(handle);
        *p++ = htonl(len);
        *p++ = htonl((uint32_t)(off >> 32));
        *p++ = htonl((uint32_t)off);
        return p;
}

/* A Position Zero Read chunk carrying the whole call */
static uint32_t *
encode_read_list(struct rpc_rdma *r, struct rpc_rdma_slot *slot,
                 struct rpc_pdu *pdu, uint32_t *p, uint32_t *end)
{
        char *seg_start = NULL;
        uint32_t seg_len = 0;
        size_t used = 0;
        int i;

        for (i = 1; i <= pdu->out.niov; i++) {
                char *buf = NULL;
                size_t len = 0;
                struct ibv_mr *mr;

                if (i < pdu->out.niov) {
                        buf = pdu->out.iov[i].buf;
                        len = pdu->out.iov[i].len;
                        if (len == 0) {
                                continue;
                        }
                        if (len < RPCRDMA_CALL_SIZE / 4 &&
                            used + len <= RPCRDMA_CALL_SIZE) {
                                if (seg_start == NULL) {
                                        seg_start = slot->call_buf + used;
                                }
                                memcpy(slot->call_buf + used, buf, len);
                                used += len;
                                seg_len += len;
                                continue;
                        }
                }
                if (seg_start) {
                        if (p + 6 > end) {
                                errno = E2BIG;
                                return NULL;
                        }
                        *p++ = htonl(1);
                        *p++ = 0;
                        p = encode_seg(p, slot->call_mr->rkey, seg_len, seg_start);
                        seg_start = NULL;
                        seg_len = 0;
                }
                if (i == pdu->out.niov) {
                        break;
                }
                if (p + 6 > end) {
                        errno = E2BIG;
                        return NULL;
                }
                mr = slot_reg(r, slot, buf, len, IBV_ACCESS_REMOTE_READ);
                if (mr == NULL) {
                        return NULL;
                }
                *p++ = htonl(1);
                *p++ = 0;
                p = encode_seg(p, mr->rkey, len, buf);
        }
        return p;
}

static uint32_t *
encode_flat_call(struct rpc_rdma *r, struct rpc_rdma_slot *slot,
                 struct rpc_pdu *pdu, uint32_t *p, size_t msg_len)
{
        struct ibv_mr *mr;
        size_t pos = 0;
        int i;

        slot->flat_call = malloc(msg_len);
        if (slot->flat_call == NULL) {
                return NULL;
        }
        for (i = 1; i < pdu->out.niov; i++) {
                memcpy(slot->flat_call + pos, pdu->out.iov[i].buf,
                       pdu->out.iov[i].len);
                pos += pdu->out.iov[i].len;
        }
        mr = slot_reg(r, slot, slot->flat_call, msg_len, IBV_ACCESS_REMOTE_READ);
        if (mr == NULL) {
                return NULL;
        }
        *p++ = htonl(1);
        *p++ = 0;
        return encode_seg(p, mr->rkey, msg_len, slot->flat_call);
}

/* 0 posted, 1 retry after a reply, -1 transport failure, -2 can never be sent */
static int
rdma_send_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        struct rpc_rdma *r = rpc->rdma;
        struct rpc_rdma_slot *slot = NULL;
        struct ibv_send_wr wr, *bad;
        struct ibv_sge sge;
        uint32_t *p, *end;
        size_t msg_len, tail, len;
        int ddp, inline_call, i;

        if (r == NULL || r->state != RDMA_ST_CONNECTED ||
            r->outstanding >= r->credits) {
                return 1;
        }
        for (i = 0; i < RPCRDMA_SLOTS; i++) {
                if (!r->slots[i].in_use && !r->slots[i].send_pending) {
                        slot = &r->slots[i];
                        break;
                }
        }
        if (slot == NULL) {
                return 1;
        }
        slot->in_use = 1;

        msg_len = pdu->out.total_size - 4;
        ddp = rdma_can_ddp(rpc, pdu);
        /* read list terminator, write list and reply chunk */
        tail = 4 + (ddp ? 12 + 16 * pdu->in.iovcnt : 4) + (ddp ? 4 : 24);
        inline_call = 16 + tail + msg_len <= r->inline_send;

        p = (uint32_t *)(void *)slot->send_buf;
        end = (uint32_t *)(void *)(slot->send_buf + r->inline_send - tail);
        *p++ = htonl(pdu->xid);
        *p++ = htonl(RPCRDMA_VERSION);
        *p++ = htonl(RPCRDMA_SLOTS);
        *p++ = htonl(inline_call ? RDMA_MSG : RDMA_NOMSG);

        if (!inline_call) {
                uint32_t *start = p;

                p = encode_read_list(r, slot, pdu, p, end);
                if (p == NULL && errno == E2BIG) {
                        slot_unregister(slot);
                        p = encode_flat_call(r, slot, pdu, start, msg_len);
                }
                if (p == NULL) {
                        goto failed;
                }
        }
        *p++ = 0;

        if (ddp) {
                uint32_t *count = p + 1;
                uint32_t nsegs = 0;

                *p++ = htonl(1);
                p++;
                for (i = 0; i < pdu->in.iovcnt; i++) {
                        struct iovec *iov = &pdu->in.iov[i];
                        struct ibv_mr *mr;

                        if (iov->iov_len == 0) {
                                continue;
                        }
                        mr = slot_reg(r, slot, iov->iov_base, iov->iov_len,
                                      IBV_ACCESS_LOCAL_WRITE |
                                      IBV_ACCESS_REMOTE_WRITE);
                        if (mr == NULL) {
                                goto failed;
                        }
                        p = encode_seg(p, mr->rkey, iov->iov_len, iov->iov_base);
                        nsegs++;
                }
                *count = htonl(nsegs);
                *p++ = 0;
                *p++ = 0;
        } else {
                struct ibv_mr *mr = slot->reply_mr;
                char *buf = slot->reply_buf;

                slot->reply_size = RPCRDMA_REPLY_SIZE;
                if (pdu->in.base) {
                        slot->reply_size += pdu->requested_read_count;
                        slot->big_reply = malloc(slot->reply_size);
                        if (slot->big_reply == NULL) {
                                goto failed;
                        }
                        slot->big_reply_mr = ibv_reg_mr(r->pd, slot->big_reply,
                                                        slot->reply_size,
                                                        IBV_ACCESS_LOCAL_WRITE |
                                                        IBV_ACCESS_REMOTE_WRITE);
                        if (slot->big_reply_mr == NULL) {
                                goto failed;
                        }
                        mr = slot->big_reply_mr;
                        buf = slot->big_reply;
                }
                *p++ = 0;
                *p++ = htonl(1);
                *p++ = htonl(1);
                p = encode_seg(p, mr->rkey, slot->reply_size, buf);
        }

        len = (char *)p - slot->send_buf;
        if (inline_call) {
                for (i = 1; i < pdu->out.niov; i++) {
                        memcpy(slot->send_buf + len, pdu->out.iov[i].buf,
                               pdu->out.iov[i].len);
                        len += pdu->out.iov[i].len;
                }
        }
        assert(len <= r->inline_send);

        sge.addr = (uintptr_t)slot->send_buf;
        sge.length = len;
        sge.lkey = r->pool_mr->lkey;
        memset(&wr, 0, sizeof(wr));
        wr.wr_id = slot - r->slots;
        wr.opcode = IBV_WR_SEND;
        wr.send_flags = IBV_SEND_SIGNALED;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        if (ibv_post_send(r->id->qp, &wr, &bad) != 0) {
                rpc_set_error_locked(rpc, "ibv_post_send() failed: %s",
                                     strerror(errno));
                slot_release(slot);
                return -1;
        }

        slot->pdu = pdu;
        slot->send_pending = 1;
        pdu->rdma_slot = slot;
        r->outstanding++;
        return 0;

 failed:
        RPC_LOG(rpc, 2, "Failed to set up RDMA chunks for xid 0x%08x: %s",
                pdu->xid, strerror(errno));
        slot_release(slot);
        if (r->outstanding) {
                return 1;
        }
        rpc_set_error_locked(rpc, "Failed to register memory for RDMA: %s. "
                             "RLIMIT_MEMLOCK may be too low", strerror(errno));
        return -2;
}

/* Remove the head of outqueue without sending it. Called with rpc_mutex held. */
static void
rdma_unqueue_head(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        rpc->outqueue.head = pdu->next;
        if (rpc->outqueue.head == NULL) {
                rpc->outqueue.tail = NULL;
        }
        if (rpc->outqueue.tailp == pdu) {
                rpc->outqueue.tailp = NULL;
        }
        assert(rpc->stats.outqueue_len > 0);
        rpc->stats.outqueue_len--;
        pdu->next = NULL;
}

int
rpc_rdma_write(struct rpc_context *rpc)
{
        struct rpc_pdu *pdu, *failed = NULL;
        int ret = 0;

        rpc_lock(rpc);
        while ((pdu = rpc->outqueue.head) != NULL) {
                if (rpc->max_waitpdu_len &&
                    rpc->waitpdu_len >= rpc->max_waitpdu_len) {
                        break;
                }
#ifdef HAVE_NFS4_2
                if (pdu->nfs4_needs_slot && !pdu->nfs4_slot_held &&
                    nfs4_pdu_take_slot(rpc, pdu) < 0) {
                        break;
                }
#endif /* HAVE_NFS4_2 */
                rdma_lock(rpc);
                ret = rdma_send_pdu(rpc, pdu);
                rdma_unlock(rpc);
                if (ret == -2) {
                        rdma_unqueue_head(rpc, pdu);
                        failed = pdu;
                        ret = 0;
                        break;
                }
                if (ret) {
                        break;
                }
                rpc_outqueue_sent(rpc, pdu);
        }
        rpc_unlock(rpc);

        if (failed) {
                if (failed->cb) {
                        failed->cb(rpc, RPC_STATUS_ERROR,
                                   rpc_get_error(rpc), failed->private_data);
                }
                rpc_free_pdu(rpc, failed);
        }
        return ret < 0 ? -1 : 0;
}

/* The READ data was placed by the server, or came inline as a fallback */
static void
rdma_finish_read(struct rpc_context *rpc, struct rpc_pdu *pdu,
                 uint32_t placed, char *msg, uint32_t msg_len)
{
        uint32_t pos;

        if (!rpc_read_reply_ok(rpc, pdu)) {
                return;
        }
        if (!zdr_uint32_t(&pdu->zdr, &pdu->read_count)) {
                pdu->zero_copy_error = "RDMA READ reply has no data length";
                return;
        }
        if (pdu->read_count > pdu->requested_read_count) {
                pdu->read_count = pdu->requested_read_count;
        }
        if (pdu->in.remaining_size > pdu->read_count) {
                rpc_shrink_cursor(rpc, &pdu->in, pdu->read_count);
        }
        if (placed >= pdu->read_count) {
                return;
        }
        pos = zdr_getpos(&pdu->zdr);
        if (placed == 0 && pos <= msg_len && msg_len - pos >= pdu->read_count) {
                rpc_memcpy_cursor(rpc, &pdu->in, msg + pos, pdu->read_count);
                return;
        }
        pdu->zero_copy_error = "RDMA READ reply carries less data than it declares";
}

static void
rdma_fail_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu, const char *error)
{
        rpc_set_error(rpc, "%s", error);
        if (pdu->cb) {
                pdu->cb(rpc, RPC_STATUS_ERROR, (void *)error, pdu->private_data);
        }
        rpc_free_pdu(rpc, pdu);
}

/* Returns -1 if the connection has to be dropped */
static int
rdma_recv(struct rpc_context *rpc, struct rpc_rdma *r, uint32_t idx,
          uint32_t len)
{
        char *buf = r->recv_bufs + idx * RPCRDMA_INLINE;
        uint32_t *p = (uint32_t *)(void *)buf;
        uint32_t *end = (uint32_t *)(void *)(buf + (len & ~3U));
        uint32_t gen = rpc->rdma_gen;
        uint32_t xid, credit, proc, placed = 0, rlen = 0, n, k;
        int first = 1, has_reply = 0;
        struct rpc_rdma_slot *slot;
        struct rpc_pdu *pdu;
        char *msg;
        uint32_t msg_len;

        if (len < 16 || ntohl(p[1]) != RPCRDMA_VERSION) {
                rpc_set_error(rpc, "Invalid RPC-over-RDMA header received");
                return -1;
        }
        xid = ntohl(p[0]);
        credit = ntohl(p[2]);
        proc = ntohl(p[3]);
        p += 4;

        if (proc == RDMA_MSG || proc == RDMA_NOMSG) {
                /* read list, the server never sends one */
                for (;;) {
                        if (p >= end) {
                                goto bad_header;
                        }
                        if (*p++ == 0) {
                                break;
                        }
                        if (p + 5 > end) {
                                goto bad_header;
                        }
                        p += 5;
                }
                /* write list, the first chunk is the READ payload */
                for (;;) {
                        if (p >= end) {
                                goto bad_header;
                        }
                        if (*p++ == 0) {
                                break;
                        }
                        if (p >= end) {
                                goto bad_header;
                        }
                        n = ntohl(*p++);
                        if (n > RPCRDMA_MAX_SEGS || p + 4 * n > end) {
                                goto bad_header;
                        }
                        for (k = 0; k < n; k++, p += 4) {
                                if (first) {
                                        placed += ntohl(p[1]);
                                }
                        }
                        first = 0;
                }
                if (p >= end) {
                        goto bad_header;
                }
                if (*p++) {
                        if (p >= end) {
                                goto bad_header;
                        }
                        n = ntohl(*p++);
                        if (n > RPCRDMA_MAX_SEGS || p + 4 * n > end) {
                                goto bad_header;
                        }
                        for (k = 0; k < n; k++, p += 4) {
                                rlen += ntohl(p[1]);
                        }
                        has_reply = 1;
                }
        }
        msg = (char *)p;
        msg_len = buf + len - msg;

        /* A backchannel call, we never offer one so there is nothing to do */
        if (proc == RDMA_MSG && msg_len >= 8 &&
            ntohl(((uint32_t *)(void *)msg)[1]) == CALL) {
                RPC_LOG(rpc, 2, "Ignoring RDMA backchannel call xid 0x%08x", xid);
                goto repost;
        }

        rdma_lock(rpc);
        if (credit == 0) {
                credit = 1;
        }
        r->credits = credit > RPCRDMA_SLOTS ? RPCRDMA_SLOTS : credit;
        if (r->outstanding) {
                r->outstanding--;
        }
        rdma_unlock(rpc);

        pdu = rpc_find_pdu(rpc, xid);
        if (pdu == NULL) {
                RPC_LOG(rpc, 2, "RDMA reply for unknown xid 0x%08x", xid);
                goto repost;
        }

        /* The caller's buffers are not the server's to touch any more */
        rdma_lock(rpc);
        slot = pdu->rdma_slot;
        if (slot) {
                slot->pdu = NULL;
                pdu->rdma_slot = NULL;
                slot_unregister(slot);
        }
        rdma_unlock(rpc);

        if (proc == RDMA_ERROR) {
                char error[64];

                snprintf(error, sizeof(error), "Server returned RDMA_ERROR %u",
                         msg_len >= 4 ? ntohl(*(uint32_t *)(void *)msg) : 0);
                rdma_fail_pdu(rpc, pdu, error);
                goto done;
        }
        if (proc == RDMA_NOMSG) {
                if (slot == NULL || !has_reply || rlen > slot->reply_size) {
                        rdma_fail_pdu(rpc, pdu, "Invalid RDMA_NOMSG reply");
                        goto done;
                }
                msg = slot->big_reply ? slot->big_reply : slot->reply_buf;
                msg_len = rlen;
        } else if (proc != RDMA_MSG) {
                rdma_fail_pdu(rpc, pdu, "Unknown RPC-over-RDMA procedure");
                goto done;
        }

        rpc->pdu = pdu;
        pdu->resp_size = len + rlen + placed;
        if (rpc_process_pdu(rpc, msg, msg_len) != 0) {
                rpc_set_error(rpc, "Invalid/garbage pdu received from server");
                if (rpc->rdma_gen == gen && slot) {
                        rdma_lock(rpc);
                        slot_release(slot);
                        rdma_unlock(rpc);
                }
                return -1;
        }
        if (rpc->rdma_gen == gen && pdu->free_pdu && pdu->free_zdr) {
                rdma_finish_read(rpc, pdu, placed, msg, msg_len);
        }
        rpc_finished_pdu(rpc);

 done:
        if (rpc->rdma_gen != gen) {
                return 0;
        }
        if (slot) {
                rdma_lock(rpc);
                slot_release(slot);
                rdma_unlock(rpc);
        }
 repost:
        if (rdma_post_recv(r, idx) != 0) {
                rpc_set_error(rpc, "ibv_post_recv() failed: %s", strerror(errno));
                return -1;
        }
        return 0;

 bad_header:
        rpc_set_error(rpc, "Malformed RPC-over-RDMA chunk lists received");
        return -1;
}

static enum rpc_rdma_event
rdma_service_cq(struct rpc_context *rpc, int *err)
{
        struct rpc_rdma *r = rpc->rdma;
        uint32_t gen = rpc->rdma_gen;
        struct ibv_wc wc[16];
        struct ibv_cq *cq;
        void *ctx;
        int i, n;

        while (ibv_get_cq_event(r->cc, &cq, &ctx) == 0) {
                ibv_ack_cq_events(cq, 1);
        }
        if (ibv_req_notify_cq(r->cq, 0) != 0) {
                rpc_set_error(rpc, "ibv_req_notify_cq() failed");
                return rdma_dead(rpc, EIO, err);
        }
        for (;;) {
                n = ibv_poll_cq(r->cq, 16, wc);
                if (n < 0) {
                        rpc_set_error(rpc, "ibv_poll_cq() failed");
                        return rdma_dead(rpc, EIO, err);
                }
                if (n == 0) {
                        break;
                }
                for (i = 0; i < n; i++) {
                        if (wc[i].status != IBV_WC_SUCCESS) {
                                rpc_set_error(rpc, "RDMA %s failed: %s",
                                              wc[i].wr_id < RPCRDMA_SLOTS ?
                                              "send" : "receive",
                                              ibv_wc_status_str(wc[i].status));
                                return rdma_dead(rpc, EIO, err);
                        }
                        if (wc[i].wr_id < RPCRDMA_SLOTS) {
                                rdma_lock(rpc);
                                r->slots[wc[i].wr_id].send_pending = 0;
                                rdma_unlock(rpc);
                                continue;
                        }
                        if (rdma_recv(rpc, r, wc[i].wr_id - RPCRDMA_SLOTS,
                                      wc[i].byte_len) != 0) {
                                if (rpc->rdma_gen != gen) {
                                        return RPC_RDMA_EV_NONE;
                                }
                                return rdma_dead(rpc, EIO, err);
                        }
                        if (rpc->rdma_gen != gen) {
                                return RPC_RDMA_EV_NONE;
                        }
                }
        }
        return RPC_RDMA_EV_NONE;
}

enum rpc_rdma_event
rpc_rdma_service(struct rpc_context *rpc, int *err)
{
        enum rpc_rdma_event ev;

        if (rpc->rdma == NULL || rpc->rdma->state == RDMA_ST_DEAD) {
                return RPC_RDMA_EV_NONE;
        }
        ev = rdma_service_cm(rpc, err);
        if (ev != RPC_RDMA_EV_NONE) {
                return ev;
        }
        if (rpc->rdma->state == RDMA_ST_CONNECTED) {
                return rdma_service_cq(rpc, err);
        }
        return RPC_RDMA_EV_NONE;
}
