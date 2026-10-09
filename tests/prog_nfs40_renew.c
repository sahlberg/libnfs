/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Local RPC peer for NFSv4.0 lease renewal; no NFS server is needed. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL: %s:%d: %s\n", \
        __FILE__, __LINE__, #x); exit(1); } } while (0)

static void io_exact(int fd, void *buffer, size_t size, int writing)
{
        char *p = buffer;
        while (size) {
                struct pollfd ready = {.fd = fd,
                                       .events = writing ? POLLOUT : POLLIN};
                CHECK(poll(&ready, 1, 2000) == 1);
                ssize_t n = writing ? write(fd, p, size) : read(fd, p, size);
                CHECK(n > 0);
                p += n;
                size -= (size_t)n;
        }
}

static void test_mount_attributes(void)
{
        struct nfs_context *nfs = nfs_init_context();
        GETATTR4resok attrs = {0};
        uint32_t bitmap = (1u << FATTR4_LEASE_TIME) |
                          (1u << FATTR4_MAXREAD) |
                          (1u << FATTR4_MAXWRITE);
        uint32_t wire[5] = { htonl(90), 0, htonl(8192), 0, htonl(8192) };
        uint32_t lease = 0;

        CHECK(nfs != NULL);
        nfs->nfsi->version = NFS_V4;
        attrs.obj_attributes.attrmask.bitmap4_len = 1;
        attrs.obj_attributes.attrmask.bitmap4_val = &bitmap;
        attrs.obj_attributes.attr_vals.attrlist4_len = sizeof(wire);
        attrs.obj_attributes.attr_vals.attrlist4_val = (char *)wire;
        CHECK(nfs4_parse_mount_rwmax(nfs, &attrs, &lease) == 0);
        CHECK(lease == 90 && nfs_get_readmax(nfs) == 8192);
        bitmap &= ~(1u << FATTR4_LEASE_TIME);
        CHECK(nfs4_parse_mount_rwmax(nfs, &attrs, &lease) < 0);
        bitmap |= 1u << FATTR4_LEASE_TIME;
        wire[0] = 0;
        CHECK(nfs4_parse_mount_rwmax(nfs, &attrs, &lease) < 0);
        wire[0] = htonl(90);
        attrs.obj_attributes.attr_vals.attrlist4_len--;
        CHECK(nfs4_parse_mount_rwmax(nfs, &attrs, &lease) < 0);
#ifdef HAVE_NFS4_2
        nfs->nfsi->version = NFS_V4_2;
        bitmap &= ~(1u << FATTR4_LEASE_TIME);
        attrs.obj_attributes.attr_vals.attrlist4_val = (char *)&wire[1];
        attrs.obj_attributes.attr_vals.attrlist4_len = 16;
        CHECK(nfs4_parse_mount_rwmax(nfs, &attrs, &lease) == 0);
#endif
        nfs_destroy_context(nfs);
}

static uint32_t receive_renew(struct rpc_context *rpc, int peer,
                              uint64_t clientid, const struct AUTH *auth)
{
        char wire[4096];
        uint32_t marker, size;
        ZDR decoder;
        struct rpc_msg call = {0};
        COMPOUND4args args = {0};

        CHECK(rpc_service(rpc, POLLOUT) == 0);
        io_exact(peer, &marker, 4, 0);
        size = ntohl(marker) & 0x7fffffffu;
        CHECK(size <= sizeof(wire));
        io_exact(peer, wire, size, 0);
        zdrmem_create(&decoder, wire, size, ZDR_DECODE);
        CHECK(zdr_callmsg(rpc, &decoder, &call));
        CHECK(call.body.cbody.cred.oa_flavor == auth->ah_cred.oa_flavor);
        CHECK(call.body.cbody.cred.oa_length == auth->ah_cred.oa_length);
        CHECK(!memcmp(call.body.cbody.cred.oa_base,
                      auth->ah_cred.oa_base, auth->ah_cred.oa_length));
        CHECK(zdr_COMPOUND4args(&decoder, &args));
        CHECK(args.minorversion == 0 && args.argarray.argarray_len == 1);
        CHECK(args.argarray.argarray_val[0].argop == OP_RENEW);
        CHECK(args.argarray.argarray_val[0].nfs_argop4_u.oprenew.clientid == clientid);
        marker = call.xid;
        zdr_destroy(&decoder);
        return marker;
}

static void reply_renew(struct rpc_context *rpc, int peer, uint32_t xid,
                        nfsstat4 status)
{
        char wire[4096];
        uint32_t marker, size;
        ZDR encoder;
        nfs_resop4 op = {0};
        COMPOUND4res result = {0};
        struct rpc_msg reply = {0};

        op.resop = OP_RENEW;
        op.nfs_resop4_u.oprenew.status = status;
        result.status = status;
        result.resarray.resarray_len = 1;
        result.resarray.resarray_val = &op;
        reply.xid = xid;
        reply.direction = REPLY;
        reply.body.rbody.stat = MSG_ACCEPTED;
        reply.body.rbody.reply.areply.stat = SUCCESS;
        reply.body.rbody.reply.areply.reply_data.results.where = (char *)&result;
        reply.body.rbody.reply.areply.reply_data.results.proc =
                (zdrproc_t)zdr_COMPOUND4res;
        zdrmem_create(&encoder, wire, sizeof(wire), ZDR_ENCODE);
        CHECK(zdr_replymsg(rpc, &encoder, &reply));
        size = zdr_getpos(&encoder);
        marker = htonl(size | 0x80000000u);
        io_exact(peer, &marker, 4, 1);
        io_exact(peer, wire, size, 1);
        zdr_destroy(&encoder);
        CHECK(rpc_service(rpc, POLLIN) == 0);
}

static void test_renewal(void)
{
        struct rpc_context *rpc = rpc_init_context();
        int pair[2];
        uint32_t xid;
        nfsstat4 statuses[] = {NFS4_OK, NFS4ERR_CB_PATH_DOWN,
                               NFS4ERR_SERVERFAULT, NFS4ERR_EXPIRED,
                               NFS4ERR_STALE_CLIENTID};
        unsigned int i;

        CHECK(rpc != NULL);
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        rpc_set_fd(rpc, pair[0]);
        rpc->is_connected = 1;
        rpc->program = NFS4_PROGRAM;
        rpc->version = NFS_V4;
        rpc_set_poll_timeout(rpc, -1);
        rpc_set_uid(rpc, 1001);
        rpc_set_gid(rpc, 1002);
        CHECK(rpc_service(rpc, 0) == 0);
        CHECK(rpc_queue_length(rpc) == 0);
#ifdef HAVE_NFS4_2
        rpc->nfs4_minorversion = 2;
        CHECK(rpc_service(rpc, 0) == 0);
        CHECK(rpc_queue_length(rpc) == 0);
        rpc->nfs4_minorversion = 0;
#endif
        CHECK(rpc_nfs40_save_renew_auth(rpc) == 0);
        rpc_set_uid(rpc, 2001);
        rpc_nfs40_start_renew(rpc, 0x123456789abcdef0ULL, 90);
        CHECK(rpc->nfs40_renew_interval == 45000);
        CHECK(rpc_get_poll_timeout(rpc) > 0);
        for (i = 0; i < sizeof(statuses)/sizeof(statuses[0]); i++) {
                if (i == 4) rpc_nfs40_start_renew(rpc, 0x123456789abcdef0ULL, 90);
                rpc->nfs40_renew_due = rpc_current_time();
                CHECK(rpc_get_poll_timeout(rpc) == 0);
                CHECK(rpc_service(rpc, 0) == 0);
                CHECK(rpc->nfs40_renew_pending);
                CHECK(rpc_get_poll_timeout(rpc) == -1);
                CHECK(rpc_service(rpc, 0) == 0);
                xid = receive_renew(rpc, pair[1], rpc->nfs40_clientid,
                                    rpc->nfs40_renew_auth);
                reply_renew(rpc, pair[1], xid, statuses[i]);
                CHECK(!rpc->nfs40_renew_pending);
                CHECK(rpc->nfs40_renew_enabled == (i < 3));
                if (i < 3) CHECK(rpc_get_poll_timeout(rpc) > 0);
        }
        {
                struct AUTH *saved = rpc->nfs40_renew_auth;
                struct AUTH *current = rpc->auth;
                uint64_t now;
                rpc_nfs40_start_renew(rpc, 1, 90);
                rpc->nfs40_renew_auth = NULL;
                rpc->auth = NULL;
                rpc->nfs40_renew_due = rpc_current_time();
                CHECK(rpc_service(rpc, 0) == 0);
                now = rpc_current_time();
                CHECK(!rpc->nfs40_renew_pending);
                CHECK(rpc->nfs40_renew_due >= now &&
                      rpc->nfs40_renew_due <= now + 1000);
                rpc->auth = current;
                rpc->nfs40_renew_auth = saved;
        }
        rpc_nfs40_start_renew(rpc, 1, 90);
        rpc->nfs40_renew_due = rpc_current_time();
        CHECK(rpc_service(rpc, 0) == 0 && rpc->nfs40_renew_pending);
        CHECK(rpc_disconnect(rpc, "test disconnect") == 0);
        CHECK(!rpc->nfs40_renew_enabled);
        close(pair[1]);
        rpc_destroy_context(rpc);
}

static void test_destroy_pending(void)
{
        struct rpc_context *rpc = rpc_init_context();
        int pair[2];
        CHECK(rpc != NULL);
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        rpc_set_fd(rpc, pair[0]);
        rpc->is_connected = 1;
        CHECK(rpc_nfs40_save_renew_auth(rpc) == 0);
        rpc_nfs40_start_renew(rpc, 1, 90);
        rpc->nfs40_renew_due = rpc_current_time();
        CHECK(rpc_service(rpc, 0) == 0 && rpc->nfs40_renew_pending);
        rpc_destroy_context(rpc);
        close(pair[1]);
}

static void unmount_cb(int status, struct nfs_context *nfs,
                       void *data, void *private_data)
{
        int *called = private_data;
        (void)nfs;
        (void)data;
        CHECK(status == 0);
        ++*called;
}

static void test_unmount(void)
{
        struct nfs_context *nfs = nfs_init_context();
        int called = 0;
        CHECK(nfs != NULL);
        nfs->nfsi->version = NFS_V4;
        rpc_nfs40_start_renew(nfs->rpc, 1, 90);
        CHECK(nfs_umount_async(nfs, unmount_cb, &called) == 0);
        CHECK(called == 1 && !nfs->rpc->nfs40_renew_enabled);
        nfs_destroy_context(nfs);
}

int main(void)
{
        test_mount_attributes();
        test_renewal();
        test_destroy_pending();
        test_unmount();
        puts("PASS: NFSv4.0 lease renewal");
        return 0;
}
