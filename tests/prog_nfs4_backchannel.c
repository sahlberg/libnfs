/* SPDX-License-Identifier: GPL-3.0-or-later */
/* The NFSv4.1/4.2 back channel, against a server played over a socketpair. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef WIN32
int main(void) { return 77; }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define CHECK(x) do { if (!(x)) { \
        fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

#ifndef HAVE_NFS4_2
int main(void) { return 77; }
#else

#define OP_CB_LAYOUTRECALL 5

static struct rpc_context *rpc;
static int peer;
static uint32_t minorversion;
static sessionid4 session = { 7 };
static int handler_calls, handler_op, handler_ops[8];
static nfsstat4 handler_status;
static int fore_calls, fore_status;

static void handler(struct rpc_context *r, struct nfs_cb_argop4 *arg,
                    struct nfs_cb_resop4 *res, void *private_data)
{
        CHECK(r == rpc);
        CHECK(private_data == &handler_calls);
        CHECK(res->resop == arg->argop);
        CHECK(res->nfs_cb_resop4_u.opcbrecall.status == NFS4ERR_NOTSUPP);
        handler_calls++;
        handler_op = arg->argop;
        switch (arg->argop) {
        case OP_CB_RECALL:
                CHECK(arg->nfs_cb_argop4_u.opcbrecall.stateid.seqid == 42);
                CHECK(arg->nfs_cb_argop4_u.opcbrecall.fh.nfs_fh4_len == 3);
                break;
        case OP_CB_PUSH_DELEG: {
                CB_PUSH_DELEG4args *a = &arg->nfs_cb_argop4_u.opcbpush_deleg;

                CHECK(a->cpda_fh.nfs_fh4_len == 3);
                CHECK(!memcmp(a->cpda_fh.nfs_fh4_val, "abc", 3));
                CHECK(a->cpda_delegation.delegation_type == OPEN_DELEGATE_READ);
                CHECK(a->cpda_delegation.open_delegation4_u.read.stateid.seqid == 9);
                break;
        }
        case OP_CB_RECALL_ANY:
        case OP_CB_RECALLABLE_OBJ_AVAIL: {
                CB_RECALL_ANY4args *a = &arg->nfs_cb_argop4_u.opcbrecall_any;

                CHECK(a->craa_objects_to_keep == 2);
                CHECK(a->craa_type_mask.bitmap4_len == 1);
                CHECK(a->craa_type_mask.bitmap4_val[0] ==
                      (1 << RCA4_TYPE_MASK_RDATA_DLG));
                break;
        }
        default:
                CHECK(0);
        }
        handler_ops[handler_calls - 1] = arg->argop;
        res->nfs_cb_resop4_u.opcbrecall.status = handler_status;
}

static void fore_cb(struct rpc_context *r, int status, void *data,
                    void *private_data)
{
        (void)r; (void)private_data;
        fore_calls++;
        fore_status = status == RPC_STATUS_SUCCESS ?
                (int)((COMPOUND4res *)data)->status : -1;
}

static void read_exact(void *buf, size_t size)
{
        char *p = buf;

        while (size) {
                ssize_t n = read(peer, p, size);
                if (n < 0 && errno == EINTR) {
                        continue;
                }
                CHECK(n > 0);
                p += n;
                size -= n;
        }
}

static void write_exact(const void *buf, size_t size)
{
        CHECK(write(peer, buf, size) == (ssize_t)size);
}

/* Let the client read what the peer wrote and send what it has queued. */
static void service(void)
{
        int i;

        for (i = 0; i < 4; i++) {
                struct pollfd pfd = { rpc_get_fd(rpc), rpc_which_events(rpc), 0 };

                CHECK(poll(&pfd, 1, 10) >= 0);
                if (pfd.revents == 0) {
                        continue;
                }
                CHECK(rpc_service(rpc, pfd.revents) == 0);
        }
}

/* Record of one RPC message, read from the peer side. */
static uint32_t read_record(char *buf, uint32_t max)
{
        uint32_t marker;

        read_exact(&marker, 4);
        marker = ntohl(marker);
        CHECK(marker & 0x80000000u);
        marker &= 0x7fffffffu;
        CHECK(marker <= max);
        read_exact(buf, marker);
        return marker;
}

/* Send a call from the server, optionally split in two fragments. */
static void send_call(uint32_t xid, uint32_t prog, uint32_t vers,
                      uint32_t proc, const char *body, uint32_t len, int split)
{
        char buf[4096];
        struct rpc_msg call;
        uint32_t marker, size, first;
        ZDR zdr;

        memset(&call, 0, sizeof(call));
        call.xid = xid;
        call.direction = CALL;
        call.body.cbody.rpcvers = RPC_MSG_VERSION;
        call.body.cbody.prog = prog;
        call.body.cbody.vers = vers;
        call.body.cbody.proc = proc;
        call.body.cbody.cred.oa_flavor = AUTH_NONE;
        call.body.cbody.verf.oa_flavor = AUTH_NONE;
        zdrmem_create(&zdr, buf, sizeof(buf), ZDR_ENCODE);
        CHECK(zdr_callmsg(rpc, &zdr, &call));
        size = zdr_getpos(&zdr);
        zdr_destroy(&zdr);
        memcpy(buf + size, body, len);
        size += len;

        first = split ? 16 : size;
        marker = htonl(first | (split ? 0 : 0x80000000u));
        write_exact(&marker, 4);
        write_exact(buf, first);
        if (split) {
                marker = htonl((size - first) | 0x80000000u);
                write_exact(&marker, 4);
                write_exact(buf + first, size - first);
        }
}

struct cb_res {
        nfsstat4 status;
        uint32_t nres;
        uint32_t resop[8];
        nfsstat4 opstatus[8];
        CB_SEQUENCE4res seq;
};

static uint32_t zdr_cb_res(ZDR *zdr, struct cb_res *r)
{
        utf8str_cs tag;
        uint32_t i;

        memset(&tag, 0, sizeof(tag));
        if (!zdr_nfsstat4(zdr, &r->status) || !zdr_utf8str_cs(zdr, &tag) ||
            !zdr_uint32_t(zdr, &r->nres) || r->nres > 8) {
                return FALSE;
        }
        for (i = 0; i < r->nres; i++) {
                if (!zdr_uint32_t(zdr, &r->resop[i])) {
                        return FALSE;
                }
                if (r->resop[i] == OP_CB_SEQUENCE) {
                        if (!zdr_CB_SEQUENCE4res(zdr, &r->seq)) {
                                return FALSE;
                        }
                        r->opstatus[i] = r->seq.csr_status;
                } else if (!zdr_nfsstat4(zdr, &r->opstatus[i])) {
                        return FALSE;
                }
        }
        return TRUE;
}

/*
 * Read a reply to a back channel call. Returns the accept status, and for a
 * CB_COMPOUND the decoded result and the raw body.
 */
static int read_reply(uint32_t xid, struct cb_res *res, char *body,
                      uint32_t *bodylen)
{
        char buf[4096];
        struct rpc_msg msg;
        uint32_t size;
        ZDR zdr;
        int stat;

        size = read_record(buf, sizeof(buf));
        memset(&msg, 0, sizeof(msg));
        msg.body.rbody.reply.areply.verf = libnfs_null_auth;
        msg.body.rbody.reply.areply.reply_data.results.where = (char *)res;
        msg.body.rbody.reply.areply.reply_data.results.proc =
                res ? (zdrproc_t)zdr_cb_res : (zdrproc_t)zdr_void;
        if (res) {
                memset(res, 0, sizeof(*res));
        }
        zdrmem_create(&zdr, buf, size, ZDR_DECODE);
        CHECK(zdr_replymsg(rpc, &zdr, &msg));
        CHECK(msg.xid == xid);
        CHECK(msg.direction == REPLY);
        CHECK(msg.body.rbody.stat == MSG_ACCEPTED);
        stat = msg.body.rbody.reply.areply.stat;
        if (body) {
                /* The CB_COMPOUND4res is the tail of the record. */
                *bodylen = size - 24;
                memcpy(body, buf + 24, *bodylen);
        }
        zdr_destroy(&zdr);
        return stat;
}

/* CB_COMPOUND body: CB_SEQUENCE(seq, slot, sess), then extra raw ops. */
static uint32_t compound(char *out, uint32_t minor, int with_seq,
                         uint32_t seq, uint32_t slot, const char *sess,
                         const uint32_t *extra, int nextra, int recall)
{
        uint32_t zero = 0, ident = 1, n, op, i;
        utf8str_cs tag = { 0, NULL };
        CB_SEQUENCE4args sargs;
        CB_RECALL4args rargs;
        ZDR zdr;

        zdrmem_create(&zdr, out, 1024, ZDR_ENCODE);
        n = (with_seq ? 1 : 0) + nextra + (recall ? 1 : 0);
        CHECK(zdr_utf8str_cs(&zdr, &tag));
        CHECK(zdr_uint32_t(&zdr, &minor));
        CHECK(zdr_uint32_t(&zdr, &ident));
        CHECK(zdr_uint32_t(&zdr, &n));
        if (with_seq) {
                memset(&sargs, 0, sizeof(sargs));
                memcpy(sargs.csa_sessionid, sess, sizeof(sessionid4));
                sargs.csa_sequenceid = seq;
                sargs.csa_slotid = slot;
                op = OP_CB_SEQUENCE;
                CHECK(zdr_uint32_t(&zdr, &op));
                CHECK(zdr_CB_SEQUENCE4args(&zdr, &sargs));
        }
        if (recall) {
                memset(&rargs, 0, sizeof(rargs));
                rargs.stateid.seqid = 42;
                rargs.fh.nfs_fh4_val = "abc";
                rargs.fh.nfs_fh4_len = 3;
                op = OP_CB_RECALL;
                CHECK(zdr_uint32_t(&zdr, &op));
                CHECK(zdr_CB_RECALL4args(&zdr, &rargs));
        }
        for (i = 0; i < (uint32_t)nextra; i++) {
                op = extra[i];
                CHECK(zdr_uint32_t(&zdr, &op));
                /* Something that is not decoded anyway. */
                CHECK(zdr_uint32_t(&zdr, &zero));
        }
        n = zdr_getpos(&zdr);
        zdr_destroy(&zdr);
        return n;
}

/* A COMPOUND of only SEQUENCE on the fore channel. */
static void submit_fore(void)
{
        COMPOUND4args args;
        nfs_argop4 op;

        memset(&op, 0, sizeof(op));
        op.argop = OP_SEQUENCE;
        memset(&args, 0, sizeof(args));
        args.argarray.argarray_len = 1;
        args.argarray.argarray_val = &op;
        CHECK(rpc_nfs4_compound_task(rpc, fore_cb, &args, NULL) != NULL);
}

/* Read a fore channel request, return its xid and slot/sequence. */
static uint32_t read_fore(SEQUENCE4args *seq)
{
        char buf[4096];
        struct rpc_msg call;
        COMPOUND4args args;
        uint32_t size;
        ZDR zdr;

        size = read_record(buf, sizeof(buf));
        memset(&call, 0, sizeof(call));
        memset(&args, 0, sizeof(args));
        zdrmem_create(&zdr, buf, size, ZDR_DECODE);
        CHECK(zdr_callmsg(rpc, &zdr, &call));
        CHECK(call.body.cbody.prog == NFS4_PROGRAM);
        CHECK(zdr_COMPOUND4args(&zdr, &args));
        CHECK(args.argarray.argarray_val[0].argop == OP_SEQUENCE);
        *seq = args.argarray.argarray_val[0].nfs_argop4_u.opsequence;
        zdr_destroy(&zdr);
        return call.xid;
}

static void reply_fore(uint32_t xid, SEQUENCE4args *seq)
{
        char buf[4096];
        struct rpc_msg msg;
        COMPOUND4res res;
        nfs_resop4 op;
        SEQUENCE4resok *ok = &op.nfs_resop4_u.opsequence.SEQUENCE4res_u.sr_resok4;
        uint32_t size, marker;
        ZDR zdr;

        memset(&op, 0, sizeof(op));
        op.resop = OP_SEQUENCE;
        memcpy(ok->sr_sessionid, seq->sa_sessionid, sizeof(sessionid4));
        ok->sr_sequenceid = seq->sa_sequenceid;
        ok->sr_slotid = seq->sa_slotid;
        memset(&res, 0, sizeof(res));
        res.resarray.resarray_len = 1;
        res.resarray.resarray_val = &op;
        memset(&msg, 0, sizeof(msg));
        msg.xid = xid;
        msg.direction = REPLY;
        msg.body.rbody.stat = MSG_ACCEPTED;
        msg.body.rbody.reply.areply.stat = SUCCESS;
        msg.body.rbody.reply.areply.reply_data.results.where = (char *)&res;
        msg.body.rbody.reply.areply.reply_data.results.proc = (zdrproc_t)zdr_COMPOUND4res;
        zdrmem_create(&zdr, buf, sizeof(buf), ZDR_ENCODE);
        CHECK(zdr_replymsg(rpc, &zdr, &msg));
        size = zdr_getpos(&zdr);
        zdr_destroy(&zdr);
        marker = htonl(size | 0x80000000u);
        write_exact(&marker, 4);
        write_exact(buf, size);
}

static void setup(uint32_t slots)
{
        struct timeval tv = { 2, 0 };
        int sv[2];

        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        CHECK(fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
        CHECK(setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
        peer = sv[1];
        rpc = rpc_init_context();
        CHECK(rpc != NULL);
        CHECK(rpc_nfs4_enable_backchannel(rpc, handler, &handler_calls) == 0);
        rpc_set_fd(rpc, sv[0]);
        rpc->is_connected = 1;
        rpc->program = NFS4_PROGRAM;
        rpc->version = NFS_V4;
        rpc->nfs4_minorversion = minorversion;
        CHECK(nfs4_session_init(rpc, session, slots) == 0);
        handler_calls = 0;
        handler_status = NFS4_OK;
        fore_calls = 0;
}

static void teardown(void)
{
        rpc_destroy_context(rpc);
        close(peer);
}

static void test_calls(void)
{
        char body[1024], raw1[4096], raw2[4096];
        uint32_t len, len1, len2;
        uint32_t extra[1];
        sessionid4 other = { 8 };
        struct cb_res res;

        setup(2);

        /* CB_NULL, and a program or procedure we do not serve. */
        send_call(0x100, NFS4_CALLBACK, NFS_CB, CB_NULL, NULL, 0, 0);
        service();
        CHECK(read_reply(0x100, NULL, NULL, NULL) == SUCCESS);
        send_call(0x101, 100003, 4, 0, NULL, 0, 0);
        service();
        CHECK(read_reply(0x101, NULL, NULL, NULL) == PROG_UNAVAIL);
        send_call(0x102, NFS4_CALLBACK, 2, 0, NULL, 0, 0);
        service();
        CHECK(read_reply(0x102, NULL, NULL, NULL) == PROG_MISMATCH);
        send_call(0x103, NFS4_CALLBACK, NFS_CB, 7, NULL, 0, 0);
        service();
        CHECK(read_reply(0x103, NULL, NULL, NULL) == PROC_UNAVAIL);

        /* CB_SEQUENCE + CB_RECALL, in two fragments. */
        len = compound(body, minorversion, 1, 1, 0, (char *)session, NULL, 0, 1);
        send_call(0x200, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 1);
        service();
        CHECK(read_reply(0x200, &res, raw1, &len1) == SUCCESS);
        CHECK(handler_calls == 1 && handler_op == OP_CB_RECALL);
        CHECK(res.status == NFS4_OK && res.nres == 2);
        CHECK(res.resop[0] == OP_CB_SEQUENCE && res.opstatus[0] == NFS4_OK);
        CHECK(res.seq.CB_SEQUENCE4res_u.csr_resok4.csr_sequenceid == 1);
        CHECK(!memcmp(res.seq.CB_SEQUENCE4res_u.csr_resok4.csr_sessionid,
                      session, sizeof(sessionid4)));
        CHECK(res.resop[1] == OP_CB_RECALL && res.opstatus[1] == NFS4_OK);

        /* A replay gets the cached reply, and the handler is not run again. */
        send_call(0x201, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x201, &res, raw2, &len2) == SUCCESS);
        CHECK(handler_calls == 1);
        CHECK(len1 == len2 && !memcmp(raw1, raw2, len1));

        /* Out of order, wrong slot, wrong session. */
        len = compound(body, minorversion, 1, 5, 0, (char *)session, NULL, 0, 1);
        send_call(0x202, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x202, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4ERR_SEQ_MISORDERED && res.nres == 1);
        len = compound(body, minorversion, 1, 2, 1, (char *)session, NULL, 0, 1);
        send_call(0x203, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x203, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4ERR_BADSLOT);
        len = compound(body, minorversion, 1, 2, 0, (char *)other, NULL, 0, 1);
        send_call(0x204, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x204, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4ERR_BADSESSION);
        CHECK(handler_calls == 1);

        /* No CB_SEQUENCE first, and a minor version that is not ours. */
        len = compound(body, minorversion, 0, 0, 0, NULL, NULL, 0, 1);
        send_call(0x205, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x205, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4ERR_OP_NOT_IN_SESSION && res.nres == 1);
        len = compound(body, 0, 1, 2, 0, (char *)session, NULL, 0, 1);
        send_call(0x206, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x206, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4ERR_MINOR_VERS_MISMATCH && res.nres == 0);
        CHECK(handler_calls == 1);

        /* An op we do not decode, then one that does not exist. */
        extra[0] = OP_CB_LAYOUTRECALL;
        len = compound(body, minorversion, 1, 2, 0, (char *)session, extra, 1, 0);
        send_call(0x207, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x207, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4ERR_NOTSUPP && res.nres == 2);
        CHECK(res.resop[1] == OP_CB_LAYOUTRECALL);
        extra[0] = 99;
        len = compound(body, minorversion, 1, 3, 0, (char *)session, extra, 1, 0);
        send_call(0x208, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x208, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4ERR_OP_ILLEGAL && res.nres == 2);
        CHECK(res.resop[1] == OP_CB_ILLEGAL);

        /* The handler's error is the result, and the slot still advances. */
        handler_status = NFS4ERR_BADHANDLE;
        len = compound(body, minorversion, 1, 4, 0, (char *)session, NULL, 0, 1);
        send_call(0x209, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x209, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4ERR_BADHANDLE && res.opstatus[1] == NFS4ERR_BADHANDLE);
        CHECK(handler_calls == 2);

        teardown();
}

/* The delegation callbacks reach the handler with their arguments. */
static void test_delegation_ops(void)
{
        static const uint32_t ops[] = {
                OP_CB_SEQUENCE, OP_CB_PUSH_DELEG, OP_CB_RECALL_ANY,
                OP_CB_RECALLABLE_OBJ_AVAIL
        };
        uint32_t ident = 1, n = 4, mask = 1 << RCA4_TYPE_MASK_RDATA_DLG, i, len;
        utf8str_cs tag = { 0, NULL };
        nfs_cb_argop4 arg;
        struct cb_res res;
        char body[1024];
        ZDR zdr;

        setup(2);
        zdrmem_create(&zdr, body, sizeof(body), ZDR_ENCODE);
        CHECK(zdr_utf8str_cs(&zdr, &tag));
        CHECK(zdr_uint32_t(&zdr, &minorversion));
        CHECK(zdr_uint32_t(&zdr, &ident));
        CHECK(zdr_uint32_t(&zdr, &n));
        for (i = 0; i < n; i++) {
                memset(&arg, 0, sizeof(arg));
                arg.argop = ops[i];
                switch (ops[i]) {
                case OP_CB_SEQUENCE:
                        memcpy(arg.nfs_cb_argop4_u.opcbsequence.csa_sessionid,
                               session, sizeof(sessionid4));
                        arg.nfs_cb_argop4_u.opcbsequence.csa_sequenceid = 1;
                        break;
                case OP_CB_PUSH_DELEG:
                        arg.nfs_cb_argop4_u.opcbpush_deleg.cpda_fh.nfs_fh4_val = "abc";
                        arg.nfs_cb_argop4_u.opcbpush_deleg.cpda_fh.nfs_fh4_len = 3;
                        arg.nfs_cb_argop4_u.opcbpush_deleg.cpda_delegation.delegation_type =
                                OPEN_DELEGATE_READ;
                        arg.nfs_cb_argop4_u.opcbpush_deleg.cpda_delegation.open_delegation4_u.read.stateid.seqid = 9;
                        break;
                default:
                        arg.nfs_cb_argop4_u.opcbrecall_any.craa_objects_to_keep = 2;
                        arg.nfs_cb_argop4_u.opcbrecall_any.craa_type_mask.bitmap4_len = 1;
                        arg.nfs_cb_argop4_u.opcbrecall_any.craa_type_mask.bitmap4_val = &mask;
                }
                CHECK(zdr_nfs_cb_argop4(&zdr, &arg));
        }
        len = zdr_getpos(&zdr);
        zdr_destroy(&zdr);

        send_call(0x400, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x400, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4_OK && res.nres == 4);
        CHECK(handler_calls == 3);
        for (i = 1; i < n; i++) {
                CHECK(handler_ops[i - 1] == (int)ops[i]);
                CHECK(res.resop[i] == ops[i] && res.opstatus[i] == NFS4_OK);
        }
        teardown();
}

/* A call whose xid is the same as one of our outstanding requests. */
static void test_xid_collision(void)
{
        SEQUENCE4args seq;
        uint32_t xid;

        setup(2);
        rpc_set_next_xid(rpc, 0x5000);
        submit_fore();
        service();
        xid = read_fore(&seq);
        CHECK(xid == 0x5000);

        send_call(0x5000, NFS4_CALLBACK, NFS_CB, CB_NULL, NULL, 0, 0);
        service();
        CHECK(read_reply(0x5000, NULL, NULL, NULL) == SUCCESS);
        CHECK(fore_calls == 0);

        reply_fore(xid, &seq);
        service();
        CHECK(fore_calls == 1 && fore_status == NFS4_OK);
        teardown();
}

/* The reply must not wait behind a COMPOUND that waits for a slot. */
static void test_reply_jumps_queue(void)
{
        SEQUENCE4args seq, seq2;
        uint32_t xid, xid2, len;
        char body[1024];
        struct cb_res res;

        setup(1);
        submit_fore();
        service();
        xid = read_fore(&seq);
        submit_fore();
        service();

        len = compound(body, minorversion, 1, 1, 0, (char *)session, NULL, 0, 1);
        send_call(0x300, NFS4_CALLBACK, NFS_CB, CB_COMPOUND, body, len, 0);
        service();
        CHECK(read_reply(0x300, &res, NULL, NULL) == SUCCESS);
        CHECK(res.status == NFS4_OK);

        reply_fore(xid, &seq);
        service();
        CHECK(fore_calls == 1);
        xid2 = read_fore(&seq2);
        CHECK(xid2 != xid);
        reply_fore(xid2, &seq2);
        service();
        CHECK(fore_calls == 2);
        teardown();
}

int main(void)
{
        for (minorversion = 1; minorversion <= 2; minorversion++) {
                test_calls();
                test_delegation_ops();
                test_xid_collision();
                test_reply_jumps_queue();
        }
        printf("PASS\n");
        return 0;
}
#endif /* HAVE_NFS4_2 */
#endif /* WIN32 */
