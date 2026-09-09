/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Deterministic RPC peer: no NAS, root, kernel mount or second machine needed. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define CHECK(expr, ...) do { if (!(expr)) { \
        fprintf(stderr, "FAIL: " __VA_ARGS__); fputc('\n', stderr); exit(1); \
} } while (0)
#define MAX_JOBS 16

#ifndef HAVE_NFS4_2
int main(void) { puts("SKIP: libnfs was built without NFSv4.2"); return 0; }
#else

struct job {
        int calls, rpc_status, nfs_status, requests, mutations;
        uint32_t last_xid, cred_len;
        char cred[512], canonical[4096];
        uint32_t canonical_len;
        uint64_t last_request;
        struct rpc_pdu *pdu;
};

struct scenario {
        const char *name;
        nfs_opnum4 operation, fail_op;
        nfsstat4 error, expected;
        int delays, jobs, cancel, partial;
};

struct fixture {
        struct rpc_context *rpc;
        int peer;
        struct scenario scenario;
        struct job job[MAX_JOBS];
        uint32_t sequences[2];
};

static void complete(struct rpc_context *rpc, int status, void *data, void *opaque)
{
        struct job *job = opaque;
        (void)rpc;
        job->calls++;
        job->rpc_status = status;
        job->nfs_status = status == RPC_STATUS_SUCCESS ?
                (int)((COMPOUND4res *)data)->status : -1;
        CHECK(job->calls == 1, "callback called twice");
}

static void read_exact(int fd, void *buffer, size_t size)
{
        char *p = buffer;
        while (size) {
                ssize_t count = read(fd, p, size);
                if (count < 0 && errno == EINTR) continue;
                CHECK(count > 0, "read RPC record: %s", strerror(errno));
                p += count;
                size -= (size_t)count;
        }
}

static void write_exact(int fd, const void *buffer, size_t size)
{
        const char *p = buffer;
        while (size) {
                ssize_t count = write(fd, p, size);
                if (count < 0 && errno == EINTR) continue;
                CHECK(count > 0, "write RPC record: %s", strerror(errno));
                p += count;
                size -= (size_t)count;
        }
}

static void result_op(nfs_resop4 *result, const nfs_argop4 *arg, nfsstat4 status)
{
        result->resop = arg->argop;
        switch (arg->argop) {
        case OP_SEQUENCE: {
                SEQUENCE4res *res = &result->nfs_resop4_u.opsequence;
                const SEQUENCE4args *seq = &arg->nfs_argop4_u.opsequence;
                res->sr_status = status;
                memcpy(res->SEQUENCE4res_u.sr_resok4.sr_sessionid,
                       seq->sa_sessionid, sizeof(sessionid4));
                res->SEQUENCE4res_u.sr_resok4.sr_sequenceid = seq->sa_sequenceid;
                res->SEQUENCE4res_u.sr_resok4.sr_slotid = seq->sa_slotid;
                res->SEQUENCE4res_u.sr_resok4.sr_highest_slotid = 1;
                res->SEQUENCE4res_u.sr_resok4.sr_target_highest_slotid = 1;
                break;
        }
        case OP_PUTROOTFH: result->nfs_resop4_u.opputrootfh.status = status; break;
        case OP_SAVEFH: result->nfs_resop4_u.opsavefh.status = status; break;
        case OP_PUTFH: result->nfs_resop4_u.opputfh.status = status; break;
        case OP_LOOKUP: result->nfs_resop4_u.oplookup.status = status; break;
        case OP_GETATTR: result->nfs_resop4_u.opgetattr.status = status; break;
        case OP_OPEN:
                result->nfs_resop4_u.opopen.status = status;
                result->nfs_resop4_u.opopen.OPEN4res_u.resok4.stateid.seqid = 1;
                result->nfs_resop4_u.opopen.OPEN4res_u.resok4.delegation.delegation_type = OPEN_DELEGATE_NONE;
                break;
        case OP_GETFH:
                result->nfs_resop4_u.opgetfh.status = status;
                result->nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object.nfs_fh4_val = "file";
                result->nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object.nfs_fh4_len = 4;
                break;
        case OP_RENAME: result->nfs_resop4_u.oprename.status = status; break;
        default: CHECK(0, "unsupported fixture op %u", arg->argop);
        }
}

static void serve(struct fixture *f)
{
        char request[8192], reply[8192], canonical[4096];
        uint32_t marker, size, i, length;
        ZDR decoder, encoder, normalized;
        struct rpc_msg call = {0}, response = {0};
        COMPOUND4args args = {0};
        COMPOUND4res result = {0};
        nfs_resop4 ops[8] = {0};
        SEQUENCE4args saved;
        struct job *job;
        int id, inject;
        uint64_t now = rpc_current_time();

        read_exact(f->peer, &marker, sizeof(marker));
        marker = ntohl(marker);
        CHECK(marker & 0x80000000u, "fragmented request not expected");
        size = marker & 0x7fffffffu;
        CHECK(size <= sizeof(request), "oversized RPC request");
        read_exact(f->peer, request, size);
        zdrmem_create(&decoder, request, size, ZDR_DECODE);
        CHECK(zdr_callmsg(f->rpc, &decoder, &call), "decode RPC call");
        CHECK(zdr_COMPOUND4args(&decoder, &args), "decode NFS compound");
        CHECK(args.minorversion == 2 && args.argarray.argarray_len <= 8,
              "unexpected minor version or op count");
        CHECK(args.tag.utf8string_len == 1, "job tag missing");
        id = (unsigned char)args.tag.utf8string_val[0] - 'A';
        CHECK(id >= 0 && id < f->scenario.jobs, "invalid job tag");
        job = &f->job[id];
        job->requests++;
        CHECK(job->requests <= 10, "%s: unbounded retry", f->scenario.name);

        saved = args.argarray.argarray_val[0].nfs_argop4_u.opsequence;
        CHECK(args.argarray.argarray_val[0].argop == OP_SEQUENCE && saved.sa_slotid < 2,
              "invalid SEQUENCE");
        CHECK(saved.sa_sequenceid == ++f->sequences[saved.sa_slotid],
              "%s: reused or skipped sequence", f->scenario.name);
        if (job->requests > 1) {
                CHECK(call.xid != job->last_xid, "retry reused RPC XID");
                CHECK(now - job->last_request >= 80, "retry has no backoff");
                CHECK(call.body.cbody.cred.oa_length == job->cred_len &&
                      !memcmp(call.body.cbody.cred.oa_base, job->cred, job->cred_len),
                      "retry changed caller credentials");
        } else {
                job->cred_len = call.body.cbody.cred.oa_length;
                CHECK(job->cred_len <= sizeof(job->cred), "oversized credentials");
                memcpy(job->cred, call.body.cbody.cred.oa_base, job->cred_len);
        }
        job->last_xid = call.xid;
        job->last_request = now;
        memset(&args.argarray.argarray_val[0].nfs_argop4_u.opsequence, 0, sizeof(saved));
        zdrmem_create(&normalized, canonical, sizeof(canonical), ZDR_ENCODE);
        CHECK(zdr_COMPOUND4args(&normalized, &args), "normalize request");
        length = zdr_getpos(&normalized);
        if (job->requests == 1) {
                memcpy(job->canonical, canonical, length);
                job->canonical_len = length;
        } else {
                CHECK(length == job->canonical_len && !memcmp(job->canonical, canonical, length),
                      "retry changed operation arguments");
        }
        zdr_destroy(&normalized);
        args.argarray.argarray_val[0].nfs_argop4_u.opsequence = saved;

        inject = job->requests <= f->scenario.delays;
        /* One unrelated request must complete while the other jobs back off. */
        if (f->scenario.jobs > 1 && id == f->scenario.jobs - 1) inject = 0;
        result.resarray.resarray_val = ops;
        for (i = 0; i < args.argarray.argarray_len; i++) {
                nfsstat4 status = inject && args.argarray.argarray_val[i].argop == f->scenario.fail_op ?
                        f->scenario.error : NFS4_OK;
                result_op(&ops[i], &args.argarray.argarray_val[i], status);
                result.resarray.resarray_len++;
                result.status = status;
                if (status != NFS4_OK) break;
                if (ops[i].resop == OP_OPEN || ops[i].resop == OP_RENAME) job->mutations++;
        }
        rpc_set_uid(f->rpc, 21111);
        rpc_set_gid(f->rpc, 32222);
        response.xid = call.xid;
        response.direction = REPLY;
        response.body.rbody.stat = MSG_ACCEPTED;
        response.body.rbody.reply.areply.stat = SUCCESS;
        response.body.rbody.reply.areply.reply_data.results.where = (char *)&result;
        response.body.rbody.reply.areply.reply_data.results.proc = (zdrproc_t)zdr_COMPOUND4res;
        zdrmem_create(&encoder, reply, sizeof(reply), ZDR_ENCODE);
        CHECK(zdr_replymsg(f->rpc, &encoder, &response), "encode RPC reply");
        size = zdr_getpos(&encoder);
        marker = htonl(size | 0x80000000u);
        write_exact(f->peer, &marker, sizeof(marker));
        write_exact(f->peer, reply, size);
        zdr_destroy(&encoder);
        zdr_destroy(&decoder);
}

static void submit(struct fixture *f, int id)
{
        nfs_argop4 ops[8] = {0};
        COMPOUND4args args = {0};
        char tag = (char)('A' + id);
        int n = 0;
        ops[n++].argop = OP_SEQUENCE;
        ops[n++].argop = OP_PUTROOTFH;
        if (f->scenario.operation == OP_RENAME) {
                ops[n++].argop = OP_SAVEFH;
                ops[n].argop = OP_PUTFH;
                ops[n].nfs_argop4_u.opputfh.object.nfs_fh4_val = "dir";
                ops[n++].nfs_argop4_u.opputfh.object.nfs_fh4_len = 3;
                ops[n].argop = OP_RENAME;
                ops[n].nfs_argop4_u.oprename.oldname.utf8string_val = "old";
                ops[n].nfs_argop4_u.oprename.oldname.utf8string_len = 3;
                ops[n].nfs_argop4_u.oprename.newname.utf8string_val = "new";
                ops[n++].nfs_argop4_u.oprename.newname.utf8string_len = 3;
        } else {
                OPEN4args *open = &ops[n].nfs_argop4_u.opopen;
                ops[n++].argop = OP_OPEN;
                open->share_access = OPEN4_SHARE_ACCESS_WRITE;
                open->share_deny = OPEN4_SHARE_DENY_NONE;
                open->owner.clientid = 1;
                open->owner.owner.owner_val = "owner";
                open->owner.owner.owner_len = 5;
                open->openhow.opentype = OPEN4_NOCREATE;
                open->claim.claim = CLAIM_NULL;
                open->claim.open_claim4_u.file.utf8string_val = "file";
                open->claim.open_claim4_u.file.utf8string_len = 4;
                ops[n++].argop = OP_GETFH;
        }
        args.argarray.argarray_val = ops;
        args.argarray.argarray_len = n;
        args.tag.utf8string_val = &tag;
        args.tag.utf8string_len = 1;
        f->job[id].pdu = rpc_nfs4_compound_task(f->rpc, complete, &args, &f->job[id]);
        CHECK(f->job[id].pdu, "queue compound: %s", rpc_get_error(f->rpc));
}

static void run(struct scenario scenario)
{
        struct fixture f = {0};
        int pair[2], i, done, cancelled = 0;
        uint64_t start = rpc_current_time();
        sessionid4 session = {1};
        struct timeval timeout = {.tv_sec = 2};

        f.scenario = scenario;
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "socketpair");
        CHECK(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0, "nonblocking client");
        CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
              "peer timeout");
        f.peer = pair[1];
        f.rpc = rpc_init_context();
        CHECK(f.rpc, "create RPC context");
        rpc_set_fd(f.rpc, pair[0]);
        f.rpc->is_connected = 1;
        f.rpc->program = NFS4_PROGRAM;
        f.rpc->version = NFS_V4;
        f.rpc->nfs4_minorversion = 2;
        CHECK(nfs4_session_init(f.rpc, session, 2) == 0, "create session");
        rpc_set_uid(f.rpc, 1001);
        rpc_set_gid(f.rpc, 1001);
        for (i = 0; i < scenario.jobs; i++) submit(&f, i);
        while (1) {
                struct pollfd fd[2] = {
                        {.fd = pair[0], .events = rpc_which_events(f.rpc)},
                        {.fd = pair[1], .events = POLLIN}
                };
                CHECK(rpc_current_time() - start < 15000, "%s: deadline exceeded", scenario.name);
                CHECK(poll(fd, 2, 10) >= 0, "poll");
                CHECK(rpc_service(f.rpc, fd[0].revents) == 0, "rpc_service: %s", rpc_get_error(f.rpc));
                if (fd[1].revents & POLLIN) serve(&f);
                if (scenario.cancel && f.job[0].requests == 1 && !f.job[0].calls &&
                    rpc_queue_length(f.rpc) == 1 && !f.rpc->waitpdu_len && !f.rpc->stats.outqueue_len) {
                        if (scenario.cancel == 1) {
                                CHECK(rpc_cancel_pdu(f.rpc, f.job[0].pdu) == 0, "cancel delayed PDU");
                                CHECK(rpc_queue_length(f.rpc) == 0, "cancel leaked queued request");
                        }
                        cancelled = 1;
                        break;
                }
                done = 0;
                for (i = 0; i < scenario.jobs; i++) done += f.job[i].calls;
                if (done == scenario.jobs) break;
        }
        if (scenario.cancel) {
                CHECK(cancelled, "%s: no delayed request to cancel", scenario.name);
                rpc_destroy_context(f.rpc);
                CHECK(f.job[0].calls == (scenario.cancel == 2), "cancel callback contract");
                if (scenario.cancel == 2) CHECK(f.job[0].rpc_status == RPC_STATUS_CANCEL,
                                              "destroy did not cancel pending callback");
        } else {
                for (i = 0; i < scenario.jobs; i++) {
                        struct job *j = &f.job[i];
                        int expected_requests = scenario.expected != NFS4_OK ?
                                (scenario.delays > 8 ? 9 : 1) : scenario.delays + 1;
                        if (scenario.jobs > 1 && i == scenario.jobs - 1) expected_requests = 1;
                        CHECK(j->rpc_status == RPC_STATUS_SUCCESS && j->nfs_status == (int)scenario.expected,
                              "%s: NFS status %d, expected %d", scenario.name, j->nfs_status, scenario.expected);
                        CHECK(j->requests == expected_requests, "%s: %d requests, expected %d",
                              scenario.name, j->requests, expected_requests);
                        CHECK(j->mutations == (scenario.expected == NFS4_OK || scenario.partial),
                              "%s: mutation repeated or missing", scenario.name);
                }
                CHECK(rpc_queue_length(f.rpc) == 0 && f.rpc->nfs4_slots_in_use == 0,
                      "%s: request or slot leak", scenario.name);
                rpc_destroy_context(f.rpc);
        }
        close(f.peer);
        printf("PASS: %s (%llu ms)\n", scenario.name,
               (unsigned long long)(rpc_current_time() - start));
}

int main(void)
{
        struct scenario scenarios[] = {
                {"open-delay", OP_OPEN, OP_OPEN, NFS4ERR_DELAY, NFS4_OK, 1, 1, 0, 0},
                {"rename-delay", OP_RENAME, OP_RENAME, NFS4ERR_DELAY, NFS4_OK, 1, 1, 0, 0},
                {"repeated-delay", OP_OPEN, OP_OPEN, NFS4ERR_DELAY, NFS4_OK, 3, 1, 0, 0},
                {"real-io-error", OP_OPEN, OP_OPEN, NFS4ERR_IO, NFS4ERR_IO, 1, 1, 0, 0},
                {"permission-error", OP_OPEN, OP_OPEN, NFS4ERR_ACCESS, NFS4ERR_ACCESS, 1, 1, 0, 0},
                {"partial-success", OP_OPEN, OP_GETFH, NFS4ERR_DELAY, NFS4ERR_DELAY, 1, 1, 0, 1},
                {"sequence-error-unchanged", OP_OPEN, OP_SEQUENCE, NFS4ERR_DELAY, NFS4ERR_DELAY, 1, 1, 0, 0},
                {"retry-budget", OP_OPEN, OP_OPEN, NFS4ERR_DELAY, NFS4ERR_DELAY, 100, 1, 0, 0},
                {"concurrent-delay", OP_RENAME, OP_RENAME, NFS4ERR_DELAY, NFS4_OK, 2, 16, 0, 0},
                {"cancel-during-delay", OP_OPEN, OP_OPEN, NFS4ERR_DELAY, NFS4_OK, 1, 1, 1, 0},
                {"destroy-during-delay", OP_OPEN, OP_OPEN, NFS4ERR_DELAY, NFS4_OK, 1, 1, 2, 0}
        };
        size_t i;
        for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) run(scenarios[i]);
        puts("PASS: all NFSv4.2 DELAY regression cases");
        return 0;
}
#endif
