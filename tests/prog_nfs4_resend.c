/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Resending NFSv4 unstable writes a server lost, against a local NFSv4.0
 * peer that keeps what a crash loses apart from what is on stable storage.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef HAVE_MULTITHREADING
#include <pthread.h>
#endif
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL: %s:%d: %s\n", \
        __FILE__, __LINE__, #x); exit(1); } } while (0)

#define FILE_SIZE (64 * 1024)
#define MAX_HELD 8

struct request {
        uint32_t xid;
        nfs_opnum4 op;          /* WRITE, COMMIT or CLOSE */
        uint64_t offset;
        uint32_t count;
        stable_how4 stable;
        int anonymous;
        int with_commit;        /* a COMMIT before the CLOSE */
        char data[FILE_SIZE];
        uint64_t when;
};

struct server {
        int fd;
        struct rpc_context *rpc;
#ifdef HAVE_MULTITHREADING
        pthread_mutex_t lock;
#endif
        char data[FILE_SIZE];   /* what the server has */
        char disk[FILE_SIZE];   /* what survives a crash */
        uint32_t verf;
        int stale_state;        /* a crash lost the open state too */
        int writes, commits, closes;
        int hold_writes;        /* queue WRITEs instead of answering */
        struct request held[MAX_HELD];
        int nheld;
        nfsstat4 write_error;   /* for the next write_errors WRITEs */
        int write_errors;
        nfsstat4 commit_error;
        nfsstat4 close_error;
        uint32_t over_report;
        struct request last_write, last_close;
        uint64_t write_times[8];
};

struct result {
        int done;
        int status;
};

static struct server srv;
static struct nfs_context *nfs;

static void io_exact(int fd, void *buffer, size_t size, int writing)
{
        char *p = buffer;
        while (size) {
                struct pollfd ready = {.fd = fd,
                                       .events = writing ? POLLOUT : POLLIN};
                ssize_t n;

                CHECK(poll(&ready, 1, 2000) == 1);
                n = writing ? write(fd, p, size) : read(fd, p, size);
                CHECK(n > 0);
                p += n;
                size -= (size_t)n;
        }
}

static void srv_lock(void)
{
#ifdef HAVE_MULTITHREADING
        pthread_mutex_lock(&srv.lock);
#endif
}

static void srv_unlock(void)
{
#ifdef HAVE_MULTITHREADING
        pthread_mutex_unlock(&srv.lock);
#endif
}

static void receive(struct request *req)
{
        static char wire[FILE_SIZE + 4096];
        uint32_t marker, size, i;
        ZDR decoder;
        struct rpc_msg call = {0};
        COMPOUND4args args = {0};

        io_exact(srv.fd, &marker, 4, 0);
        size = ntohl(marker) & 0x7fffffffu;
        CHECK(size <= sizeof(wire));
        io_exact(srv.fd, wire, size, 0);
        zdrmem_create(&decoder, wire, size, ZDR_DECODE);
        CHECK(zdr_callmsg(srv.rpc, &decoder, &call));
        CHECK(zdr_COMPOUND4args(&decoder, &args));
        CHECK(args.minorversion == 0);
        CHECK(args.argarray.argarray_val[0].argop == OP_PUTFH);

        memset(req, 0, offsetof(struct request, data));
        req->xid = call.xid;
        req->when = rpc_current_time();
        for (i = 1; i < args.argarray.argarray_len; i++) {
                nfs_argop4 *op = &args.argarray.argarray_val[i];
                static const char zero[12];

                switch (op->argop) {
                case OP_WRITE:
                        /* The data follows the COMPOUND, see rpc_nfs4_writev_task() */
                        req->op = OP_WRITE;
                        req->offset = op->nfs_argop4_u.opwrite.offset;
                        req->stable = op->nfs_argop4_u.opwrite.stable;
                        req->anonymous = !memcmp(op->nfs_argop4_u.opwrite.stateid.other,
                                                 zero, 12);
                        CHECK(zdr_u_int(&decoder, &req->count));
                        CHECK(req->offset + req->count <= FILE_SIZE);
                        memcpy(req->data, wire + zdr_getpos(&decoder),
                               req->count);
                        break;
                case OP_COMMIT:
                        req->op = OP_COMMIT;
                        req->with_commit = 1;
                        break;
                case OP_CLOSE:
                        req->op = OP_CLOSE;
                        break;
                default:
                        CHECK(0);
                }
        }
        zdr_destroy(&decoder);
}

static void put_verf(char *verf)
{
        memset(verf, 0, NFS4_VERIFIER_SIZE);
        memcpy(verf, &srv.verf, sizeof(srv.verf));
}

static void answer(struct request *req)
{
        static char wire[4096];
        uint32_t marker, size;
        ZDR encoder;
        nfs_resop4 ops[3] = {{0}};
        COMPOUND4res result = {0};
        struct rpc_msg reply = {0};
        nfsstat4 status = NFS4_OK;
        int n = 0;

        srv_lock();
        ops[n++].resop = OP_PUTFH;
        if (req->op == OP_WRITE) {
                WRITE4resok *ok = &ops[n].nfs_resop4_u.opwrite.WRITE4res_u.resok4;

                srv.write_times[srv.writes++ % 8] = rpc_current_time();
                srv.last_write = *req;
                if (srv.write_errors > 0) {
                        srv.write_errors--;
                        status = srv.write_error;
                } else if (srv.stale_state && !req->anonymous) {
                        status = NFS4ERR_STALE_STATEID;
                }
                if (status == NFS4_OK) {
                        memcpy(srv.data + req->offset, req->data, req->count);
                        if (req->stable == FILE_SYNC4) {
                                memcpy(srv.disk + req->offset, req->data,
                                       req->count);
                        }
                        ok->count = req->count + srv.over_report;
                        ok->committed = req->stable;
                        put_verf(ok->writeverf);
                }
                ops[n].resop = OP_WRITE;
                ops[n++].nfs_resop4_u.opwrite.status = status;
        }
        if (req->with_commit && status == NFS4_OK) {
                srv.commits++;
                status = srv.commit_error;
                srv.commit_error = NFS4_OK;
                if (status == NFS4_OK) {
                        memcpy(srv.disk, srv.data, FILE_SIZE);
                        put_verf(ops[n].nfs_resop4_u.opcommit.COMMIT4res_u.resok4.writeverf);
                }
                ops[n].resop = OP_COMMIT;
                ops[n++].nfs_resop4_u.opcommit.status = status;
        }
        if (req->op == OP_CLOSE && status == NFS4_OK) {
                srv.closes++;
                srv.last_close = *req;
                status = srv.close_error;
                ops[n].resop = OP_CLOSE;
                ops[n++].nfs_resop4_u.opclose.status = status;
        }
        result.status = status;
        result.resarray.resarray_len = n;
        result.resarray.resarray_val = ops;
        reply.xid = req->xid;
        reply.direction = REPLY;
        reply.body.rbody.stat = MSG_ACCEPTED;
        reply.body.rbody.reply.areply.stat = SUCCESS;
        reply.body.rbody.reply.areply.reply_data.results.where = (char *)&result;
        reply.body.rbody.reply.areply.reply_data.results.proc =
                (zdrproc_t)zdr_COMPOUND4res;
        zdrmem_create(&encoder, wire, sizeof(wire), ZDR_ENCODE);
        CHECK(zdr_replymsg(srv.rpc, &encoder, &reply));
        srv_unlock();
        size = zdr_getpos(&encoder);
        marker = htonl(size | 0x80000000u);
        io_exact(srv.fd, &marker, 4, 1);
        io_exact(srv.fd, wire, size, 1);
        zdr_destroy(&encoder);
}

/* The server restarts: what was not on stable storage is gone */
static void crash(int lose_state)
{
        srv_lock();
        memcpy(srv.data, srv.disk, FILE_SIZE);
        srv.verf++;
        srv.stale_state = lose_state;
        srv_unlock();
}

/* Runs client and server until *done, or for msecs if done is NULL */
static void pump(int *done, int msecs)
{
        uint64_t start = rpc_current_time();
        static struct request req;

        while (done ? !*done : rpc_current_time() - start < (uint64_t)msecs) {
                struct pollfd fds[2] = {
                        {.fd = nfs_get_fd(nfs), .events = nfs_which_events(nfs)},
                        {.fd = srv.fd, .events = POLLIN}
                };
                int timeout = nfs_get_poll_timeout(nfs);

                CHECK(rpc_current_time() - start < 30000);
                if (timeout < 0 || timeout > 20) {
                        timeout = 20;
                }
                CHECK(poll(fds, 2, timeout) >= 0);
                CHECK(nfs_service(nfs, fds[0].revents) == 0);
                if (fds[1].revents & POLLIN) {
                        receive(&req);
                        if (srv.hold_writes && req.op == OP_WRITE) {
                                CHECK(srv.nheld < MAX_HELD);
                                srv.held[srv.nheld++] = req;
                        } else {
                                answer(&req);
                        }
                }
        }
}

static void release_held(void)
{
        int i;

        for (i = 0; i < srv.nheld; i++) {
                answer(&srv.held[i]);
        }
        srv.nheld = 0;
        srv.hold_writes = 0;
}

static void done_cb(int status, struct nfs_context *ctx, void *data,
                    void *private_data)
{
        struct result *r = private_data;

        (void)ctx;
        (void)data;
        CHECK(!__atomic_load_n(&r->done, __ATOMIC_ACQUIRE));
        r->status = status;
        __atomic_store_n(&r->done, 1, __ATOMIC_RELEASE);
}

static struct nfsfh *open_file(const char *stateid)
{
        struct nfsfh *fh = calloc(1, sizeof(*fh));

        CHECK(fh != NULL);
        fh->fh.val = strdup("file");
        fh->fh.len = 4;
        fh->stateid.seqid = 1;
        memcpy(fh->stateid.other, stateid, 12);
        return fh;
}

static void setup(uint64_t resend)
{
        int pair[2];

        memset(&srv, 0, sizeof(srv));
        srv.verf = 1;
        srv.rpc = rpc_init_context();
        CHECK(srv.rpc != NULL);
#ifdef HAVE_MULTITHREADING
        pthread_mutex_init(&srv.lock, NULL);
#endif
        nfs = nfs_init_context();
        CHECK(nfs != NULL);
        nfs->nfsi->version = NFS_V4;
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        rpc_set_fd(nfs->rpc, pair[0]);
        nfs->rpc->is_connected = 1;
        nfs->rpc->program = NFS4_PROGRAM;
        nfs->rpc->version = NFS_V4;
        srv.fd = pair[1];
        nfs_set_resend_unstable(nfs, resend);
}

static void teardown(void)
{
        CHECK(nfs->nfsi->nfs4_files == NULL && nfs->nfsi->unstable_bytes == 0);
        nfs_destroy_context(nfs);
        rpc_destroy_context(srv.rpc);
        close(srv.fd);
}

static int write_sync(struct nfsfh *fh, const void *buf, size_t count,
                      uint64_t offset)
{
        struct result r = {0};

        CHECK(nfs_pwrite_async(nfs, fh, buf, count, offset, done_cb, &r) == 0);
        pump(&r.done, 0);
        return r.status;
}

static int fsync_sync(struct nfsfh *fh)
{
        struct result r = {0};

        CHECK(nfs_fsync_async(nfs, fh, done_cb, &r) == 0);
        pump(&r.done, 0);
        return r.status;
}

static int close_sync(struct nfsfh *fh)
{
        struct result r = {0};

        CHECK(nfs_close_async(nfs, fh, done_cb, &r) == 0);
        pump(&r.done, 0);
        return r.status;
}

static void fill(char *buf, char c, size_t count)
{
        memset(buf, c, count);
}

static int range_is(uint64_t offset, size_t count, char c)
{
        size_t i;

        for (i = 0; i < count; i++) {
                if (srv.data[offset + i] != c) {
                        return 0;
                }
        }
        return 1;
}

/* Without resend-unstable libnfs does what it always did */
static void test_disabled(void)
{
        struct nfsfh *fh;
        char buf[8192];

        setup(0);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        CHECK(fh->file == NULL && nfs->nfsi->unstable_bytes == 0);
        crash(0);
        CHECK(fsync_sync(fh) == 0);
        CHECK(srv.writes == 1 && srv.commits == 1);
        CHECK(close_sync(fh) == 0);
        teardown();
        puts("PASS: disabled by default");
}

static void test_commit_ok(void)
{
        struct nfsfh *fh;
        char buf[8192];

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        CHECK(nfs->nfsi->unstable_bytes == sizeof(buf));
        CHECK(fsync_sync(fh) == 0);
        CHECK(nfs->nfsi->unstable_bytes == 0);
        CHECK(srv.writes == 1 && srv.commits == 1);
        CHECK(close_sync(fh) == 0);
        CHECK(srv.commits == 2 && !srv.last_close.with_commit);
        CHECK(nfs->nfsi->nfs4_files == NULL);
        teardown();
        puts("PASS: data a COMMIT covered is dropped");
}

static void test_resend(void)
{
        struct nfsfh *fh;
        char buf[8192];

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        crash(0);
        CHECK(range_is(0, sizeof(buf), 0));
        CHECK(fsync_sync(fh) == 0);
        CHECK(range_is(0, sizeof(buf), 1));
        CHECK(srv.writes == 2 && srv.commits == 1);
        CHECK(srv.last_write.stable == FILE_SYNC4 && !srv.last_write.anonymous);
        CHECK(nfs->nfsi->unstable_bytes == 0);
        CHECK(close_sync(fh) == 0);
        teardown();
        puts("PASS: lost data is written again as FILE_SYNC4");
}

/* Only what no newer WRITE replaced is written again */
static void test_newer_write_wins(void)
{
        struct nfsfh *fh;
        char old[8192], new[4096];

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(old, 1, sizeof(old));
        fill(new, 2, sizeof(new));
        CHECK(write_sync(fh, old, sizeof(old), 0) == (int)sizeof(old));
        crash(0);
        CHECK(write_sync(fh, new, sizeof(new), 2048) == (int)sizeof(new));
        CHECK(fsync_sync(fh) == 0);
        CHECK(range_is(0, 2048, 1));
        CHECK(range_is(2048, 4096, 2));
        CHECK(range_is(6144, 2048, 1));
        CHECK(srv.writes == 4);
        CHECK(close_sync(fh) == 0);
        teardown();
        puts("PASS: a resend never overwrites newer data");
}

/* Two opens of one file share what is kept */
static void test_two_opens(void)
{
        struct nfsfh *fh1, *fh2;
        char old[8192], new[8192];

        setup(1 << 20);
        fh1 = open_file("openstateid1");
        fh2 = open_file("openstateid2");
        fill(old, 1, sizeof(old));
        fill(new, 2, sizeof(new));
        CHECK(write_sync(fh1, old, sizeof(old), 0) == (int)sizeof(old));
        crash(0);
        CHECK(write_sync(fh2, new, sizeof(new), 0) == (int)sizeof(new));
        CHECK(fh1->file == fh2->file);
        CHECK(fsync_sync(fh2) == 0);
        CHECK(fsync_sync(fh1) == 0);
        CHECK(range_is(0, sizeof(new), 2));
        CHECK(srv.writes == 2);
        CHECK(close_sync(fh1) == 0);
        CHECK(nfs->nfsi->nfs4_files != NULL);
        CHECK(close_sync(fh2) == 0);
        CHECK(nfs->nfsi->nfs4_files == NULL);
        teardown();
        puts("PASS: opens of one file share kept data");
}

/*
 * The resend waits for WRITEs in flight, and WRITEs issued meanwhile wait for
 * the resend, so lost data never lands after newer data.
 */
static void test_barrier(void)
{
        struct nfsfh *fh;
        char old[8192], new[8192], late[4096];
        struct result w = {0}, f = {0}, l = {0};

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(old, 1, sizeof(old));
        fill(new, 2, sizeof(new));
        fill(late, 3, sizeof(late));
        CHECK(write_sync(fh, old, sizeof(old), 0) == (int)sizeof(old));
        crash(0);

        srv.hold_writes = 1;
        CHECK(nfs_pwrite_async(nfs, fh, new, sizeof(new), 4096, done_cb, &w) == 0);
        pump(NULL, 100);
        CHECK(srv.nheld == 1);
        CHECK(nfs_fsync_async(nfs, fh, done_cb, &f) == 0);
        pump(NULL, 100);
        CHECK(srv.commits == 1 && !f.done);
        CHECK(fh->file->resending && fh->file->draining != NULL);
        CHECK(nfs_pwrite_async(nfs, fh, late, sizeof(late), 32768, done_cb, &l) == 0);
        pump(NULL, 100);
        CHECK(srv.nheld == 1 && fh->file->deferred != NULL);

        release_held();
        pump(&f.done, 0);
        pump(&l.done, 0);
        CHECK(w.done && w.status == (int)sizeof(new));
        CHECK(f.status == 0 && l.status == (int)sizeof(late));
        CHECK(range_is(0, 4096, 1));
        CHECK(range_is(4096, 8192, 2));
        CHECK(range_is(32768, 4096, 3));
        CHECK(close_sync(fh) == 0);
        teardown();
        puts("PASS: lost data never lands after newer data");
}

static void test_grace(void)
{
        struct nfsfh *fh;
        char buf[8192];

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        crash(0);
        srv.write_error = NFS4ERR_GRACE;
        srv.write_errors = 2;
        CHECK(fsync_sync(fh) == 0);
        CHECK(srv.writes == 4 && range_is(0, sizeof(buf), 1));
        CHECK(srv.write_times[2] - srv.write_times[1] >= 100);
        CHECK(srv.write_times[3] - srv.write_times[2] >= 200);
        CHECK(close_sync(fh) == 0);
        teardown();
        puts("PASS: NFS4ERR_GRACE is retried with backoff");
}

static void test_lost_state(void)
{
        struct nfsfh *fh;
        char buf[8192];

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        crash(1);
        CHECK(fsync_sync(fh) == 0);
        CHECK(srv.writes == 3 && srv.last_write.anonymous);
        CHECK(range_is(0, sizeof(buf), 1));
        CHECK(close_sync(fh) == 0);
        teardown();
        puts("PASS: lost open state falls back to the anonymous stateid");
}

/* Like the kernel, a failure drops the data and is reported once */
static void test_resend_refused(void)
{
        struct nfsfh *fh;
        char buf[8192];

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        crash(0);
        srv.write_error = NFS4ERR_ACCESS;
        srv.write_errors = 1;
        CHECK(fsync_sync(fh) == -EACCES);
        CHECK(nfs->nfsi->unstable_bytes == 0);
        CHECK(fsync_sync(fh) == 0);
        CHECK(close_sync(fh) == 0);
        teardown();
        puts("PASS: a refused resend fails fsync and drops the data");
}

/* A server reporting more than was sent must not make us read past it */
static void test_over_report(void)
{
        struct nfsfh *fh;
        long page = sysconf(_SC_PAGESIZE);
        char *map, *buf;

        setup(1 << 20);
        fh = open_file("openstateid1");
        map = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(map != MAP_FAILED);
        CHECK(mprotect(map + page, page, PROT_NONE) == 0);
        buf = map + page - 4096;
        fill(buf, 1, 4096);
        srv.over_report = 8192;
        CHECK(write_sync(fh, buf, 4096, 0) == 4096);
        CHECK(nfs->nfsi->unstable_bytes == 4096);
        srv.over_report = 0;
        CHECK(close_sync(fh) == 0);
        munmap(map, 2 * page);
        teardown();
        puts("PASS: an over-reported WRITE count is clamped");
}

/* Over the limit a WRITE waits for a COMMIT, and never fails because of it */
static void test_limit(void)
{
        struct nfsfh *fh;
        char buf[8192];

        setup(16384);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 8192) == (int)sizeof(buf));
        CHECK(srv.commits == 0);
        CHECK(write_sync(fh, buf, sizeof(buf), 16384) == (int)sizeof(buf));
        CHECK(srv.commits == 1 && nfs->nfsi->unstable_bytes == 0);

        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 8192) == (int)sizeof(buf));
        srv.commit_error = NFS4ERR_IO;
        CHECK(write_sync(fh, buf, sizeof(buf), 16384) == (int)sizeof(buf));
        CHECK(srv.commits == 2 && nfs->nfsi->unstable_bytes == 0);
        CHECK(fsync_sync(fh) == -EIO);
        CHECK(fsync_sync(fh) == 0);
        CHECK(close_sync(fh) == 0);
        teardown();
        puts("PASS: the memory limit holds WRITEs back without failing them");
}

/* close waits for the resend, it frees the handle the resend uses */
static void test_close_during_resend(void)
{
        struct nfsfh *fh;
        char buf[8192];
        struct result f = {0}, c = {0};

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        crash(0);
        srv.hold_writes = 1;
        CHECK(nfs_fsync_async(nfs, fh, done_cb, &f) == 0);
        pump(NULL, 100);
        CHECK(srv.nheld == 1 && fh->file->unstable != NULL);
        CHECK(nfs_close_async(nfs, fh, done_cb, &c) == 0);
        pump(NULL, 100);
        CHECK(srv.closes == 0);
        release_held();
        pump(&f.done, 0);
        pump(&c.done, 0);
        CHECK(f.status == 0 && c.status == 0 && srv.closes == 1);
        CHECK(range_is(0, sizeof(buf), 1));
        teardown();
        puts("PASS: close waits for lost data to be written again");
}

/* CLOSE of state the server lost after a restart leaves nothing open */
static void test_close_lost_state(void)
{
        struct nfsfh *fh;
        char buf[8192];

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        crash(1);
        srv.close_error = NFS4ERR_STALE_STATEID;
        CHECK(close_sync(fh) == 0);
        CHECK(srv.closes == 1 && range_is(0, sizeof(buf), 1));
        teardown();

        setup(0);
        fh = open_file("openstateid1");
        srv.close_error = NFS4ERR_EXPIRED;
        CHECK(close_sync(fh) == 0);
        teardown();

        setup(0);
        fh = open_file("openstateid1");
        srv.close_error = NFS4ERR_IO;
        CHECK(close_sync(fh) == -EIO);
        teardown();
        puts("PASS: CLOSE of lost open state succeeds");
}

/* Destroying the context fails a COMMIT that waits for a retry */
static void test_destroy_during_retry(void)
{
        struct nfsfh *fh;
        char buf[8192];
        struct result f = {0};

        setup(1 << 20);
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        crash(0);
        srv.write_error = NFS4ERR_GRACE;
        srv.write_errors = 100;
        CHECK(nfs_fsync_async(nfs, fh, done_cb, &f) == 0);
        pump(NULL, 150);
        CHECK(!f.done && nfs->rpc->timers != NULL);
        nfs_destroy_context(nfs);
        CHECK(f.done && f.status < 0);
        rpc_destroy_context(srv.rpc);
        close(srv.fd);
        free(fh->fh.val);
        free(fh);

        /* close frees its handle even when the context goes first */
        setup(1 << 20);
        fh = open_file("openstateid1");
        CHECK(write_sync(fh, buf, sizeof(buf), 0) == (int)sizeof(buf));
        crash(0);
        srv.write_error = NFS4ERR_GRACE;
        srv.write_errors = 100;
        memset(&f, 0, sizeof(f));
        CHECK(nfs_close_async(nfs, fh, done_cb, &f) == 0);
        pump(NULL, 150);
        CHECK(!f.done && srv.closes == 0);
        nfs_destroy_context(nfs);
        CHECK(f.done && f.status < 0);
        rpc_destroy_context(srv.rpc);
        close(srv.fd);
        puts("PASS: destroy fails a pending retry");
}

#ifdef HAVE_MULTITHREADING
static int serving, sem_taken;
static pthread_barrier_t barrier;
static struct nfsfh *shared_fh;

static void *serve_thread(void *arg)
{
        static struct request req;

        (void)arg;
        while (__atomic_load_n(&serving, __ATOMIC_ACQUIRE)) {
                struct pollfd fd = {.fd = srv.fd, .events = POLLIN};

                if (poll(&fd, 1, 20) == 1) {
                        receive(&req);
                        answer(&req);
                }
        }
        return NULL;
}

static void post_open_sem(struct rpc_context *rpc, int status, void *data,
                          void *private_data)
{
        (void)rpc;
        (void)status;
        (void)data;
        (void)private_data;
        nfs_mt_sem_post(&nfs->nfsi->nfs4_open_call_sem);
}

/* Like an OPEN in flight, whose reply only the service thread processes */
static void *hold_open_sem(void *arg)
{
        static struct rpc_timer timer;

        (void)arg;
        nfs_mt_sem_wait(&nfs->nfsi->nfs4_open_call_sem);
        __atomic_store_n(&sem_taken, 1, __ATOMIC_RELEASE);
        rpc_add_timer(nfs->rpc, &timer, 200, post_open_sem, NULL);
        return NULL;
}

static void wait_done(struct result *r)
{
        uint64_t start = rpc_current_time();

        while (!__atomic_load_n(&r->done, __ATOMIC_ACQUIRE)) {
                CHECK(rpc_current_time() - start < 10000);
                usleep(1000);
        }
}

/* Each writer owns 16 KiB, writes it, then fsyncs after the crash */
static void *writer(void *arg)
{
        long id = (long)arg;
        char buf[4096];
        int i;

        fill(buf, (char)(id + 1), sizeof(buf));
        for (i = 0; i < 4; i++) {
                CHECK(nfs_pwrite(nfs, shared_fh, buf, sizeof(buf),
                                 id * 16384 + i * 4096) == (int)sizeof(buf));
        }
        pthread_barrier_wait(&barrier);
        pthread_barrier_wait(&barrier);
        CHECK(nfs_fsync(nfs, shared_fh) == 0);
        return NULL;
}

static void test_multithreaded(void)
{
        pthread_t server, holder, writers[4];
        struct nfsfh *fh;
        char buf[8192];
        struct result w = {0}, c = {0};
        long i;

        setup(1 << 20);
        __atomic_store_n(&serving, 1, __ATOMIC_RELEASE);
        CHECK(pthread_create(&server, NULL, serve_thread, NULL) == 0);
        CHECK(nfs_mt_service_thread_start(nfs) == 0);

        /* close with lost data while another thread has an OPEN pending */
        fh = open_file("openstateid1");
        fill(buf, 1, sizeof(buf));
        CHECK(nfs_pwrite_async(nfs, fh, buf, sizeof(buf), 0, done_cb, &w) == 0);
        wait_done(&w);
        crash(0);
        CHECK(pthread_create(&holder, NULL, hold_open_sem, NULL) == 0);
        while (!__atomic_load_n(&sem_taken, __ATOMIC_ACQUIRE)) {
                usleep(1000);
        }
        CHECK(nfs_close_async(nfs, fh, done_cb, &c) == 0);
        wait_done(&c);
        CHECK(c.status == 0);
        pthread_join(holder, NULL);
        srv_lock();
        CHECK(range_is(0, sizeof(buf), 1));
        srv_unlock();

        /* concurrent writers and fsyncs across a crash */
        shared_fh = open_file("openstateid2");
        pthread_barrier_init(&barrier, NULL, 5);
        for (i = 0; i < 4; i++) {
                CHECK(pthread_create(&writers[i], NULL, writer, (void *)i) == 0);
        }
        pthread_barrier_wait(&barrier);
        crash(0);
        pthread_barrier_wait(&barrier);
        for (i = 0; i < 4; i++) {
                pthread_join(writers[i], NULL);
        }
        srv_lock();
        for (i = 0; i < 4; i++) {
                CHECK(range_is(i * 16384, 16384, (char)(i + 1)));
        }
        srv_unlock();
        CHECK(nfs_close(nfs, shared_fh) == 0);

        nfs_mt_service_thread_stop(nfs);
        __atomic_store_n(&serving, 0, __ATOMIC_RELEASE);
        pthread_join(server, NULL);
        pthread_barrier_destroy(&barrier);
        teardown();
        puts("PASS: multithreaded close, writes and fsyncs");
}
#endif /* HAVE_MULTITHREADING */

int main(void)
{
        test_disabled();
        test_commit_ok();
        test_resend();
        test_newer_write_wins();
        test_two_opens();
        test_barrier();
        test_grace();
        test_lost_state();
        test_resend_refused();
        test_over_report();
        test_limit();
        test_close_during_resend();
        test_close_lost_state();
        test_destroy_during_retry();
#ifdef HAVE_MULTITHREADING
        test_multithreaded();
#endif
        puts("PASS: NFSv4 unstable write resend");
        return 0;
}
