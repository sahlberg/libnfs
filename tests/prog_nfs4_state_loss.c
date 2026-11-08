/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A local RPC peer verifies terminal client-state loss without a real server. */
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
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#define CHECK(x) do { if (!(x)) { \
        fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)
struct answer { int calls, status; };

#if defined(__linux__) && defined(HAVE_MULTITHREADING)
static libnfs_sem_t service_paused, service_resume;

/* Pause the real background loop at its error backoff, without a timed sleep. */
unsigned int sleep(unsigned int seconds)
{
        CHECK(seconds == 5);
        CHECK(nfs_mt_sem_post(&service_paused) == 0);
        CHECK(nfs_mt_sem_wait(&service_resume) == 0);
        return 0;
}
#endif

static void completed(int status, struct nfs_context *nfs, void *data, void *opaque)
{
        struct answer *a = opaque;

        (void)nfs;
        (void)data;
        CHECK(++a->calls == 1);
        a->status = status;
}

static void pending_failed(int status, struct nfs_context *nfs, void *data,
                           void *opaque)
{
        CHECK(status < 0);
        completed(status, nfs, data, opaque);
        /* Cleanup must not hide the reason the context became unusable. */
        rpc_set_error(nfs->rpc, "cleanup callback diagnostic");
        nfs_set_error(nfs, "cleanup callback diagnostic");
}

static void transfer(int fd, void *buffer, size_t size, int writing)
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

static uint32_t receive_request(int peer, char *request, size_t capacity)
{
        uint32_t marker, size;

        transfer(peer, &marker, 4, 0);
        CHECK(ntohl(marker) & 0x80000000u);
        size = ntohl(marker) & 0x7fffffffu;
        CHECK(size <= capacity);
        transfer(peer, request, size, 0);
        return size;
}

static void respond(struct rpc_context *rpc, int peer, nfs_opnum4 failed_op,
                    nfsstat4 error)
{
        char request[4096], wire[4096];
        uint32_t marker, size;
        ZDR in, out;
        struct rpc_msg call = {0}, reply = {0};
        COMPOUND4args args = {0};
        COMPOUND4res result = {0};
        nfs_resop4 ops[16] = {0};
        unsigned int i;

        size = receive_request(peer, request, sizeof(request));
        zdrmem_create(&in, request, size, ZDR_DECODE);
        CHECK(zdr_callmsg(rpc, &in, &call));
        CHECK(zdr_COMPOUND4args(&in, &args));
        CHECK(args.minorversion == 0 && args.argarray.argarray_len <= 16);
        for (i = 0; i < args.argarray.argarray_len; i++) {
                nfs_argop4 *arg = &args.argarray.argarray_val[i];
                nfsstat4 status = arg->argop == failed_op ? error : NFS4_OK;

                ops[i].resop = arg->argop;
                switch (arg->argop) {
                case OP_PUTFH: ops[i].nfs_resop4_u.opputfh.status = NFS4_OK; break;
                case OP_LOOKUP: ops[i].nfs_resop4_u.oplookup.status = NFS4_OK; break;
                case OP_GETATTR: ops[i].nfs_resop4_u.opgetattr.status = status; break;
                case OP_ACCESS:
                        ops[i].nfs_resop4_u.opaccess.status = NFS4_OK;
                        ops[i].nfs_resop4_u.opaccess.ACCESS4res_u.resok4.supported =
                        ops[i].nfs_resop4_u.opaccess.ACCESS4res_u.resok4.access =
                                arg->nfs_argop4_u.opaccess.access;
                        break;
                case OP_OPEN: ops[i].nfs_resop4_u.opopen.status = status; break;
                case OP_RENEW: ops[i].nfs_resop4_u.oprenew.status = status; break;
                default: CHECK(0);
                }
                result.resarray.resarray_len = i + 1;
                if (status != NFS4_OK) {
                        result.status = status;
                        break;
                }
        }
        result.resarray.resarray_val = ops;
        reply.xid = call.xid; reply.direction = REPLY;
        reply.body.rbody.stat = MSG_ACCEPTED;
        reply.body.rbody.reply.areply.stat = SUCCESS;
        reply.body.rbody.reply.areply.reply_data.results.where = (char *)&result;
        reply.body.rbody.reply.areply.reply_data.results.proc = (zdrproc_t)zdr_COMPOUND4res;
        zdrmem_create(&out, wire, sizeof(wire), ZDR_ENCODE);
        CHECK(zdr_replymsg(rpc, &out, &reply));
        size = zdr_getpos(&out);
        marker = htonl(size | 0x80000000u);
        transfer(peer, &marker, 4, 1);
        transfer(peer, wire, size, 1);
        zdr_destroy(&out);
        zdr_destroy(&in);
}

static struct nfs_context *fixture(int *peer)
{
        struct nfs_context *nfs = nfs_init_context();
        int pair[2];

        CHECK(nfs && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        CHECK(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
        nfs->nfsi->version = NFS_V4;
        nfs->nfsi->clientid = 1234;
        nfs->nfsi->rootfh.len = 4;
        nfs->nfsi->rootfh.val = strdup("root");
        CHECK(nfs->nfsi->rootfh.val != NULL);
        rpc_set_fd(nfs->rpc, pair[0]);
        nfs->rpc->is_connected = 1;
        rpc_set_resiliency(nfs->rpc, -1, 60000, 2);
        *peer = pair[1];
        return nfs;
}

static void open_result(nfsstat4 error, int terminal)
{
        struct answer a = {0}, pending = {0}, unsent = {0};
        struct nfsfh fh = {0};
        int peer, ret;
        struct nfs_context *nfs = fixture(&peer);

        CHECK(nfs_open_async(nfs, "/file", 0, completed, &a) == 0);
        if (terminal) {
                CHECK(nfs_fstat64_async(nfs, &fh, pending_failed, &pending) == 0);
                rpc_disable_socket(nfs->rpc, 1);
                CHECK(nfs_fstat64_async(nfs, &fh, pending_failed, &unsent) == 0);
                rpc_disable_socket(nfs->rpc, 0);
        }
        respond(nfs->rpc, peer, OP_OPEN, error);
        ret = nfs_service(nfs, POLLIN);
        CHECK(ret == (terminal ? -1 : 0));
        CHECK(a.calls == 1 && a.status == nfsstat4_to_errno(error));
        CHECK(nfs->rpc->is_connected); /* No transport reconnect repairs this. */
        if (terminal) {
                CHECK(strstr(nfs_get_error(nfs), nfsstat4_to_str(error)) != NULL);
                CHECK(pending.calls == 1 && pending.status == -EFAULT);
                CHECK(unsent.calls == 1 && unsent.status == -EFAULT);
                CHECK(rpc_queue_length(nfs->rpc) == 0);
                CHECK(nfs_service(nfs, 0) == -1);
        } else {
                CHECK(nfs->rpc->nfs40_state_error == 0);
                CHECK(nfs_fstat64_async(nfs, &fh, completed, &pending) == 0);
                respond(nfs->rpc, peer, OP_GETATTR, NFS4_OK);
                CHECK(nfs_service(nfs, POLLIN) == 0);
                CHECK(pending.calls == 1 && pending.status == 0);
        }
        nfs_destroy_context(nfs);
        CHECK(pending.calls == 1 && unsent.calls == terminal);
        close(peer);
}

static void stat_result(nfsstat4 error)
{
        struct answer result = {0};
        struct nfsfh fh = {0};
        int peer;
        struct nfs_context *nfs = fixture(&peer);


        /* The shared error helper is separate from pathname OPEN handling. */
        CHECK(nfs_fstat64_async(nfs, &fh, completed, &result) == 0);
        respond(nfs->rpc, peer, OP_GETATTR, error);
        CHECK(nfs_service(nfs, POLLIN) == -1);
        CHECK(result.calls == 1 && result.status == nfsstat4_to_errno(error));
        CHECK(strstr(nfs_get_error(nfs), nfsstat4_to_str(error)) != NULL);
        nfs_destroy_context(nfs);
        close(peer);
}

static void renew_result(nfsstat4 error)
{
        struct answer pending = {0};
        struct nfsfh fh = {0};
        int peer;
        struct nfs_context *nfs = fixture(&peer);
        CHECK(rpc_nfs40_save_renew_auth(nfs->rpc) == 0);
        rpc_nfs40_start_renew(nfs->rpc, 1234, 90);
        nfs->rpc->nfs40_renew_due = rpc_current_time();
        CHECK(nfs_service(nfs, 0) == 0);
        CHECK(nfs_fstat64_async(nfs, &fh, pending_failed, &pending) == 0);
        respond(nfs->rpc, peer, OP_RENEW, error);
        CHECK(nfs_service(nfs, POLLIN) == -1);
        CHECK(!nfs->rpc->nfs40_renew_enabled);
        CHECK(strstr(nfs_get_error(nfs), nfsstat4_to_str(error)) != NULL);
        CHECK(pending.calls == 1 && pending.status == -EFAULT);
        nfs_destroy_context(nfs);
        CHECK(pending.calls == 1);
        close(peer);
}

#if defined(__linux__) && defined(HAVE_MULTITHREADING)
struct sync_result {
        struct nfs_context *nfs;
        struct nfsfh fh;
        int status;
};

static void *sync_stat(void *opaque)
{
        struct sync_result *result = opaque;
        struct nfs_stat_64 st;

        result->status = nfs_fstat64(result->nfs, &result->fh, &st);
        return NULL;
}

static void background_result(nfsstat4 error)
{
        struct answer first = {0}, pending = {0};
        struct sync_result sync = {0};
        struct nfsfh fh = {0};
        struct nfs_context *nfs;
        pthread_t caller;
        char request[4096];
        int peer;

        CHECK(nfs_mt_sem_init(&service_paused, 0) == 0);
        CHECK(nfs_mt_sem_init(&service_resume, 0) == 0);
        nfs = fixture(&peer);
        CHECK(nfs_open_async(nfs, "/file", 0, completed, &first) == 0);
        CHECK(nfs_fstat64_async(nfs, &fh, pending_failed, &pending) == 0);
        respond(nfs->rpc, peer, OP_OPEN, error);
        receive_request(peer, request, sizeof(request)); /* Pending FSTAT. */
        CHECK(nfs_mt_service_thread_start(nfs) == 0);
        CHECK(nfs_mt_sem_wait(&service_paused) == 0);
        CHECK(first.calls == 1 && first.status == nfsstat4_to_errno(error));
        CHECK(pending.calls == 1 && pending.status == -EFAULT);
        CHECK(rpc_queue_length(nfs->rpc) == 0);
        CHECK(strstr(nfs_get_error(nfs), nfsstat4_to_str(error)) != NULL);

        /* A synchronous caller must fail too, even though the background
         * thread remains alive and the server never replies to its request.
         */
        sync.nfs = nfs;
        CHECK(pthread_create(&caller, NULL, sync_stat, &sync) == 0);
        receive_request(peer, request, sizeof(request));
        CHECK(nfs_mt_sem_post(&service_resume) == 0);
        CHECK(nfs_mt_sem_wait(&service_paused) == 0);
        CHECK(pthread_join(caller, NULL) == 0);
        CHECK(sync.status < 0 && rpc_queue_length(nfs->rpc) == 0);

        /* Release the test's backoff pause while using the normal stop/join. */
        nfs->rpc->multithreading_enabled = 0;
        CHECK(nfs_mt_sem_post(&service_resume) == 0);
        nfs_mt_service_thread_stop(nfs);
        nfs_destroy_context(nfs);
        CHECK(first.calls == 1 && pending.calls == 1);
        close(peer);
        CHECK(nfs_mt_sem_destroy(&service_paused) == 0);
        CHECK(nfs_mt_sem_destroy(&service_resume) == 0);
}
#endif

int main(void)
{
        alarm(20);
        open_result(NFS4ERR_STALE_CLIENTID, 1);
        open_result(NFS4ERR_EXPIRED, 1);
        open_result(NFS4ERR_NOENT, 0);
        open_result(NFS4ERR_IO, 0);
        open_result(NFS4ERR_STALE, 0);
        open_result(NFS4ERR_GRACE, 0);
        stat_result(NFS4ERR_STALE_CLIENTID);
        stat_result(NFS4ERR_EXPIRED);
        renew_result(NFS4ERR_STALE_CLIENTID);
        renew_result(NFS4ERR_EXPIRED);
#if defined(__linux__) && defined(HAVE_MULTITHREADING)
        background_result(NFS4ERR_STALE_CLIENTID);
        background_result(NFS4ERR_EXPIRED);
        puts("PASS: background async and synchronous callers fail without hanging");
#endif
        puts("PASS: OPEN/GETATTR/RENEW state loss is terminal; ordinary errors remain local");
        return 0;
}
#endif
