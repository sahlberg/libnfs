/* SPDX-License-Identifier: GPL-3.0-or-later */
/* CLOSE ownership and allocation failures, without a server or mount. */
#define _GNU_SOURCE
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifndef __linux__
int main(void) { return 77; }
#else
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define CHECK(x) do { if (!(x)) { \
        fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

static unsigned int fail_after, allocation_failed;
static void *watched_handle, *watched_value;
static unsigned int handle_frees, value_frees;

/* Interpose calloc in the real protocol paths. A volatile function pointer
 * prevents the compiler folding malloc + memset back into calloc.
 */
void *calloc(size_t count, size_t size)
{
        void *(*volatile allocate)(size_t) = malloc;
        void *p;

        if ((size && count > SIZE_MAX / size) ||
            (fail_after && --fail_after == 0)) {
                allocation_failed = 1;
                errno = ENOMEM;
                return NULL;
        }
        p = allocate(count * size);
        if (p)
                memset(p, 0, count * size);
        return p;
}

static void observed_free(void *p)
{
        if (p && p == watched_handle) {
                watched_handle = NULL;
                handle_frees++;
        }
        if (p && p == watched_value) {
                watched_value = NULL;
                value_frees++;
        }
        free(p);
}

/* Compile the real public dispatch and handle destructor with free observed.
 * Protocol implementations and the synchronous wrapper come from libnfs.
 */
#define free observed_free
#include "../lib/libnfs.c"
#undef free

struct result { int calls, status; };

static void completed(int status, struct nfs_context *nfs, void *data, void *opaque)
{
        struct result *result = opaque;

        (void)nfs;
        (void)data;
        CHECK(++result->calls == 1);
        result->status = status;
}

static struct nfs_context *context(int version)
{
        struct nfs_context *nfs = nfs_init_context();

        CHECK(nfs != NULL && nfs_set_version(nfs, version) == 0);
#ifdef HAVE_NFS4_2
        if (version == NFS_V4_2) {
                sessionid4 session = {1};

                CHECK(nfs4_session_init(nfs->rpc, session, 2) == 0);
        }
#endif
        rpc_disable_socket(nfs->rpc, 1); /* Keep successful submissions queued. */
        return nfs;
}

static struct nfsfh *handle(int dirty, int malformed)
{
        struct nfsfh *fh = calloc(1, sizeof(*fh));

        CHECK(fh != NULL);
        fh->fh.len = malformed ? NFS4_FHSIZE + 1 : 4;
        fh->fh.val = calloc(1, fh->fh.len);
        CHECK(fh->fh.val != NULL);
        fh->is_dirty = dirty;
        CHECK(!watched_handle && !watched_value);
        watched_handle = fh;
        watched_value = fh->fh.val;
        handle_frees = value_frees = 0;
        return fh;
}

static void consumed(void)
{
        CHECK(handle_frees == 1 && value_frees == 1);
        CHECK(!watched_handle && !watched_value);
}

static void submission_failures(int version)
{
        unsigned int failure, limit = 0;

        /* Sweep every calloc used to submit CLOSE, through the first success. */
        for (failure = 1; failure <= 16; failure++) {
                struct nfs_context *nfs = context(version);
                struct nfsfh *fh = handle(1, 0);
                struct result result = {0};
                int ret;

                fail_after = failure;
                allocation_failed = 0;
                ret = nfs_close_async(nfs, fh, completed, &result);
                fail_after = 0;
                CHECK(result.calls == 0);
                if (allocation_failed) {
                        CHECK(ret < 0 && rpc_queue_length(nfs->rpc) == 0);
                        consumed();
                } else {
                        CHECK(ret == 0 && handle_frees == 0 && value_frees == 0);
                        limit = failure;
                }
                nfs_destroy_context(nfs);
                consumed();
                CHECK(result.calls == (ret == 0));
                if (limit)
                        break;
        }
        CHECK(limit >= (version == NFS_V3 ? 3 : 2));

        /* Without a running service thread, sync setup adds no calloc calls. */
        for (failure = 1; failure < limit; failure++) {
                struct nfs_context *nfs = context(version);
                struct nfsfh *fh = handle(1, 0);

                fail_after = failure;
                allocation_failed = 0;
                CHECK(nfs_close(nfs, fh) < 0);
                fail_after = 0;
                CHECK(allocation_failed && rpc_queue_length(nfs->rpc) == 0);
                consumed();
                nfs_destroy_context(nfs);
                consumed();
        }
}

static void encoding_failure(int version)
{
        struct nfs_context *nfs = context(version);
        struct nfsfh *fh = handle(1, 1);
        struct result result = {0};

        CHECK(nfs_close_async(nfs, fh, completed, &result) < 0);
        CHECK(result.calls == 0 && rpc_queue_length(nfs->rpc) == 0);
        consumed();
        nfs_destroy_context(nfs);
        consumed();
}

static void completion(int version, int error, int destroy)
{
        struct nfs_context *nfs = context(version);
        struct nfsfh *fh = handle(1, 0);
        struct result result = {0};
        struct rpc_pdu *pdu;

        CHECK(nfs_close_async(nfs, fh, completed, &result) == 0);
        CHECK(result.calls == 0 && handle_frees == 0 && value_frees == 0);
        if (!destroy) {
                /* Deliver a decoded reply to the actual queued callback. */
                pdu = nfs->rpc->outqueue.head;
                CHECK(pdu && rpc_find_pdu(nfs->rpc, pdu->xid) == pdu);
                if (version == NFS_V3) {
                        COMMIT3res reply = {0};
                        reply.status = error ? NFS3ERR_IO : NFS3_OK;
                        pdu->cb(nfs->rpc, RPC_STATUS_SUCCESS, &reply,
                                pdu->private_data);
                } else {
                        COMPOUND4res reply = {0};
                        nfs_resop4 ops[3] = {0};
                        unsigned int offset = version == NFS_V4 ? 0 : 1;

                        if (offset) {
                                ops[0].resop = OP_SEQUENCE;
                                ops[0].nfs_resop4_u.opsequence.sr_status = NFS4_OK;
                        }
                        ops[offset].resop = OP_PUTFH;
                        ops[offset].nfs_resop4_u.opputfh.status = NFS4_OK;
                        ops[offset + 1].resop = OP_CLOSE;
                        ops[offset + 1].nfs_resop4_u.opclose.status =
                                error ? NFS4ERR_IO : NFS4_OK;
                        reply.status = error ? NFS4ERR_IO : NFS4_OK;
                        reply.resarray.resarray_len = offset + 2;
                        reply.resarray.resarray_val = ops;
                        pdu->cb(nfs->rpc, RPC_STATUS_SUCCESS, &reply,
                                pdu->private_data);
                }
                rpc_free_pdu(nfs->rpc, pdu);
                CHECK(result.calls == 1 && result.status == (error ? -EIO : 0));
                consumed();
        }
        nfs_destroy_context(nfs);
        CHECK(result.calls == 1);
        if (destroy)
                CHECK(result.status < 0);
        consumed();
}

static void clean_v3(void)
{
        struct nfs_context *nfs = context(NFS_V3);
        struct nfsfh *fh = handle(0, 0);
        struct result result = {0};

        CHECK(nfs_close_async(nfs, fh, completed, &result) == 0);
        CHECK(result.calls == 1 && result.status == 0);
        consumed();
        fh = handle(0, 0);
        CHECK(nfs_close(nfs, fh) == 0);
        consumed();
        nfs_destroy_context(nfs);
        consumed();
}

static void fsync_failure(void)
{
        struct nfs_context *nfs = context(NFS_V3);
        struct nfsfh *fh = handle(1, 1);
        struct result result = {0};

        /* FSYNC submission failure keeps its handle and invokes no callback. */
        CHECK(nfs_fsync_async(nfs, fh, completed, &result) < 0);
        CHECK(result.calls == 0 && handle_frees == 0 && value_frees == 0);
        nfs_free_nfsfh(fh);
        consumed();
        nfs_destroy_context(nfs);
}

#ifdef HAVE_MULTITHREADING
static void sync_setup_failure(void)
{
        struct nfs_context *nfs = context(NFS_V4);
        struct nfsfh *fh = handle(1, 0);

        /* Fail allocation of the synchronous caller's thread-local context. */
        nfs->rpc->multithreading_enabled = 1;
        fail_after = 1;
        allocation_failed = 0;
        CHECK(nfs_close(nfs, fh) < 0);
        fail_after = 0;
        nfs->rpc->multithreading_enabled = 0;
        CHECK(allocation_failed && rpc_queue_length(nfs->rpc) == 0);
        consumed();
        nfs_destroy_context(nfs);
}
#endif

int main(void)
{
        const int versions[] = {NFS_V3, NFS_V4,
#ifdef HAVE_NFS4_2
                                NFS_V4_2,
#endif
        };
        unsigned int i;

        alarm(20);
        clean_v3();
        fsync_failure();
#ifdef HAVE_MULTITHREADING
        sync_setup_failure();
#endif
        for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
                submission_failures(versions[i]);
                encoding_failure(versions[i]);
                completion(versions[i], 0, 0);
                completion(versions[i], 1, 0);
                completion(versions[i], 0, 1);
        }
        puts("PASS: CLOSE consumes handles on submission, setup, completion and cancellation errors");
        return 0;
}
#endif
