/* Exercise the public object API against a deterministic, local RPC peer. */
#define _GNU_SOURCE
#include "config.h"
#if !defined(HAVE_NFS4_2) || defined(WIN32)
int main(void) { return 77; }
#else
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-object.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#ifdef TEST_ALLOC_FAILURE
/* Optional GNU ld --wrap build: fail one allocation during request submission. */
static int allocation_budget = -1;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
char *__real_strdup(const char *);
static int fail_allocation(void)
{
        if (allocation_budget < 0) return 0;
        if (allocation_budget-- != 0) return 0;
        errno = ENOMEM;
        return 1;
}
void *__wrap_malloc(size_t size) { return fail_allocation() ? NULL : __real_malloc(size); }
void *__wrap_calloc(size_t count, size_t size) { return fail_allocation() ? NULL : __real_calloc(count, size); }
char *__wrap_strdup(const char *text) { return fail_allocation() ? NULL : __real_strdup(text); }
#endif

struct completion {
        int calls, status, kind;
        void *value;
        struct nfs_stat_64 attributes;
};

static struct nfs_context *context;
static int peer, malformed, fail_op;
static nfsstat4 fail_status = NFS4ERR_ACCESS;
static unsigned request_count;
static nfs_opnum4 expected[8];
static size_t expected_count;
static const char *base_key = "root";
static const char *reply_key = "file";
static int claim = -1;
static unsigned setattr_mask;
static uint32_t denied_access;
static struct stateid expected_state;

static void complete(int status, struct nfs_context *nfs, void *data, void *opaque)
{
        struct completion *cb = opaque;
        assert(nfs == context && ++cb->calls == 1);
        cb->status = status;
        if (status) return;
        if (cb->kind == 1) {
                struct nfs4_object_result *result = data;
                cb->value = result->object;
                cb->attributes = result->attributes;
        } else if (cb->kind == 2) {
                cb->attributes = *(struct nfs_stat_64 *)data;
        } else if (cb->kind == 3) {
                cb->value = data;
        } else if (cb->kind == 4) {
                assert(!strcmp(data, "target"));
        } else if (cb->kind == 5) {
                struct nfs4_stat_64 *result = data;
                assert(!strcmp(result->nfs_user, "1001"));
                assert(!strcmp(result->nfs_group, "group@example"));
                cb->attributes = result->st;
        }
        if (cb->kind == 1 || cb->kind == 2 || cb->kind == 5) {
                assert(cb->attributes.nfs_uid == 1001);
                assert(cb->attributes.nfs_gid == (uint64_t)-1);
        }
}

static void transfer(int fd, void *buffer, size_t size, int writing)
{
        char *p = buffer;
        while (size) {
                ssize_t count = writing ? write(fd, p, size) : read(fd, p, size);
                if (count < 0 && errno == EINTR) continue;
                assert(count > 0);
                p += count;
                size -= count;
        }
}

static void check_setattr(SETATTR4args *args)
{
        uint32_t bitmap[2] = {0}, value;
        uint64_t large;
        char *owner = NULL;
        ZDR zdr;
        assert(args->stateid.seqid == expected_state.seqid);
        assert(!memcmp(args->stateid.other, expected_state.other, 12));
        zdrmem_create(&zdr, args->obj_attributes.attr_vals.attrlist4_val,
                      args->obj_attributes.attr_vals.attrlist4_len, ZDR_DECODE);
        if (setattr_mask & NFS4_OBJECT_SIZE) {
                bitmap[0] |= 1U << FATTR4_SIZE;
                assert(zdr_uint64_t(&zdr, &large) && large == 123);
        }
        if (setattr_mask & NFS4_OBJECT_MODE) {
                bitmap[1] |= 1U << (FATTR4_MODE - 32);
                assert(zdr_uint32_t(&zdr, &value) && value == 0640);
        }
        if (setattr_mask & NFS4_OBJECT_UID) {
                bitmap[1] |= 1U << (FATTR4_OWNER - 32);
                assert(zdr_string(&zdr, &owner, 31) && !strcmp(owner, "1001"));
                owner = NULL;
        }
        if (setattr_mask & NFS4_OBJECT_GID) {
                bitmap[1] |= 1U << (FATTR4_OWNER_GROUP - 32);
                assert(zdr_string(&zdr, &owner, 31) && !strcmp(owner, "21111"));
        }
        for (unsigned bit = NFS4_OBJECT_ATIME; bit <= NFS4_OBJECT_MTIME; bit <<= 1) {
                unsigned now = bit << 2;
                if (!(setattr_mask & (bit | now))) continue;
                bitmap[1] |= 1U << ((bit == NFS4_OBJECT_ATIME ?
                                     FATTR4_TIME_ACCESS_SET : FATTR4_TIME_MODIFY_SET) - 32);
                assert(zdr_uint32_t(&zdr, &value));
                assert(value == (setattr_mask & now ? SET_TO_SERVER_TIME4 : SET_TO_CLIENT_TIME4));
                if (value == SET_TO_CLIENT_TIME4) {
                        assert(zdr_uint64_t(&zdr, &large) && large == 1700000000);
                        assert(zdr_uint32_t(&zdr, &value) && value == 123456789);
                }
        }
        assert(zdr_getpos(&zdr) == args->obj_attributes.attr_vals.attrlist4_len);
        assert(args->obj_attributes.attrmask.bitmap4_len == 2);
        assert(!memcmp(args->obj_attributes.attrmask.bitmap4_val, bitmap, sizeof(bitmap)));
        zdr_destroy(&zdr);
}

static void serve(void)
{
        char request[8192], reply[8192], attributes[64];
        char *owner = "1001", *group = "group@example";
        uint32_t marker, size, attr_size;
        uint32_t bitmap[2] = {(1U << FATTR4_TYPE) | (1U << FATTR4_SIZE),
                (1U << (FATTR4_OWNER - 32)) | (1U << (FATTR4_OWNER_GROUP - 32))};
        uint32_t type = NF4REG;
        uint64_t length = 123;
        ZDR decoder, encoder, attrs;
        struct rpc_msg call = {0}, response = {0};
        COMPOUND4args args = {0};
        COMPOUND4res result = {0};
        nfs_resop4 ops[8] = {0};
        transfer(peer, &marker, 4, 0);
        marker = ntohl(marker);
        assert(marker & 0x80000000U);
        size = marker & 0x7fffffff;
        assert(size <= sizeof(request));
        transfer(peer, request, size, 0);
        zdrmem_create(&decoder, request, size, ZDR_DECODE);
        assert(zdr_callmsg(context->rpc, &decoder, &call));
        assert(zdr_COMPOUND4args(&decoder, &args));
        assert(args.minorversion == 2 && args.argarray.argarray_len == expected_count);
        zdrmem_create(&attrs, attributes, sizeof(attributes), ZDR_ENCODE);
        assert(zdr_uint32_t(&attrs, &type) && zdr_uint64_t(&attrs, &length));
        assert(zdr_string(&attrs, &owner, 31) && zdr_string(&attrs, &group, 31));
        attr_size = zdr_getpos(&attrs);
        zdr_destroy(&attrs);
        result.resarray.resarray_val = ops;
        for (unsigned i = 0; i < expected_count; i++) {
                nfs_argop4 *arg = &args.argarray.argarray_val[i];
                nfs_resop4 *out = &ops[i];
                assert(arg->argop == expected[i]);
                out->resop = arg->argop;
                result.resarray.resarray_len++;
                if (fail_op == (int)arg->argop) {
                        /* Every operation's result union starts with nfsstat4. */
                        memcpy(&out->nfs_resop4_u, &fail_status, sizeof(fail_status));
                        result.status = fail_status;
                        break;
                }
                switch (arg->argop) {
                case OP_SEQUENCE: {
                        SEQUENCE4args *seq = &arg->nfs_argop4_u.opsequence;
                        SEQUENCE4resok *res = &out->nfs_resop4_u.opsequence.SEQUENCE4res_u.sr_resok4;
                        memcpy(res->sr_sessionid, seq->sa_sessionid, sizeof(sessionid4));
                        res->sr_sequenceid = seq->sa_sequenceid;
                        res->sr_slotid = seq->sa_slotid;
                        res->sr_highest_slotid = res->sr_target_highest_slotid = 1;
                        break;
                }
                case OP_PUTFH:
                        assert(arg->nfs_argop4_u.opputfh.object.nfs_fh4_len == 4);
                        assert(!memcmp(arg->nfs_argop4_u.opputfh.object.nfs_fh4_val,
                                       i == 1 ? base_key : "root", 4));
                        break;
                case OP_LOOKUP:
                        assert(arg->nfs_argop4_u.oplookup.objname.utf8string_len == 5);
                        assert(!memcmp(arg->nfs_argop4_u.oplookup.objname.utf8string_val, "child", 5));
                        break;
                case OP_GETFH:
                        out->nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object.nfs_fh4_val = (char *)reply_key;
                        out->nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object.nfs_fh4_len = 4;
                        break;
                case OP_GETATTR: {
                        fattr4 *attr = &out->nfs_resop4_u.opgetattr.GETATTR4res_u.resok4.obj_attributes;
                        attr->attrmask.bitmap4_len = 2;
                        attr->attrmask.bitmap4_val = bitmap;
                        attr->attr_vals.attrlist4_val = attributes;
                        attr->attr_vals.attrlist4_len = malformed == 1 ? 4 :
                                malformed == 2 ? attr_size - 1 : attr_size;
                        break;
                }
                case OP_OPEN:
                        assert((int)arg->nfs_argop4_u.opopen.claim.claim == claim);
                        out->nfs_resop4_u.opopen.OPEN4res_u.resok4.stateid.seqid = 7;
                        memset(out->nfs_resop4_u.opopen.OPEN4res_u.resok4.stateid.other, 0x42, 12);
                        break;
                case OP_SETATTR: check_setattr(&arg->nfs_argop4_u.opsetattr); break;
                case OP_READLINK:
                        out->nfs_resop4_u.opreadlink.READLINK4res_u.resok4.link.utf8string_val = "target";
                        out->nfs_resop4_u.opreadlink.READLINK4res_u.resok4.link.utf8string_len = 6;
                        break;
                case OP_READDIR:
                        out->nfs_resop4_u.opreaddir.READDIR4res_u.resok4.reply.eof = 1;
                        break;
                case OP_ACCESS:
                        out->nfs_resop4_u.opaccess.ACCESS4res_u.resok4.supported = arg->nfs_argop4_u.opaccess.access;
                        out->nfs_resop4_u.opaccess.ACCESS4res_u.resok4.access = arg->nfs_argop4_u.opaccess.access & ~denied_access;
                        break;
                case OP_CLOSE: case OP_SAVEFH: case OP_RENAME: case OP_LINK:
                case OP_REMOVE: case OP_CREATE: break;
                default: assert(0);
                }
        }
        response.xid = call.xid;
        response.direction = REPLY;
        response.body.rbody.stat = MSG_ACCEPTED;
        response.body.rbody.reply.areply.stat = SUCCESS;
        response.body.rbody.reply.areply.reply_data.results.where = (char *)&result;
        response.body.rbody.reply.areply.reply_data.results.proc = (zdrproc_t)zdr_COMPOUND4res;
        zdrmem_create(&encoder, reply, sizeof(reply), ZDR_ENCODE);
        assert(zdr_replymsg(context->rpc, &encoder, &response));
        size = zdr_getpos(&encoder);
        marker = htonl(size | 0x80000000U);
        transfer(peer, &marker, 4, 1);
        transfer(peer, reply, size, 1);
        zdr_destroy(&encoder);
        zdr_destroy(&decoder);
        request_count++;
}

static void finish(int queued, struct completion *cb, int status, const nfs_opnum4 *ops, size_t count)
{
        uint64_t deadline = rpc_current_time() + 3000;
        assert(queued == 0);
        expected_count = count;
        memcpy(expected, ops, count * sizeof(*ops));
        while (!cb->calls) {
                struct pollfd fds[2] = {{nfs_get_fd(context), nfs_which_events(context), 0},
                                       {peer, POLLIN, 0}};
                assert(rpc_current_time() < deadline);
                assert(poll(fds, 2, 10) >= 0);
                assert(nfs_service(context, fds[0].revents) == 0);
                if (fds[1].revents & POLLIN) serve();
        }
        assert(cb->status == status);
        assert(!rpc_queue_length(context->rpc) && !context->rpc->nfs4_slots_in_use);
}

#define RUN(expr, status, ...) do { \
        const nfs_opnum4 ops[] = {OP_SEQUENCE, OP_PUTFH, __VA_ARGS__}; \
        finish((expr), &cb, status, ops, sizeof(ops) / sizeof(*ops)); \
} while (0)

int main(void)
{
        int pair[2];
        sessionid4 session = {1};
        struct timeval timeout = {.tv_sec = 3};
        struct nfs4_object *root, *file, *copy;
        struct nfsfh *open_fh;
        struct completion cb = { .kind = 1 };
        struct nfs_stat_64 st = {.nfs_size = 123, .nfs_mode = 0640,
                .nfs_uid = 1001, .nfs_gid = 21111, .nfs_atime = 1700000000,
                .nfs_mtime = 1700000000, .nfs_atime_nsec = 123456789, .nfs_mtime_nsec = 123456789};
        size_t key_length;
        context = nfs_init_context();
        assert(context && !nfs4_object_root(context));
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
        assert(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        peer = pair[1];
        rpc_set_fd(context->rpc, pair[0]);
        context->rpc->is_connected = 1;
        context->rpc->program = NFS4_PROGRAM;
        context->rpc->version = NFS_V4;
        context->rpc->nfs4_minorversion = 2;
        context->nfsi->version = NFS_V4_2;
        context->nfsi->rootfh.val = strdup("root");
        context->nfsi->rootfh.len = 4;
        assert(nfs4_session_init(context->rpc, session, 2) == 0);
        root = nfs4_object_root(context);
        assert(root);
        RUN(nfs4_object_lookup_async(context, root, "child", complete, &cb), 0, OP_LOOKUP, OP_GETFH, OP_GETATTR);
        file = cb.value;
        assert(cb.attributes.nfs_size == 123);
        assert(!memcmp(nfs4_object_key(file, &key_length), "file", 4) && key_length == 4);
        base_key = "file";
        cb = (struct completion){.kind = 3}; claim = CLAIM_FH;
        RUN(nfs4_object_open_async(context, file, O_RDWR, complete, &cb), 0, OP_OPEN, OP_GETFH);
        open_fh = cb.value;
        copy = nfs4_object_from_open(context, open_fh);
        assert(copy && !memcmp(nfs4_object_key(copy, &key_length), "file", 4));
        cb = (struct completion){.kind = 2};
        int queued = nfs4_object_getattr_async(context, copy, complete, &cb);
        nfs4_object_free(copy); /* Queued requests own their input filehandles. */
        RUN(queued, 0, OP_GETATTR);
        assert(cb.attributes.nfs_size == 123);
        cb = (struct completion){.kind = 2};
        RUN(nfs_fstat64_async(context, open_fh, complete, &cb), 0, OP_GETATTR);
        cb = (struct completion){.kind = 5};
        RUN(nfs4_fstat64_async(context, open_fh, complete, &cb), 0, OP_GETATTR);
        for (setattr_mask = 0; setattr_mask <= 255; setattr_mask++) {
                cb = (struct completion){.kind = 2};
                expected_state = open_fh->stateid;
                RUN(nfs4_object_setattr_async(context, file, open_fh, &st, setattr_mask, complete, &cb), 0, OP_SETATTR, OP_GETATTR);
        }
        memset(&expected_state, 0, sizeof(expected_state));
        setattr_mask = NFS4_OBJECT_MODE;
        cb = (struct completion){.kind = 2};
        RUN(nfs4_object_setattr_async(context, file, NULL, &st, setattr_mask, complete, &cb), 0, OP_SETATTR, OP_GETATTR);
        /* Truncate before the size, then after both owner strings were decoded. */
        for (malformed = 1; malformed <= 2; malformed++) {
                base_key = "root";
                cb = (struct completion){.kind = 1};
                RUN(nfs4_object_lookup_async(context, root, "child", complete, &cb), -EINVAL, OP_LOOKUP, OP_GETFH, OP_GETATTR);
                base_key = "file";
                cb = (struct completion){.kind = 2};
                RUN(nfs4_object_getattr_async(context, file, complete, &cb), -EINVAL, OP_GETATTR);
                cb = (struct completion){.kind = 5};
                RUN(nfs4_fstat64_async(context, open_fh, complete, &cb), -EINVAL, OP_GETATTR);
        }
        malformed = 0;
        cb = (struct completion){0};
        RUN(nfs_close_async(context, open_fh, complete, &cb), 0, OP_CLOSE);
        cb = (struct completion){.kind = 4};
        RUN(nfs4_object_readlink_async(context, file, complete, &cb), 0, OP_READLINK);
        cb = (struct completion){0};
        RUN(nfs4_object_access_async(context, file, R_OK | W_OK, complete, &cb), 0, OP_ACCESS);
        for (int directory = 0; directory < 2; directory++) {
                denied_access = directory ? ACCESS4_EXECUTE : ACCESS4_LOOKUP;
                cb = (struct completion){0};
                RUN(nfs4_object_access_async(context, file, X_OK, complete, &cb), 0, OP_ACCESS);
        }
        denied_access = ACCESS4_LOOKUP | ACCESS4_EXECUTE;
        cb = (struct completion){0};
        RUN(nfs4_object_access_async(context, file, X_OK, complete, &cb), -EACCES, OP_ACCESS);
        denied_access = ACCESS4_EXTEND;
        cb = (struct completion){0};
        RUN(nfs4_object_access_async(context, file, W_OK, complete, &cb), -EACCES, OP_ACCESS);
        denied_access = 0;
        cb = (struct completion){0};
        RUN(nfs4_object_link_async(context, file, root, "hardlink", complete, &cb), 0, OP_SAVEFH, OP_PUTFH, OP_LINK);
        base_key = "root";
        cb = (struct completion){0};
        RUN(nfs4_object_rename_async(context, root, "old", root, "new", complete, &cb), 0, OP_SAVEFH, OP_PUTFH, OP_RENAME);
        cb = (struct completion){0};
        RUN(nfs4_object_remove_async(context, root, "old", complete, &cb), 0, OP_REMOVE);
        cb = (struct completion){.kind = 3};
        RUN(nfs4_object_opendir_async(context, root, complete, &cb), 0, OP_GETFH, OP_READDIR);
        nfs_closedir(context, cb.value);
        for (unsigned i = 0; i < 4; i++) {
                int modes[] = {S_IFDIR, S_IFLNK, S_IFIFO, S_IFSOCK};
                cb = (struct completion){.kind = 1};
                RUN(nfs4_object_create_async(context, root, "created", modes[i] | 0755, 0, "target", complete, &cb), 0, OP_CREATE, OP_GETFH, OP_GETATTR);
                nfs4_object_free(cb.value);
        }
        cb = (struct completion){.kind = 3}; claim = CLAIM_NULL;
        RUN(nfs4_object_openat_async(context, root, "created", O_CREAT | O_RDWR, 0600, complete, &cb), 0, OP_OPEN, OP_GETFH);
        open_fh = cb.value;
        base_key = "file";
        cb = (struct completion){0};
        RUN(nfs_close_async(context, open_fh, complete, &cb), 0, OP_CLOSE);
        base_key = "root"; fail_op = OP_LOOKUP;
        cb = (struct completion){.kind = 1};
        RUN(nfs4_object_lookup_async(context, root, "child", complete, &cb), -EACCES, OP_LOOKUP, OP_GETFH, OP_GETATTR);
        fail_status = NFS4ERR_STALE;
        fail_op = OP_PUTFH;
        cb = (struct completion){.kind = 2};
        RUN(nfs4_object_getattr_async(context, file, complete, &cb), nfsstat4_to_errno(NFS4ERR_STALE), OP_GETATTR);
        cb = (struct completion){.kind = 3};
        RUN(nfs4_object_open_async(context, file, O_RDONLY, complete, &cb), nfsstat4_to_errno(NFS4ERR_STALE), OP_OPEN, OP_GETFH);
        fail_op = 0;
        const char *invalid[] = {NULL, "", ".", "..", "a/b"};
        for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
                cb = (struct completion){0};
                assert(nfs4_object_lookup_async(context, root, invalid[i], complete, &cb) == -EINVAL);
                assert(!cb.calls && !rpc_queue_length(context->rpc));
        }
        assert(nfs4_object_setattr_async(context, root, NULL, &st, 256, complete, &cb) == -EINVAL);
        st.nfs_mtime_nsec = 1000000000;
        assert(nfs4_object_setattr_async(context, root, NULL, &st, NFS4_OBJECT_MTIME, complete, &cb) == -EINVAL);
        assert(nfs4_object_open_async(context, file, O_CREAT, complete, &cb) == -EINVAL);
        assert(!cb.calls && !rpc_queue_length(context->rpc));
#ifdef TEST_ALLOC_FAILURE
        unsigned failures = 0;
        for (int kind = 0; kind < 3; kind++) {
                for (int budget = 0; budget < 32; budget++) {
                        int queued;
                        base_key = kind ? "file" : "root";
                        claim = CLAIM_FH;
                        setattr_mask = 255;
                        st.nfs_mtime_nsec = 123456789;
                        cb = (struct completion){.kind = kind == 0 ? 1 : kind == 1 ? 2 : 3};
                        allocation_budget = budget;
                        if (!kind)
                                queued = nfs4_object_lookup_async(context, root, "child", complete, &cb);
                        else if (kind == 1)
                                queued = nfs4_object_setattr_async(context, file, NULL, &st, 255, complete, &cb);
                        else
                                queued = nfs4_object_open_async(context, file, O_RDWR, complete, &cb);
                        allocation_budget = -1;
                        if (queued < 0) {
                                assert(queued == -ENOMEM && !cb.calls);
                                assert(!rpc_queue_length(context->rpc) && !context->rpc->nfs4_slots_in_use);
                                failures++;
                        } else if (!kind) {
                                RUN(queued, 0, OP_LOOKUP, OP_GETFH, OP_GETATTR);
                                nfs4_object_free(cb.value);
                        } else if (kind == 1) {
                                RUN(queued, 0, OP_SETATTR, OP_GETATTR);
                        } else {
                                RUN(queued, 0, OP_OPEN, OP_GETFH);
                                open_fh = cb.value;
                                cb = (struct completion){0};
                                RUN(nfs_close_async(context, open_fh, complete, &cb), 0, OP_CLOSE);
                        }
                }
        }
        assert(failures >= 15);
        printf("PASS: %u allocation failures, no callback or queued request on submission error\n", failures);
#endif
        cb = (struct completion){.kind = 1};
        assert(!nfs4_object_lookup_async(context, root, "child", complete, &cb));
        nfs4_object_free(root);
        nfs4_object_free(file);
        nfs_destroy_context(context);
        assert(cb.calls == 1 && cb.status == -EINTR);
        close(peer);
        printf("PASS: object API, %u RPCs, 256 SETATTR masks, ownership, malformed attributes, errors\n", request_count);
        return 0;
}
#endif
