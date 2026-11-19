/* A failed zero-copy READ reply must not touch the buffer after the callback. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef WIN32
int main(void) { return 77; }
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define CHECK(x) do { if (!(x)) { \
        fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

#define BUFLEN 256

static int calls, last_status;
static unsigned char buf[BUFLEN];

static void read_cb(struct rpc_context *rpc, int status, void *data,
                    void *private_data)
{
        (void)rpc; (void)data; (void)private_data;
        calls++;
        last_status = status;
}

static unsigned char *put32(unsigned char *p, uint32_t v)
{
        v = htonl(v);
        memcpy(p, &v, 4);
        return p + 4;
}

/* Record marker, then the words, then fill bytes of payload. */
static size_t build(unsigned char *out, const uint32_t *w, int nw,
                    size_t fill, unsigned char c)
{
        unsigned char *p = put32(out, 0x80000000 | (uint32_t)(nw * 4 + fill));
        int i;

        for (i = 0; i < nw; i++) {
                p = put32(p, w[i]);
        }
        memset(p, c, fill);
        return (size_t)(p - out) + fill;
}

static void send_read(struct rpc_context *rpc, int peer, uint32_t xid)
{
        static char fh[] = "testfh00";
        struct iovec iov = { buf, BUFLEN };
        READ3args args;
        char junk[4096];

        memset(&args, 0, sizeof(args));
        args.file.data.data_len = sizeof(fh) - 1;
        args.file.data.data_val = fh;
        args.count = BUFLEN;
        rpc_set_next_xid(rpc, xid);
        CHECK(rpc_nfs3_readv_task(rpc, read_cb, &iov, 1, &args, NULL) != NULL);
        CHECK(rpc_service(rpc, POLLOUT) == 0);
        while (read(peer, junk, sizeof(junk)) > 0)
                ;
}

static void expect_error(struct rpc_context *rpc, int peer,
                         const unsigned char *msg, size_t len)
{
        size_t i;

        calls = 0;
        memset(buf, 0, sizeof(buf));
        CHECK(write(peer, msg, len) == (ssize_t)len);
        CHECK(rpc_service(rpc, POLLIN) == 0);
        CHECK(calls == 1);
        CHECK(last_status == RPC_STATUS_ERROR);
        for (i = 0; i < sizeof(buf); i++) {
                CHECK(buf[i] == 0);
        }
}

int main(void)
{
        /* xid, REPLY, MSG_ACCEPTED, AUTH_NONE, SUCCESS, NFS3_OK, no attr */
        uint32_t ok[] = { 0, 1, 0, 0, 0, 0, 0, 0, BUFLEN, 1, BUFLEN };
        uint32_t call[] = { 0, 0 };
        uint32_t denied[] = { 0, 1, 1, 1, 1, 1, BUFLEN };
        uint32_t unavail[] = { 0, 1, 0, 0, 0, 1, 0, 0, 1, BUFLEN };
        unsigned char msg[4096];
        struct rpc_context *rpc;
        size_t len, len2, i;
        int sv[2];

        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        CHECK(fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
        CHECK(fcntl(sv[1], F_SETFL, O_NONBLOCK) == 0);
        rpc = rpc_init_context();
        CHECK(rpc != NULL);
        rpc->program = NFS_PROGRAM;
        rpc->version = NFS_V3;
        rpc_set_fd(rpc, sv[0]);
        CHECK(rpc_service(rpc, POLLOUT) == 0);

        /* Not a reply at all. */
        send_read(rpc, sv[1], call[0] = 0x1000);
        len = build(msg, call, 2, 0, 0);
        expect_error(rpc, sv[1], msg, len);

        /* Denied, followed by what would be read data. */
        send_read(rpc, sv[1], denied[0] = 0x1001);
        len = build(msg, denied, 7, BUFLEN, 0x43);
        expect_error(rpc, sv[1], msg, len);

        /* PROG_UNAVAIL, followed by what would be read data. */
        send_read(rpc, sv[1], unavail[0] = 0x1002);
        len = build(msg, unavail, 10, BUFLEN, 0x41);
        expect_error(rpc, sv[1], msg, len);

        /* A denied reply longer than the zero-copy preamble, then a good one. */
        send_read(rpc, sv[1], denied[0] = 0x1003);
        len = build(msg, denied, 7, 2000, 0x43);
        expect_error(rpc, sv[1], msg, len);
        CHECK(calls == 1);
        send_read(rpc, sv[1], ok[0] = 0x1004);
        len2 = build(msg, ok, 11, BUFLEN, 0x55);
        calls = 0;
        CHECK(write(sv[1], msg, len2) == (ssize_t)len2);
        CHECK(rpc_service(rpc, POLLIN) == 0);
        CHECK(calls == 1);
        CHECK(last_status == RPC_STATUS_SUCCESS);
        for (i = 0; i < BUFLEN; i++) {
                CHECK(buf[i] == 0x55);
        }

        /* A reply short of the data it declares, then the next record. */
        send_read(rpc, sv[1], ok[0] = 0x1005);
        len = build(msg, ok, 11, 100, 0x41);
        ok[0] = 0x1006;
        len += build(msg + len, ok, 11, BUFLEN, 0x42);
        calls = 0;
        memset(buf, 0, sizeof(buf));
        CHECK(write(sv[1], msg, len) == (ssize_t)len);
        rpc_service(rpc, POLLIN);
        CHECK(calls == 1);
        CHECK(last_status == RPC_STATUS_ERROR);
        for (i = 100; i < BUFLEN; i++) {
                CHECK(buf[i] == 0);
        }

        rpc_destroy_context(rpc);
        close(sv[1]);
        return 0;
}
#endif
