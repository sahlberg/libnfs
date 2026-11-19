/* A zero-copy READ cut off mid reply and resent on reconnect completes once. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef WIN32
int main(void) { return 77; }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
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

#define BUFLEN 8192

static unsigned char buf[BUFLEN];
static int calls, last_status;

static void read_cb(struct rpc_context *rpc, int status, void *data,
                    void *private_data)
{
        (void)rpc; (void)data;
        calls++;
        last_status = status;
        free(private_data);
}

static void connect_cb(struct rpc_context *rpc, int status, void *data,
                       void *private_data)
{
        (void)rpc; (void)data; (void)private_data;
        CHECK(status == RPC_STATUS_SUCCESS);
}

static void service(struct rpc_context *rpc, int ms)
{
        struct pollfd p = { rpc_get_fd(rpc), (short)rpc_which_events(rpc), 0 };

        if (poll(&p, 1, ms) > 0) {
                CHECK(rpc_service(rpc, p.revents) == 0);
        } else {
                CHECK(rpc_service(rpc, 0) == 0);
        }
}

/* Drive the client until the listener has a connection, then read the call. */
static int next_call(struct rpc_context *rpc, int listener, uint32_t *xid)
{
        struct pollfd l = { listener, POLLIN, 0 };
        unsigned char call[4096];
        uint32_t marker, len;
        size_t got;
        int i, peer;

        for (i = 0; i < 200 && poll(&l, 1, 0) == 0; i++) {
                service(rpc, 10);
        }
        if (i == 200) {
                return -1;
        }
        peer = accept(listener, NULL, NULL);
        CHECK(peer >= 0);
        for (i = 0; i < 200 &&
                    recv(peer, &marker, 4, MSG_PEEK | MSG_DONTWAIT) < 4; i++) {
                service(rpc, 10);
        }
        CHECK(recv(peer, &marker, 4, MSG_DONTWAIT) == 4);
        len = ntohl(marker) & 0x7fffffff;
        CHECK(len <= sizeof(call));
        for (got = 0; got < len; ) {
                ssize_t n = recv(peer, call + got, len - got, MSG_DONTWAIT);
                if (n > 0) {
                        got += (size_t)n;
                } else {
                        service(rpc, 10);
                }
        }
        memcpy(xid, call, 4);
        return peer;
}

static void reply(int peer, uint32_t xid, const uint32_t *w, int nw,
                  uint32_t claimed, size_t fill)
{
        unsigned char msg[BUFLEN + 256], *p = msg;
        uint32_t v;
        int i;

        v = htonl(0x80000000 | (uint32_t)(4 + nw * 4 + claimed));
        memcpy(p, &v, 4); p += 4;
        memcpy(p, &xid, 4); p += 4;
        for (i = 0; i < nw; i++) {
                v = htonl(w[i]);
                memcpy(p, &v, 4); p += 4;
        }
        memset(p, 0x41, fill);
        p += fill;
        CHECK(write(peer, msg, (size_t)(p - msg)) == p - msg);
}

int main(void)
{
        /* REPLY, MSG_ACCEPTED, AUTH_NONE, SUCCESS, NFS3_OK, no attr */
        uint32_t ok[] = { 1, 0, 0, 0, 0, 0, 0, BUFLEN, 1, BUFLEN };
        uint32_t unavail[] = { 1, 0, 0, 0, 1 };
        static char fh[] = "testfh00";
        struct iovec iov = { buf, BUFLEN };
        struct sockaddr_in sin;
        socklen_t sl = sizeof(sin);
        struct rpc_context *rpc;
        READ3args args;
        uint32_t xid;
        int listener, peer, i;

        listener = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(listener >= 0);
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(listener, (struct sockaddr *)&sin, sizeof(sin)) == 0);
        CHECK(listen(listener, 4) == 0);
        CHECK(getsockname(listener, (struct sockaddr *)&sin, &sl) == 0);

        rpc = rpc_init_context();
        CHECK(rpc != NULL);
        rpc->program = NFS_PROGRAM;
        rpc->version = NFS_V3;
        CHECK(rpc_connect_async(rpc, "127.0.0.1", ntohs(sin.sin_port),
                                connect_cb, NULL) == 0);
        rpc_set_resiliency(rpc, 5, 0, 0);

        memset(&args, 0, sizeof(args));
        args.file.data.data_len = sizeof(fh) - 1;
        args.file.data.data_val = fh;
        args.count = BUFLEN;
        CHECK(rpc_nfs3_readv_task(rpc, read_cb, &iov, 1, &args,
                                  malloc(16)) != NULL);

        /* Part of the payload, then the connection goes away. */
        peer = next_call(rpc, listener, &xid);
        CHECK(peer >= 0);
        reply(peer, xid, ok, 10, BUFLEN, 3000);
        for (i = 0; i < 20; i++) {
                service(rpc, 10);
        }
        close(peer);

        /* The resent READ is refused. */
        peer = next_call(rpc, listener, &xid);
        CHECK(peer >= 0);
        reply(peer, xid, unavail, 5, 0, 0);
        for (i = 0; i < 20; i++) {
                service(rpc, 10);
        }
        CHECK(calls == 1);
        CHECK(last_status == RPC_STATUS_ERROR);

        /* Nothing is left to send, or to complete a second time. */
        peer = next_call(rpc, listener, &xid);
        if (peer >= 0) {
                reply(peer, xid, ok, 10, BUFLEN, BUFLEN);
                for (i = 0; i < 20; i++) {
                        service(rpc, 10);
                }
                close(peer);
        }
        CHECK(calls == 1);

        rpc_destroy_context(rpc);
        close(listener);
        return 0;
}
#endif
