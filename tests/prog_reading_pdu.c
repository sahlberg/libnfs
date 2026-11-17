/* A reply that is still being read must be completed once and freed. */
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

#define BUFLEN 4096

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

/* Start a READ and hand it half of its reply, so it stays in rpc->pdu. */
static struct rpc_context *half_read(int *peer)
{
        /* REPLY, MSG_ACCEPTED, AUTH_NONE, SUCCESS, NFS3_OK, no attr */
        static const uint32_t ok[] = { 1, 0, 0, 0, 0, 0, 0, BUFLEN, 0, BUFLEN };
        static char fh[] = "testfh00";
        struct iovec iov = { buf, BUFLEN };
        unsigned char msg[2048], *p;
        struct rpc_context *rpc;
        READ3args args;
        char junk[4096];
        unsigned int i;
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

        memset(&args, 0, sizeof(args));
        args.file.data.data_len = sizeof(fh) - 1;
        args.file.data.data_val = fh;
        args.count = BUFLEN;
        rpc_set_next_xid(rpc, 0x2000);
        CHECK(rpc_nfs3_readv_task(rpc, read_cb, &iov, 1, &args, NULL) != NULL);
        CHECK(rpc_service(rpc, POLLOUT) == 0);
        while (read(sv[1], junk, sizeof(junk)) > 0)
                ;

        p = put32(msg, 0x80000000 | (4 + sizeof(ok) + BUFLEN));
        p = put32(p, 0x2000);
        for (i = 0; i < sizeof(ok) / 4; i++) {
                p = put32(p, ok[i]);
        }
        memset(p, 0x55, sizeof(msg) - (p - msg));
        CHECK(write(sv[1], msg, sizeof(msg)) == sizeof(msg));
        calls = 0;
        CHECK(rpc_service(rpc, POLLIN) == 0);
        CHECK(calls == 0);
        CHECK(rpc->pdu != NULL);

        *peer = sv[1];
        return rpc;
}

int main(void)
{
        struct rpc_context *rpc;
        int peer;

        /* The server goes away and reconnect is disabled. */
        rpc = half_read(&peer);
        close(peer);
        CHECK(rpc_service(rpc, POLLIN) < 0);
        CHECK(calls == 1);
        CHECK(last_status == RPC_STATUS_ERROR);
        CHECK(rpc->pdu == NULL);
        rpc_destroy_context(rpc);
        CHECK(calls == 1);

        /* The context is destroyed while the reply is still arriving. */
        rpc = half_read(&peer);
        rpc_destroy_context(rpc);
        CHECK(calls == 1);
        CHECK(last_status == RPC_STATUS_CANCEL);
        close(peer);
        return 0;
}
#endif
