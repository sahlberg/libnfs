/* A server context must drop a REPLY, not decode it as a CALL. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef WIN32
int main(void) { return 77; }
#else
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"

#define CHECK(x) do { if (!(x)) { \
        fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

static int calls;

static int null_cb(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        (void)opaque;
        calls++;
        return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
}

int main(void)
{
        static const unsigned char reply[] = {
                0x80, 0x00, 0x00, 0x18,         /* last fragment, 24 bytes */
                0x11, 0x22, 0x33, 0x44,         /* xid */
                0x00, 0x00, 0x00, 0x01,         /* REPLY */
                0x00, 0x00, 0x00, 0x00,         /* MSG_ACCEPTED */
                0x00, 0x00, 0x00, 0x00,         /* AUTH_NONE */
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,         /* SUCCESS */
        };
        static const unsigned char call[] = {
                0x80, 0x00, 0x00, 0x28,         /* last fragment, 40 bytes */
                0x11, 0x22, 0x33, 0x45,         /* xid */
                0x00, 0x00, 0x00, 0x00,         /* CALL */
                0x00, 0x00, 0x00, 0x02,         /* rpcvers */
                0x00, 0x01, 0x86, 0xa3,         /* NFS */
                0x00, 0x00, 0x00, 0x03,         /* v3 */
                0x00, 0x00, 0x00, 0x00,         /* NULL */
                0x00, 0x00, 0x00, 0x00,         /* AUTH_NONE cred */
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,         /* AUTH_NONE verf */
                0x00, 0x00, 0x00, 0x00,
        };
        struct service_proc procs[] = {
                { 0, null_cb, (zdrproc_t)zdr_void, 0, NULL },
        };
        struct rpc_context *rpc;
        char buf[128];
        int sv[2];

        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        rpc = rpc_init_server_context(sv[0]);
        CHECK(rpc != NULL);
        CHECK(rpc_register_service(rpc, 100003, 3, procs, 1) == 0);

        CHECK(write(sv[1], reply, sizeof(reply)) == sizeof(reply));
        CHECK(rpc_service(rpc, POLLIN) == 0);
        CHECK(calls == 0);
        CHECK(recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT) < 0);

        /* The connection still serves calls after the dropped reply. */
        CHECK(write(sv[1], call, sizeof(call)) == sizeof(call));
        CHECK(rpc_service(rpc, POLLIN) == 0);
        CHECK(calls == 1);
        CHECK(recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT) > 0);

        rpc_destroy_context(rpc);
        close(sv[1]);
        return 0;
}
#endif
