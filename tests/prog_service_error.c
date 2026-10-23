/* A terminal service error must replace an earlier pathname diagnostic. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef WIN32
int main(void) { return 77; }
#else
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

int main(void)
{
        struct nfs_context *nfs = nfs_init_context();
        struct rpc_context *rpc;
        int pair[2];

        CHECK(nfs != NULL);
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        rpc = nfs_get_rpc_context(nfs);
        rpc_set_fd(rpc, pair[0]);
        rpc->is_connected = 1;
        rpc_set_resiliency(rpc, 0, 60000, 2);
        nfs_set_error(nfs, "stale NFS4ERR_NOENT pathname error");

        CHECK(nfs_service(nfs, 0) == 0);
        CHECK(strstr(nfs_get_error(nfs), "NOENT") != NULL);
        CHECK(nfs_service(nfs, POLLHUP) == -1);
        CHECK(strstr(nfs_get_error(nfs), "POLLHUP") != NULL);
        CHECK(strstr(nfs_get_error(nfs), "NOENT") == NULL);
        CHECK(strcmp(nfs_get_error(nfs), rpc_get_error(rpc)) == 0);

        nfs_destroy_context(nfs);
        close(pair[1]);

        /* A poll failure may reach rpc_service() without an RPC diagnostic. */
        nfs = nfs_init_context();
        CHECK(nfs != NULL);
        nfs_set_error(nfs, "stale pathname diagnostic");
        CHECK(nfs_service(nfs, -1) == -1);
        CHECK(strcmp(nfs_get_error(nfs),
                     "RPC service failed without a diagnostic") == 0);
        nfs_destroy_context(nfs);
        puts("PASS: service errors expose the terminal RPC diagnostic");
        return 0;
}
#endif
