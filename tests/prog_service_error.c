/* A terminal service error must replace an earlier pathname diagnostic. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef WIN32
int main(void) { return 77; }
#else
#include <errno.h>
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

/* Linux executable interposition exercises the real internal poll loops. */
#ifdef __linux__
static int poll_failure;
#ifdef HAVE_MULTITHREADING
static int background;
static struct nfs_context *background_nfs;
static libnfs_sem_t entered, proceed, completed;
#endif

int poll(struct pollfd *fds, nfds_t count, int timeout)
{
        (void)timeout;
        CHECK(count > 0);
#ifdef HAVE_MULTITHREADING
        if (background) {
                CHECK(nfs_mt_sem_post(&entered) == 0);
                CHECK(nfs_mt_sem_wait(&proceed) == 0);
        }
#endif
        if (poll_failure) {
                errno = EBADF;
                return -1;
        }
        fds[count - 1].revents = POLLHUP;
        return 1;
}

#ifdef HAVE_MULTITHREADING
unsigned int sleep(unsigned int seconds)
{
        (void)seconds;
        CHECK(background);
        background_nfs->rpc->multithreading_enabled = 0;
        CHECK(nfs_mt_sem_post(&completed) == 0);
        return 0;
}
#endif

static void test_internal_callers(int fail_poll)
{
        struct nfs_context *nfs = nfs_init_context();
        struct rpc_context *rpc;
        struct nfsfh fh = {0};
        struct nfs_stat_64 st;
        int pair[2];
        const char *expected = fail_poll ? "Poll failed:" : "POLLHUP";

        CHECK(nfs != NULL);
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        rpc = nfs_get_rpc_context(nfs);
        rpc_set_fd(rpc, pair[0]);
        rpc->is_connected = 1;
        rpc_set_resiliency(rpc, 0, 60000, 2);
        rpc_set_error(rpc, "stale RPC diagnostic");
        nfs_set_error(nfs, "stale pathname diagnostic");
        poll_failure = fail_poll;
        CHECK(nfs_fstat64(nfs, &fh, &st) < 0);
        CHECK(strstr(nfs_get_error(nfs), expected) != NULL);
        CHECK(strstr(nfs_get_error(nfs), "stale") == NULL);
        if (fail_poll)
                CHECK(strstr(nfs_get_error(nfs), strerror(EBADF)) != NULL);
        CHECK(rpc_queue_length(rpc) == 0);
        nfs_destroy_context(nfs);
        close(pair[1]);

#ifdef HAVE_MULTITHREADING
        nfs = nfs_init_context();
        CHECK(nfs != NULL);
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        rpc = nfs_get_rpc_context(nfs);
        rpc_set_fd(rpc, pair[0]);
        rpc->is_connected = 1;
        rpc_set_resiliency(rpc, 0, 60000, 2);
        rpc_set_error(rpc, "stale RPC diagnostic");
        nfs_set_error(nfs, "stale pathname diagnostic");
        CHECK(nfs_mt_sem_init(&entered, 0) == 0);
        CHECK(nfs_mt_sem_init(&proceed, 0) == 0);
        CHECK(nfs_mt_sem_init(&completed, 0) == 0);
        background = 1;
        background_nfs = nfs;
        CHECK(nfs_mt_service_thread_start(nfs) == 0);
        CHECK(nfs_mt_sem_wait(&entered) == 0);
        CHECK(nfs_mt_sem_post(&proceed) == 0);
        CHECK(nfs_mt_sem_wait(&completed) == 0);
        nfs_mt_service_thread_stop(nfs);
        CHECK(strstr(nfs_get_error(nfs), expected) != NULL);
        CHECK(strstr(nfs_get_error(nfs), "stale") == NULL);
        if (fail_poll)
                CHECK(strstr(nfs_get_error(nfs), strerror(EBADF)) != NULL);
        background = 0;
        CHECK(nfs_mt_sem_destroy(&entered) == 0);
        CHECK(nfs_mt_sem_destroy(&proceed) == 0);
        CHECK(nfs_mt_sem_destroy(&completed) == 0);
        nfs_destroy_context(nfs);
        close(pair[1]);
#endif
}
#endif

int main(void)
{
        struct nfs_context *nfs = nfs_init_context();
        struct rpc_context *rpc;
        int pair[2];
        uint64_t generation;

        alarm(10);
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
        rpc = nfs_get_rpc_context(nfs);
        generation = rpc->error_generation;
        rpc_set_error(rpc, "stale RPC diagnostic");
        CHECK(rpc->error_generation != generation);
        generation = rpc->error_generation;
        rpc_set_error_locked(rpc, "another stale RPC diagnostic");
        CHECK(rpc->error_generation != generation);
        CHECK(nfs_service(nfs, -1) == -1);
        CHECK(strcmp(nfs_get_error(nfs),
                     "RPC service failed without a diagnostic") == 0);
        nfs_destroy_context(nfs);
#ifdef __linux__
        test_internal_callers(0);
        test_internal_callers(1);
#endif
        puts("PASS: direct, synchronous and background service diagnostics");
        return 0;
}
#endif
