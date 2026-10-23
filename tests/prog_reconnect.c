/* Deterministic transport failures, with real loopback RPC replay after recovery. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef WIN32
int main(void) { return 77; }
#else
#define _GNU_SOURCE
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
static int injected_errno, injected_so_error, connect_calls;
static int injected_pipe_errno, injected_dup_errno, fail_socket_dup;
static int parked_pipe[2] = {-1, -1};
static int pipe_writers[32], pipe_count;
static int fake_pipe(int fds[2])
{
        int ret;
        if (injected_pipe_errno) {
                errno = injected_pipe_errno;
                return -1;
        }
        ret = pipe(fds);
        if (ret == 0) {
                parked_pipe[0] = fds[0];
                parked_pipe[1] = fds[1];
                if (pipe_count == 32) abort();
                pipe_writers[pipe_count++] = fds[1];
        }
        return ret;
}
static int fake_dup2(int source, int target)
{
        if (injected_dup_errno && (source == parked_pipe[0] || fail_socket_dup)) {
                errno = injected_dup_errno;
                return -1;
        }
        return dup2(source, target);
}
static int fake_connect(int fd, const struct sockaddr *address, socklen_t length)
{
        connect_calls++;
        if (injected_errno) {
                errno = injected_errno;
                return -1;
        }
        return connect(fd, address, length);
}
static int fake_getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{
        if (injected_so_error && level == SOL_SOCKET && option == SO_ERROR) {
                *(int *)value = injected_so_error;
                injected_so_error = 0;
                return 0;
        }
        return getsockopt(fd, level, option, value, length);
}
/* Compile the real transport with OS connection and pipe setup substituted.
 * No production fault-injection API or network configuration changes needed. */
#define connect fake_connect
#define getsockopt fake_getsockopt
#define pipe fake_pipe
#define dup2 fake_dup2
#include "../lib/socket.c"
#undef connect
#undef getsockopt
#undef pipe
#undef dup2

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
struct result { int calls, status; };
static void complete(struct rpc_context *rpc, int status, void *data, void *opaque)
{
        struct result *r = opaque;
        (void)rpc; (void)data;
        CHECK(++r->calls == 1);
        r->status = status;
}
static struct rpc_context *fixture(int retries, struct result *r, int *peer)
{
        struct rpc_context *rpc = rpc_init_context();
        struct sockaddr_in *address;
        int pair[2];
        CHECK(rpc != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        rpc_set_fd(rpc, pair[0]);
        rpc->is_connected = 1;
        address = (struct sockaddr_in *)&rpc->s;
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address->sin_port = htons(2049);
        rpc_set_resiliency(rpc, retries, 60000, 2);
        CHECK(rpc_nfs4_null_task(rpc, complete, r) != NULL);
        *peer = pair[1];
        connect_calls = 0;
        injected_so_error = 0;
        parked_pipe[0] = parked_pipe[1] = -1;
        return rpc;
}
static void due(struct rpc_context *rpc)
{
        CHECK(rpc->reconnect_due != 0);
        rpc->reconnect_due = rpc_current_time();
}
static void transfer(int fd, void *buffer, size_t length, int writing)
{
        char *p = buffer;
        while (length) {
                struct pollfd ready = { .fd = fd, .events = writing ? POLLOUT : POLLIN };
                ssize_t count;
                CHECK(poll(&ready, 1, 2000) == 1);
                count = writing ? write(fd, p, length) : read(fd, p, length);
                CHECK(count > 0);
                p += count; length -= count;
        }
}
static void serve_null(struct rpc_context *rpc, int peer, struct result *r)
{
        uint32_t marker, reply[7], xid;
        char buffer[4096];
        CHECK(rpc_service(rpc, POLLOUT) == 0);
        transfer(peer, &marker, sizeof(marker), 0);
        CHECK((ntohl(marker) & 0x7fffffff) <= sizeof(buffer));
        transfer(peer, buffer, ntohl(marker) & 0x7fffffff, 0);
        memcpy(&xid, buffer, sizeof(xid));
        reply[0] = htonl(0x80000018);
        reply[1] = xid;
        reply[2] = htonl(REPLY);
        reply[3] = htonl(MSG_ACCEPTED);
        reply[4] = htonl(AUTH_NONE);
        reply[5] = 0;
        reply[6] = htonl(SUCCESS);
        transfer(peer, reply, sizeof(reply), 1);
        CHECK(rpc_service(rpc, POLLIN) == 0);
        CHECK(r->calls == 1 && r->status == RPC_STATUS_SUCCESS);
}
static void recovery(void)
{
        struct result r = {0}, second = {0};
        int old_peer, listener, peer, i, registered_fd, writer, flags;
        struct sockaddr_in address = {0};
        socklen_t length = sizeof(address);
        struct rpc_context *rpc = fixture(-1, &r, &old_peer);
        listener = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(listener >= 0);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
        CHECK(listen(listener, 1) == 0);
        CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0);
        memcpy(&rpc->s, &address, sizeof(address));
        registered_fd = rpc_get_fd(rpc);
        flags = fcntl(registered_fd, F_GETFD);
        injected_errno = ENETUNREACH;
        CHECK(rpc_service(rpc, POLLHUP) == 0);
        CHECK(connect_calls == 1 && r.calls == 0 && rpc_queue_length(rpc) == 1);
        CHECK(rpc_get_fd(rpc) == registered_fd && rpc_which_events(rpc) == 0);
        CHECK(fcntl(registered_fd, F_GETFD) == flags);
        writer = rpc->reconnect_write_fd;
        CHECK(writer >= 0 && (fcntl(writer, F_GETFD) & FD_CLOEXEC));
        /* The application keeps its original descriptor and event mask. */
        for (i = 0; i < 10; i++) {
                struct pollfd ready = { .fd = registered_fd, .events = POLLIN | POLLOUT };
                CHECK(poll(&ready, 1, 1) == 0);
        }
        rpc_set_poll_timeout(rpc, -1);
        CHECK(rpc_get_poll_timeout(rpc) > 0 && rpc_get_poll_timeout(rpc) <= 1000);
        for (i = 0; i < 10; i++) CHECK(rpc_service(rpc, POLLERR | POLLHUP) == 0);
        CHECK(connect_calls == 1); /* stale readiness cannot cause a retry storm */
        due(rpc);
        injected_errno = EHOSTUNREACH;
        CHECK(rpc_service(rpc, 0) == 0 && connect_calls == 2);
        CHECK(r.calls == 0 && rpc->num_retries == -1);
        CHECK(rpc_get_fd(rpc) == registered_fd);
        writer = rpc->reconnect_write_fd;
        injected_errno = 0;
        due(rpc);
        CHECK(rpc_service(rpc, 0) == 0);
        CHECK(rpc_get_fd(rpc) == registered_fd);
        CHECK(rpc->reconnect_write_fd == -1);
        CHECK(fcntl(writer, F_GETFD) == -1 && errno == EBADF);
        {
                struct pollfd ready = { .fd = listener, .events = POLLIN };
                CHECK(poll(&ready, 1, 2000) == 1);
        }
        peer = accept(listener, NULL, NULL);
        CHECK(peer >= 0);
        CHECK(rpc_service(rpc, POLLOUT) == 0 && rpc->is_connected);
        serve_null(rpc, peer, &r);
        CHECK(rpc_nfs4_null_task(rpc, complete, &second) != NULL);
        serve_null(rpc, peer, &second);
        CHECK(rpc_queue_length(rpc) == 0);
        rpc_destroy_context(rpc);
        close(peer); close(listener); close(old_peer);
        puts("PASS: unlimited retries preserve requests, wait without spinning, and replay after recovery");
}
static void limits(void)
{
        int policy;
        for (policy = 0; policy <= 2; policy++) {
                struct result r = {0};
                int peer, ret;
                struct rpc_context *rpc = fixture(policy, &r, &peer);
                injected_errno = ENETUNREACH;
                ret = rpc_service(rpc, POLLHUP);
                if (policy == 2) {
                        CHECK(ret == 0 && !r.calls);
                        due(rpc);
                        ret = rpc_service(rpc, 0);
                }
                CHECK(ret == -1 && connect_calls == policy);
                if (policy == 0) {
                        rpc_destroy_context(rpc);
                        CHECK(r.calls == 1 && r.status == RPC_STATUS_CANCEL);
                } else {
                        CHECK(r.calls == 1 && r.status == RPC_STATUS_ERROR);
                        CHECK(rpc_queue_length(rpc) == 0);
                        rpc_destroy_context(rpc);
                }
                close(peer);
        }
        puts("PASS: disabled and finite reconnect policies fail exactly once at the configured limit");
}
static void termination(int destroy, int error)
{
        struct result r = {0};
        int peer, registered_fd, writer;
        struct rpc_context *rpc = fixture(-1, &r, &peer);
        registered_fd = rpc_get_fd(rpc);
        injected_errno = error;
        if (error == EINVAL) {
                CHECK(rpc_service(rpc, POLLHUP) == -1);
                CHECK(r.calls == 1 && !rpc->reconnect_due);
                rpc_destroy_context(rpc);
        } else {
                CHECK(rpc_service(rpc, POLLHUP) == 0 && !r.calls);
                writer = rpc->reconnect_write_fd;
                CHECK(writer >= 0);
                if (destroy) {
                        rpc_destroy_context(rpc);
                        CHECK(r.calls == 1 && r.status == RPC_STATUS_CANCEL);
                } else {
                        CHECK(rpc_disconnect(rpc, "test disconnect") == 0);
                        CHECK(!rpc->reconnect_due && rpc_get_fd(rpc) == -1);
                        CHECK(r.calls == 1);
                        CHECK(rpc_service(rpc, 0) == 0 && connect_calls == 1);
                        rpc_destroy_context(rpc);
                }
                CHECK(fcntl(writer, F_GETFD) == -1 && errno == EBADF);
        }
        CHECK(fcntl(registered_fd, F_GETFD) == -1 && errno == EBADF);
        close(peer);
}
static void request_timeout(void)
{
        struct result r = {0};
        int peer;
        struct rpc_context *rpc = fixture(-1, &r, &peer);
        injected_errno = ENETUNREACH;
        CHECK(rpc_service(rpc, POLLHUP) == 0);
        CHECK(rpc->outqueue.head != NULL);
        rpc->retrans = 0;
        rpc->outqueue.head->timeout = rpc_current_time() - 1;
        rpc->last_timeout_scan = 0;
        CHECK(rpc_service(rpc, 0) == 0);
        CHECK(r.calls == 1 && r.status == RPC_STATUS_TIMEOUT);
        CHECK(connect_calls == 1);
        rpc_destroy_context(rpc); close(peer);
        puts("PASS: request timeout remains effective during reconnect backoff");
}
static void asynchronous_error(int events)
{
        struct result r = {0};
        int peer;
        struct rpc_context *rpc = fixture(-1, &r, &peer);
        injected_errno = EINPROGRESS;
        CHECK(rpc_service(rpc, POLLHUP) == 0 && !rpc->reconnect_due);
        injected_so_error = ECONNREFUSED;
        CHECK(rpc_service(rpc, events) == 0 && rpc->reconnect_due);
        CHECK(r.calls == 0);
        rpc_destroy_context(rpc);
        CHECK(r.calls == 1);
        close(peer);
}
static void pipe_failures(void)
{
        int failure;
        for (failure = 0; failure < 2; failure++) {
                struct result r = {0};
                int peer, fd;
                struct rpc_context *rpc = fixture(-1, &r, &peer);
                fd = rpc_get_fd(rpc);
                injected_errno = ENETUNREACH;
                injected_pipe_errno = failure == 0 ? EMFILE : 0;
                injected_dup_errno = failure == 1 ? EIO : 0;
                CHECK(rpc_service(rpc, POLLHUP) == -1);
                CHECK(r.calls == 1 && r.status == RPC_STATUS_ERROR);
                CHECK(!rpc->reconnect_due && rpc->reconnect_write_fd == -1);
                CHECK(strstr(rpc_get_error(rpc), failure ? "park reconnect" : "pipe()") != NULL);
                if (failure) {
                        CHECK(fcntl(parked_pipe[0], F_GETFD) == -1 && errno == EBADF);
                        CHECK(fcntl(parked_pipe[1], F_GETFD) == -1 && errno == EBADF);
                }
                injected_pipe_errno = injected_dup_errno = 0;
                rpc_destroy_context(rpc);
                CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
                close(peer);
        }
        puts("PASS: pipe/setup failures remain terminal and release descriptors");
}
static void replacement_failure(void)
{
        struct result r = {0};
        int peer, fd, writer, socket_fd;
        struct rpc_context *rpc = fixture(-1, &r, &peer);
        fd = rpc_get_fd(rpc);
        injected_errno = ENETUNREACH;
        CHECK(rpc_service(rpc, POLLHUP) == 0);
        writer = rpc->reconnect_write_fd;
        injected_dup_errno = EIO;
        fail_socket_dup = 1;
        due(rpc);
        CHECK(rpc_service(rpc, 0) == -1);
        CHECK(r.calls == 1 && !rpc->reconnect_due);
        CHECK(rpc->reconnect_write_fd == -1);
        CHECK(fcntl(writer, F_GETFD) == -1 && errno == EBADF);
        socket_fd = rpc->fd;
        CHECK(socket_fd != fd);
        injected_dup_errno = fail_socket_dup = 0;
        rpc_destroy_context(rpc);
        CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
        CHECK(fcntl(socket_fd, F_GETFD) == -1 && errno == EBADF);
        close(peer);
}
static void disable_during_backoff(void)
{
        struct result r = {0};
        int peer, writer;
        struct rpc_context *rpc = fixture(-1, &r, &peer);
        injected_errno = ENETUNREACH;
        CHECK(rpc_service(rpc, POLLHUP) == 0);
        writer = rpc->reconnect_write_fd;
        rpc_set_resiliency(rpc, 0, 60000, 2);
        due(rpc);
        CHECK(rpc_service(rpc, 0) == -1);
        CHECK(r.calls == 1 && rpc->reconnect_write_fd == -1);
        CHECK(fcntl(writer, F_GETFD) == -1 && errno == EBADF);
        rpc_destroy_context(rpc);
        close(peer);
}
int main(void)
{
        int i;
        alarm(20);
        recovery(); limits(); request_timeout();
        pipe_failures(); replacement_failure(); disable_during_backoff();
        termination(0, ENETUNREACH); termination(1, ENETUNREACH);
        termination(0, EINVAL);
        asynchronous_error(POLLOUT);
        asynchronous_error(POLLERR | POLLHUP);
        for (i = 0; i < pipe_count; i++)
                CHECK(fcntl(pipe_writers[i], F_GETFD) == -1 && errno == EBADF);
        puts("PASS: cancel/destroy, permanent error, and asynchronous connection failure");
        return 0;
}
#endif
