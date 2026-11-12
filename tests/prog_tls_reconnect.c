/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A reconnecting xprtsec=tls session must not go on without TLS.
 * Local RPC peer; neither an NFS server nor kTLS is needed. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#if defined(WIN32) || !defined(HAVE_TLS)
int main(void) { return 77; }
#else
#define _GNU_SOURCE
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
static int connect_calls, injected_errno;
static int fake_connect(int fd, const struct sockaddr *address, socklen_t length)
{
        connect_calls++;
        if (injected_errno) {
                errno = injected_errno;
                return -1;
        }
        return connect(fd, address, length);
}
/* Compile the real transport so that the static reconnect callbacks are the
 * code under test, and count how often it connects. */
#define connect fake_connect
#include "../lib/socket.c"
#undef connect

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
enum answer { NO_STARTTLS, DENIED, SILENCE };
struct result { int calls, status; };
static void complete(struct rpc_context *rpc, int status, void *data, void *opaque)
{
        struct result *r = opaque;
        (void)rpc; (void)data;
        CHECK(++r->calls == 1);
        r->status = status;
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
static int accepted(int listener)
{
        struct pollfd ready = { .fd = listener, .events = POLLIN };
        int peer;
        CHECK(poll(&ready, 1, 2000) == 1);
        peer = accept(listener, NULL, NULL);
        CHECK(peer >= 0);
        return peer;
}
/* The first thing sent on a new connection has to be the AUTH_TLS probe. */
static uint32_t probe(int peer)
{
        uint32_t marker, call[64], length;
        transfer(peer, &marker, sizeof(marker), 0);
        length = ntohl(marker) & 0x7fffffff;
        CHECK(length >= 7 * sizeof(uint32_t) && length <= sizeof(call));
        transfer(peer, call, length, 0);
        /* xid, direction, RPC version, program, version, procedure, flavor */
        CHECK(ntohl(call[1]) == CALL && ntohl(call[3]) == NFS_PROGRAM);
        CHECK(ntohl(call[5]) == 0 && ntohl(call[6]) == AUTH_TLS);
        return call[0];
}
/* Answer the probe without offering STARTTLS, either as a server that does
 * not know RPC-with-TLS would or by rejecting the call. */
static void refuse(int peer, uint32_t xid, enum answer answer)
{
        uint32_t reply[7], length;
        reply[1] = xid;
        reply[2] = htonl(REPLY);
        if (answer == DENIED) {
                length = 5 * sizeof(uint32_t);
                reply[3] = htonl(MSG_DENIED);
                reply[4] = htonl(AUTH_ERROR);
                reply[5] = htonl(AUTH_REJECTEDCRED);
        } else {
                length = 6 * sizeof(uint32_t);
                reply[3] = htonl(MSG_ACCEPTED);
                reply[4] = htonl(AUTH_NONE);
                reply[5] = 0; /* an empty verifier, not "STARTTLS" */
                reply[6] = htonl(SUCCESS);
        }
        reply[0] = htonl(0x80000000 | length);
        transfer(peer, reply, sizeof(reply[0]) + length, 1);
}
/* An established xprtsec=tls session with one request in flight loses its
 * connection and libnfs connects again. */
static struct rpc_context *reconnected(int retries, struct result *r,
                                       int *listener, int *old_peer, int *peer)
{
        struct sockaddr_in address = {0};
        socklen_t length = sizeof(address);
        int pair[2];
        struct rpc_context *rpc = rpc_init_context();

        CHECK(rpc != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        *listener = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(*listener >= 0);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(*listener, (struct sockaddr *)&address, sizeof(address)) == 0);
        CHECK(listen(*listener, 2) == 0);
        CHECK(getsockname(*listener, (struct sockaddr *)&address, &length) == 0);

        rpc_set_fd(rpc, pair[0]);
        rpc->is_connected = 1;
        memcpy(&rpc->s, &address, sizeof(address));
        rpc->use_tls = 1;
        rpc->nfs_version = NFS_V4;
        rpc->tls_context.state = TLS_HANDSHAKE_COMPLETED;
        rpc_set_resiliency(rpc, retries, 60000, 2);
        CHECK(rpc_nfs4_null_task(rpc, complete, r) != NULL);
        connect_calls = 0;

        CHECK(rpc_service(rpc, POLLHUP) == 0 && connect_calls == 1);
        *peer = accepted(*listener);
        CHECK(rpc_service(rpc, POLLOUT) == 0 && rpc->is_connected);
        *old_peer = pair[1];
        return rpc;
}
/* Nothing but the probe was sent on the connection that got no TLS. */
static void silent(int peer)
{
        struct pollfd ready = { .fd = peer, .events = POLLIN };
        char byte;
        CHECK(poll(&ready, 1, 2000) == 1);
        CHECK(read(peer, &byte, 1) <= 0);
}
static void retried(enum answer answer)
{
        struct result r = {0};
        int listener, old_peer, peer, next;
        unsigned int i;
        struct rpc_context *rpc = reconnected(-1, &r, &listener, &old_peer, &peer);
        uint32_t xid = probe(peer);

        if (answer == SILENCE) {
                for (i = 0; i < rpc->num_hashes; i++)
                        if (rpc->waitpdu[i].head)
                                rpc->waitpdu[i].head->timeout = rpc_current_time() - 1;
                rpc->last_timeout_scan = 0;
                CHECK(rpc_service(rpc, POLLOUT) == 0);
        } else {
                refuse(peer, xid, answer);
                CHECK(rpc_service(rpc, POLLIN) == 0);
        }

        /* The connection is given up, a new one started and the request
         * kept back. */
        CHECK(!rpc->is_connected && connect_calls == 2 && !rpc->tls_reconnect_failed);
        CHECK(rpc->tls_context.state != TLS_HANDSHAKE_COMPLETED);
        CHECK(r.calls == 0 && rpc_queue_length(rpc) == 1);
        silent(peer);

        /* The next connection is probed again before anything else. */
        next = accepted(listener);
        CHECK(rpc_service(rpc, POLLOUT) == 0 && rpc->is_connected);
        probe(next);
        CHECK(r.calls == 0 && rpc_queue_length(rpc) == 2);

        /* Destroying the context with the probe pending must not reconnect. */
        rpc_destroy_context(rpc);
        CHECK(r.calls == 1 && r.status == RPC_STATUS_CANCEL && connect_calls == 2);
        close(next); close(peer); close(old_peer); close(listener);
}
static void exhausted(void)
{
        struct result r = {0}, later = {0};
        int listener, old_peer, peer;
        struct rpc_context *rpc = reconnected(1, &r, &listener, &old_peer, &peer);

        refuse(peer, probe(peer), NO_STARTTLS);
        CHECK(rpc_service(rpc, POLLIN) == -1);

        /* Out of retries: the request fails and the socket is unusable. */
        CHECK(r.calls == 1 && r.status == RPC_STATUS_ERROR && connect_calls == 1);
        CHECK(!rpc->is_connected && rpc->fd == -1);
        rpc_nfs4_null_task(rpc, complete, &later);
        silent(peer);

        rpc_destroy_context(rpc);
        CHECK(later.calls == 1);
        close(peer); close(old_peer); close(listener);
}
static void outlived(void)
{
        struct result r = {0};
        int listener, old_peer, peer;
        struct rpc_context *rpc = reconnected(-1, &r, &listener, &old_peer, &peer);

        /* The new connection is lost with the probe unanswered and the
         * next attempt fails for good. */
        probe(peer);
        injected_errno = EINVAL;
        CHECK(rpc_service(rpc, POLLHUP) == -1 && connect_calls == 2);
        injected_errno = 0;

        /* The probe fails along with the request and restarts nothing. */
        CHECK(r.calls == 1 && r.status == RPC_STATUS_ERROR);
        CHECK(rpc_queue_length(rpc) == 0);
        rpc_destroy_context(rpc);
        close(peer); close(old_peer); close(listener);
}
int main(void)
{
        alarm(20);
        retried(NO_STARTTLS);
        puts("PASS: a reconnect answered without STARTTLS is given up and retried");
        retried(DENIED);
        puts("PASS: a reconnect whose AUTH_TLS probe is rejected is given up and retried");
        retried(SILENCE);
        puts("PASS: a reconnect whose AUTH_TLS probe times out is given up and retried");
        exhausted();
        puts("PASS: a reconnect that runs out of retries without TLS sends nothing");
        outlived();
        puts("PASS: a probe that outlives its connection does not revive a failed context");
        return 0;
}
#endif
