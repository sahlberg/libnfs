// Copyright 2026 Kun-Wei Wu
// SPDX-License-Identifier: LGPL-2.1-or-later

// Fuzzes the high-level libnfs client (lib/nfs_v3.c, lib/nfs_v4.c,
// lib/libnfs.c) against a malicious server.
//
// The fuzzer mounts an export with the public async API and then runs a
// few file operations (stat, open, pread, opendir, readlink, rename, ...).
// It plays the server itself: every TCP connection libnfs opens is replaced
// by one end of a socketpair (socket(), connect(), bind() and a few more
// are wrapped at link time with -Wl,--wrap, see README.md). The fuzzer
// reads each CALL libnfs sends, copies its XID and answers with the next
// reply taken from the fuzz input.
//
// So the input controls the content of every reply (portmapper, mountd,
// NFSv3 results, NFSv4 COMPOUND results) but does not have to guess XIDs or
// record markers; those are covered by libnfs_rpc_reply_stream_fuzzer.
//
// Build-time: -DFUZZ_NFS_VERSION=3 | 40 | 41 | 42, one binary per NFS
// version (40, 41, 42 = NFSv4.0, 4.1, 4.2).
//
// Input layout:
//   data[0]     option bits (see OPT_* below). With OPT_BACKCHANNEL (NFSv4.1
//               and 4.2) the client registers a callback handler, and an
//               unsolicited record that is a CB_COMPOUND call reaches the
//               back channel code in nfs4/nfs4.c
//   data[1..8]  four operations, each [selector][argument]. Selector bit 7
//               set = do not wait for this operation's reply before
//               starting the next one, so several requests are in flight
//   data[9..]   replies, each: u16 little-endian header, then the body
//               header bits 0..12  body length (max 8191)
//               header bit  13     unused
//               header bit  14     1 = unsolicited record: the body is sent
//                                  as-is (own XID) without waiting for a
//                                  CALL (NFSv4.1 back channel, stray replies)
//               header bit  15     0 = the fuzzer prepends the 20 byte
//                                  "accepted, AUTH_NONE verifier, SUCCESS"
//                                  RPC reply header, 1 = body is everything
//                                  after the XID
//
// Only the public API is used. No internal state is preset.

/* glibc needs this for caddr_t, SEEK_DATA and SOCK_CLOEXEC */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <utime.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-raw-nfs4.h"

#ifndef FUZZ_NFS_VERSION
#define FUZZ_NFS_VERSION 3
#endif
/* libnfs.h: NFS_V3 = 3, NFS_V4 = 4 (NFSv4.0), NFS_V4_1 = 41, NFS_V4_2 = 42 */
#define NFS_VERSION (FUZZ_NFS_VERSION == 40 ? NFS_V4 : FUZZ_NFS_VERSION)

#define OPT_PORTMAP        0x01 /* v3: look ports up via the portmapper */
#define OPT_AUTORECONNECT  0x02 /* allow one reconnect instead of none */
#define OPT_NO_DIRCACHE    0x04
#define OPT_NO_TRAVERSE    0x08 /* nfs_set_auto_traverse_mounts(0) */
#define OPT_SMALL_IO       0x10 /* tiny readmax/writemax: multi-RPC reads */
#define OPT_SMALL_READDIR  0x20
#define OPT_BACKCHANNEL    0x40 /* v4.1+: ask for a back channel */
#define OPT_BC_ACCEPT      0x80 /* the callback answers NFS4_OK */

#define HDR_SIZE     9
#define NUM_OPS      4
#define NUM_SEL      64   /* operation = selector % NUM_SEL, see call_op() */
#define SEL_CLOSE    13
#define SEL_UMOUNT   34
#define SEL_NOWAIT   0x80 /* selector bit 7 */
#define MAX_PEERS    8
#define MAX_SOCKETS  24   /* connections per input, bounds reconnect loops */
#define MAX_ITERS    400
#define CALL_BUF     (64 * 1024)
#define IO_BUF       256  /* size of the caller's write buffer */

/* The fake network: socketpairs instead of TCP connections. */

struct peer {
	int used;
	int cfd;    /* the end libnfs owns */
	int sfd;    /* the fuzzer ("server") end */
	size_t len; /* bytes of CALL data buffered */
	uint8_t buf[CALL_BUF];
};
static struct peer peers[MAX_PEERS];
static int net_active;  /* wrappers only act while an input is running */
static int net_sockets; /* sockets handed out for this input */

int __real_socket(int domain, int type, int protocol);
int __real_connect(int fd, const struct sockaddr *addr, socklen_t len);
int __real_bind(int fd, const struct sockaddr *addr, socklen_t len);
int __real_dup2(int oldfd, int newfd);
int __real_setsockopt(int fd, int level, int name, const void *val,
                      socklen_t len);

static struct peer *peer_by_cfd(int fd)
{
	int i;

	for (i = 0; i < MAX_PEERS; i++)
		if (peers[i].used && peers[i].cfd == fd)
			return &peers[i];
	return NULL;
}

static void peer_drop(struct peer *p)
{
	close(p->sfd);
	p->used = 0;
	p->len = 0;
}

/* Remove the first n buffered bytes (one whole record). */
static void peer_consume(struct peer *p, size_t n)
{
	memmove(p->buf, p->buf + n, p->len - n);
	p->len -= n;
}

/* Close server ends whose client end libnfs has already closed. */
static void peers_reap(void)
{
	char c;
	int i;

	for (i = 0; i < MAX_PEERS; i++) {
		struct peer *p = &peers[i];

		if (p->used && p->len == 0 &&
		    recv(p->sfd, &c, 1, MSG_PEEK | MSG_DONTWAIT) == 0)
			peer_drop(p);
	}
}

int __wrap_socket(int domain, int type, int protocol)
{
	int sv[2], i;

	/* the low bits are the socket type, above them SOCK_NONBLOCK etc. */
	if (!net_active || (type & 0xf) != SOCK_STREAM)
		return __real_socket(domain, type, protocol);

	peers_reap();
	for (i = 0; i < MAX_PEERS && peers[i].used; i++)
		;
	if (i == MAX_PEERS || net_sockets >= MAX_SOCKETS) {
		errno = EMFILE;
		return -1;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | (type & SOCK_CLOEXEC), 0,
	               sv) != 0)
		return -1;
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	net_sockets++;
	peers[i].used = 1;
	peers[i].cfd = sv[0];
	peers[i].sfd = sv[1];
	return sv[0];
}

/*
 * The socketpair is already connected; libnfs then sees POLLOUT with
 * SO_ERROR == 0, exactly like a non-blocking connect that succeeded.
 */
int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (net_active && peer_by_cfd(fd) != NULL)
		return 0;
	return __real_connect(fd, addr, len);
}

/* libnfs tries to bind to a reserved port; pretend the first try works. */
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (net_active && peer_by_cfd(fd) != NULL)
		return 0;
	return __real_bind(fd, addr, len);
}

/*
 * TCP keepalive and friends do not exist on a socketpair, and libnfs treats
 * a failed SO_KEEPALIVE as a failed connect.
 */
int __wrap_setsockopt(int fd, int level, int name, const void *val,
                      socklen_t len)
{
	if (net_active && peer_by_cfd(fd) != NULL)
		return 0;
	return __real_setsockopt(fd, level, name, val, len);
}

/* A reconnect moves the new socket onto the old descriptor number. */
int __wrap_dup2(int oldfd, int newfd)
{
	struct peer *p, *stale;
	int ret = __real_dup2(oldfd, newfd);

	if (net_active && ret >= 0 && oldfd != newfd) {
		stale = peer_by_cfd(newfd); /* dup2 closed this one */
		p = peer_by_cfd(oldfd);
		if (stale != NULL && stale != p)
			peer_drop(stale);
		if (p != NULL)
			p->cfd = newfd;
	}
	return ret;
}

/* Avoids reading /etc/services for every connection. */
struct servent *__wrap_getservbyport(int port, const char *proto)
{
	(void)port; (void)proto;
	return NULL;
}

/* The fuzz input reader and the fake server. */

struct input {
	const uint8_t *p;
	size_t left;
};

static uint32_t be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static void send_all(int fd, const uint8_t *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = send(fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n <= 0)
			return; /* client end gone or buffer full */
		buf += n;
		len -= (size_t)n;
	}
}

static void send_be32(int fd, uint32_t v)
{
	uint8_t b[4] = { v >> 24, v >> 16, v >> 8, v };

	send_all(fd, b, sizeof(b));
}

/* Take the next reply entry. Returns 0 when the input is used up. */
static int next_entry(struct input *in, uint16_t *hdr, const uint8_t **body,
                      size_t *len)
{
	if (in->left < 2)
		return 0;
	*hdr = (uint16_t)(in->p[0] | (in->p[1] << 8));
	in->p += 2;
	in->left -= 2;
	*len = *hdr & 0x1fff;
	if (*len > in->left)
		*len = in->left;
	*body = in->p;
	in->p += *len;
	in->left -= *len;
	return 1;
}

/* Send one record: marker, optional XID and "accepted" header, body. */
static void send_record(int fd, int have_xid, uint32_t xid, int ok_header,
                        const uint8_t *body, size_t len)
{
	/* REPLY, MSG_ACCEPTED, verifier AUTH_NONE length 0, SUCCESS */
	static const uint8_t ok[20] = { 0, 0, 0, 1 };
	size_t total = len + (have_xid ? 4 : 0) + (ok_header ? sizeof(ok) : 0);

	send_be32(fd, 0x80000000u | (uint32_t)total);
	if (have_xid)
		send_be32(fd, xid);
	if (ok_header)
		send_all(fd, ok, sizeof(ok));
	send_all(fd, body, len);
}

/*
 * Read the CALLs libnfs wrote and answer each one. Returns the number of
 * records written to the client.
 */
static int serve_peer(struct peer *p, struct input *in)
{
	int sent = 0;
	uint16_t hdr;
	const uint8_t *body;
	size_t len;

	while (p->len < CALL_BUF) {
		ssize_t n = recv(p->sfd, p->buf + p->len, CALL_BUF - p->len,
		                 MSG_DONTWAIT);
		if (n <= 0)
			break;
		p->len += (size_t)n;
	}

	while (p->len >= 8) {
		uint32_t marker = be32(p->buf);
		uint32_t reclen = marker & 0x7fffffff;
		uint32_t xid = be32(p->buf + 4);

		if (reclen < 4 || reclen > CALL_BUF - 4 ||
		    !(marker & 0x80000000u)) {
			p->len = 0; /* not something this server understands */
			break;
		}
		if (p->len < 4 + (size_t)reclen)
			break; /* CALL not complete yet */
		if (reclen >= 8 && be32(p->buf + 8) == 1) {
			/* a REPLY: libnfs answering a back channel call */
			peer_consume(p, 4 + reclen);
			continue;
		}

		/* Unsolicited records first, then the reply to this CALL. */
		for (;;) {
			if (!next_entry(in, &hdr, &body, &len))
				return sent; /* input used up: silence */
			if (!(hdr & 0x4000))
				break;
			send_record(p->sfd, 0, 0, 0, body, len);
			sent++;
		}
		send_record(p->sfd, 1, xid, !(hdr & 0x8000), body, len);
		sent++;

		peer_consume(p, 4 + reclen);
	}
	return sent;
}

/* The client application. */

enum kind { K_NONE, K_MOUNT, K_FH, K_DIR, K_STAT64, K_STAT4, K_STATVFS64,
            K_STR, K_READ, K_U64, K_STAT, K_STATVFS, K_ACL, K_READ_PLUS,
            K_WRITE_SAME };

/* Per-operation data that libnfs may use until the callback has run. */
struct opctx {
	enum kind k;         /* how to read the callback's data */
	uint8_t *rbuf;       /* exactly rcount bytes, so ASan sees overflows */
	size_t rcount;
	struct iovec iov[2]; /* for readv/preadv, both halves point into rbuf */
	struct nfs4_flock fl;
	app_data_block4 adb; /* WRITE_SAME argument */
};

struct state {
	struct nfs_context *nfs;
	int pending;         /* async calls still waiting for their callback */
	int mounted;
	int opening;         /* an open is in flight: do not start another */
	int unmounted;       /* nfs_umount() was called: no more operations */
	struct nfsfh *fh;
	struct opctx ops[NUM_OPS];
	struct opctx misc;   /* mount, and the final close */
};
static struct state st;
static volatile uint64_t sink;

/* Read every byte, so ASan checks what a callback was handed. */
static void touch(const void *p, size_t n)
{
	const volatile uint8_t *b = p;
	uint64_t s = 0;
	size_t i;

	for (i = 0; i < n; i++)
		s += b[i];
	sink += s;
}

static void touch_str(const char *s)
{
	touch(s, strlen(s));
}

static void op_cb(int status, struct nfs_context *nfs, void *data,
                  void *private_data)
{
	struct opctx *o = private_data;

	st.pending--;
	if (o->k == K_FH)
		st.opening = 0;
	if (status < 0) {
		if (data != NULL)
			touch_str(data); /* error string */
		return;
	}
	switch (o->k) {
	case K_MOUNT:
		st.mounted = 1;
		break;
	case K_FH:
		if (st.fh == NULL)
			st.fh = data;
		break;
	case K_DIR: {
		struct nfsdir *dir = data;
		struct nfsdirent *e;
		long pos = -1;
		int pass;

		/*
		 * Read to the end, rewind, read again, seek to the first
		 * entry's position, read once more.
		 */
		for (pass = 0; pass < 3; pass++) {
			while ((e = nfs_readdir(nfs, dir)) != NULL) {
				touch_str(e->name);
				touch(e, sizeof(*e));
				if (pos < 0)
					pos = nfs_telldir(nfs, dir);
			}
			if (pass == 0)
				nfs_rewinddir(nfs, dir);
			else if (pos >= 0)
				nfs_seekdir(nfs, dir, pos);
		}
		nfs_closedir(nfs, dir);
		break;
	}
	case K_STAT64:
		touch(data, sizeof(struct nfs_stat_64));
		break;
	case K_STAT4: {
		struct nfs4_stat_64 *s4 = data;

		touch(&s4->st, sizeof(s4->st));
		if (s4->nfs_user != NULL)
			touch_str(s4->nfs_user);
		if (s4->nfs_group != NULL)
			touch_str(s4->nfs_group);
		break;
	}
	case K_STATVFS64:
		touch(data, sizeof(struct nfs_statvfs_64));
		break;
	case K_STR:
		touch_str(data);
		break;
	case K_READ:
		/*
		 * status = bytes read; more than rcount is a library bug and
		 * this read then runs off the end of the heap buffer.
		 */
		touch(o->rbuf, (size_t)status);
		break;
	case K_U64:
		touch(data, sizeof(uint64_t));
		break;
	case K_STAT:
		touch(data, sizeof(struct stat));
		break;
	case K_STATVFS:
		touch(data, sizeof(struct statvfs));
		break;
	case K_ACL: {
#if FUZZ_NFS_VERSION >= 40
		fattr4_acl *acl = data;
		uint32_t i;

		for (i = 0; i < acl->fattr4_acl_len; i++) {
			nfsace4 *ace = &acl->fattr4_acl_val[i];

			touch(ace, sizeof(*ace));
			touch(ace->who.utf8string_val, ace->who.utf8string_len);
		}
#else
		fattr3_acl *acl = data;

		touch(acl->ace, acl->ace_count * sizeof(acl->ace[0]));
		touch(acl->default_ace,
		      acl->default_ace_count * sizeof(acl->default_ace[0]));
		/*
		 * The NFSv3 callback owns the two arrays (libnfs' own sync
		 * wrapper takes them over the same way); NFSv4 frees its own.
		 */
		nfs3_acl_free(acl);
#endif
		break;
	}
	case K_READ_PLUS: {
		READ_PLUS4resok *r = data;
		uint32_t i;

		for (i = 0; i < r->rpr_contents.rpr_contents_len; i++) {
			read_plus_content *c =
				&r->rpr_contents.rpr_contents_val[i];
			data4 *d = &c->read_plus_content_u.rpc_data;

			if (c->rpc_content == NFS4_CONTENT_DATA)
				touch(d->d_data.d_data_val,
				      d->d_data.d_data_len);
			else
				touch(&c->read_plus_content_u.rpc_hole,
				      sizeof(c->read_plus_content_u.rpc_hole));
		}
		break;
	}
	case K_WRITE_SAME: {
		write_response4 *w = data;

		touch(w->wr_callback_id.wr_callback_id_val,
		      w->wr_callback_id.wr_callback_id_len * sizeof(stateid4));
		touch(&w->wr_count, sizeof(w->wr_count));
		break;
	}
	default:
		break;
	}
}

/* Callback + its context; records in the context how to read the result. */
#define CB(kind) (o->k = (kind), op_cb), o

#if FUZZ_NFS_VERSION >= 41
/*
 * Back channel handler: called for CB_GETATTR, CB_RECALL, CB_PUSH_DELEG,
 * CB_RECALL_ANY and CB_RECALLABLE_OBJ_AVAIL with the decoded arguments.
 */
static void bc_cb(struct rpc_context *rpc, struct nfs_cb_argop4 *arg,
                  struct nfs_cb_resop4 *res, void *private_data)
{
	(void)rpc;
	switch (arg->argop) {
	case OP_CB_GETATTR: {
		CB_GETATTR4args *a = &arg->nfs_cb_argop4_u.opcbgetattr;

		touch(a->fh.nfs_fh4_val, a->fh.nfs_fh4_len);
		touch(a->attr_request.bitmap4_val,
		      4 * (size_t)a->attr_request.bitmap4_len);
		break;
	}
	case OP_CB_RECALL: {
		CB_RECALL4args *a = &arg->nfs_cb_argop4_u.opcbrecall;

		touch(&a->stateid, sizeof(a->stateid));
		touch(a->fh.nfs_fh4_val, a->fh.nfs_fh4_len);
		break;
	}
	case OP_CB_PUSH_DELEG: {
		CB_PUSH_DELEG4args *a = &arg->nfs_cb_argop4_u.opcbpush_deleg;

		touch(a->cpda_fh.nfs_fh4_val, a->cpda_fh.nfs_fh4_len);
		break;
	}
	case OP_CB_RECALL_ANY: {
		CB_RECALL_ANY4args *a = &arg->nfs_cb_argop4_u.opcbrecall_any;

		touch(a->craa_type_mask.bitmap4_val,
		      4 * (size_t)a->craa_type_mask.bitmap4_len);
		break;
	}
	default:
		break;
	}
	/* NFS4_OK; for CB_GETATTR that is an empty attribute list */
	if (private_data != NULL)
		memset(&res->nfs_cb_resop4_u, 0, sizeof(res->nfs_cb_resop4_u));
}
#endif

static const char *const paths[] = {
	"/", "a", "/a/b", "a/../b/./c", "/link/x", "dir/", "//a//b/",
	"../../up", "a/b/c/d/e/f/g/h", "file.txt",
};
#define PATH(a) paths[(a) % (sizeof(paths) / sizeof(paths[0]))]

/*
 * A fresh read buffer of exactly n bytes, so ASan sees an overflow. The two
 * iovecs cover it: the first `first` bytes and the rest.
 */
static void read_buf(struct opctx *o, size_t n, size_t first)
{
	free(o->rbuf);
	o->rbuf = malloc(n);
	o->rcount = n;
	o->iov[0].iov_base = o->rbuf;
	o->iov[0].iov_len = first;
	o->iov[1].iov_base = o->rbuf + first;
	o->iov[1].iov_len = n - first;
}

/*
 * Call the operation `op` picks. Returns what libnfs returned (0 = queued),
 * or -1 if the operation does not exist for this NFS version or does not
 * apply now: it needs an open file, or it opens one and one is open already.
 */
static int call_op(struct opctx *o, int op, uint8_t arg)
{
	static const int oflags[] = {
		O_RDONLY, O_RDWR, O_WRONLY | O_CREAT, O_RDWR | O_CREAT | O_EXCL,
		O_WRONLY | O_TRUNC, O_RDWR | O_APPEND, O_RDONLY | O_NOFOLLOW,
		O_WRONLY | O_CREAT | O_TRUNC,
	};
	static const int whence[] = { SEEK_SET, SEEK_CUR, SEEK_END,
	                              SEEK_DATA, SEEK_HOLE };
	/* 0, PUNCH_HOLE|KEEP_SIZE, ZERO_RANGE, KEEP_SIZE (refused) */
	static const int fmodes[] = { 0, 3, 0x10, 1 };
	static uint8_t wbuf[IO_BUF];
	struct nfs_context *nfs = st.nfs;
	struct nfsfh *fh = st.fh;
	const char *path = PATH(arg);
	const char *path2 = PATH(arg >> 4);
	int oflag = oflags[(arg >> 4) % 8];
	uint64_t off = (uint64_t)arg << 4;
	struct timeval tv[2] = { { 1, 2 }, { 3, 4 } };
	struct utimbuf ut = { 5, 6 };

	/* Operations on a path. */
	switch (op) {
	case 0:
		return nfs_stat64_async(nfs, path, CB(K_STAT64));
	case 1:
		return nfs_lstat64_async(nfs, path, CB(K_STAT64));
	case 14:
		return nfs_opendir_async(nfs, path, CB(K_DIR));
	case 15:
		return nfs_mkdir2_async(nfs, path, 0755, CB(K_NONE));
	case 16:
		return nfs_rmdir_async(nfs, path, CB(K_NONE));
	case 17:
		return nfs_unlink_async(nfs, path, CB(K_NONE));
	case 18:
		return nfs_rename_async(nfs, path, path2, CB(K_NONE));
	case 19:
		return nfs_symlink_async(nfs, path2, path, CB(K_NONE));
	case 20:
		return nfs_link_async(nfs, path, path2, CB(K_NONE));
	case 21:
		return nfs_readlink_async(nfs, path, CB(K_STR));
	case 22:
		return nfs_chmod_async(nfs, path, 0644, CB(K_NONE));
	case 23:
		return nfs_lchown_async(nfs, path, 1000, 1000, CB(K_NONE));
	case 24:
		return nfs_utimes_async(nfs, path, tv, CB(K_NONE));
	case 25:
		return nfs_truncate_async(nfs, path, arg, CB(K_NONE));
	case 26:
		return nfs_statvfs64_async(nfs, path, CB(K_STATVFS64));
	case 27:
		return nfs_access_async(nfs, path, arg & 7, CB(K_NONE));
	case 28:
		return nfs_access2_async(nfs, path, CB(K_NONE));
	case 29:
		return nfs_mknod_async(nfs, path, 0600 | S_IFCHR, 0x0102,
		                       CB(K_NONE));
	case 30:
		return nfs_chdir_async(nfs, path, CB(K_NONE));
	case 31:
#if FUZZ_NFS_VERSION >= 40
		return nfs4_stat64_async(nfs, path, CB(K_STAT4));
#else
		return nfs_chown_async(nfs, path, 1, 2, CB(K_NONE));
#endif
	case SEL_UMOUNT:
		st.unmounted = 1;
		return nfs_umount_async(nfs, CB(K_NONE));
	case 35:
		return nfs_stat_async(nfs, path, CB(K_STAT));
	case 37:
		return nfs_statvfs_async(nfs, path, CB(K_STATVFS));
	case 40:
		return nfs_utime_async(nfs, path, (arg & 0x80) ? NULL : &ut,
		                       CB(K_NONE));
	case 41:
		return nfs_lchmod_async(nfs, path, 0700, CB(K_NONE));
	case 42:
		return nfs_chown_async(nfs, path, 5, 6, CB(K_NONE));
	case 45:
		return nfs_lutimes_async(nfs, path, tv, CB(K_NONE));
	case 46:
		return nfs_mkdir_async(nfs, path, CB(K_NONE));
#if FUZZ_NFS_VERSION >= 40
	case 49:
		return nfs4_opendir_namedattr_async(nfs, path, CB(K_DIR));
	case 51:
		return nfs4_remove_namedattr_async(nfs, path, "attr",
		                                   CB(K_NONE));
	case 54:
		return nfs4_lstat64_async(nfs, path, CB(K_STAT4));
#endif
	}

	/* Operations that open the one file the fuzzer keeps open. */
	if (fh == NULL) {
		if (st.opening)
			return -1;
		switch (op) {
		case 2:
			return nfs_open_async(nfs, path, oflag, CB(K_FH));
		case 3:
			return nfs_open2_async(nfs, path, oflag, 0640,
			                       CB(K_FH));
		case 4:
			return nfs_creat_async(nfs, path, 0600, CB(K_FH));
#if FUZZ_NFS_VERSION >= 40
		case 50:
			return nfs4_open_namedattr_async(nfs, path, "attr",
			                                 oflag, CB(K_FH));
#endif
		}
		return -1;
	}

	/* Operations on the open file. */
	switch (op) {
	case 5:
		read_buf(o, 1 + arg, 0); /* 1..256 bytes */
		return nfs_pread_async(nfs, fh, o->rbuf, o->rcount, off,
		                       CB(K_READ));
	case 6:
		read_buf(o, 1 + arg, 0);
		return nfs_read_async(nfs, fh, o->rbuf, o->rcount, CB(K_READ));
	case 7:
		return nfs_pwrite_async(nfs, fh, wbuf, 1 + arg, off,
		                        CB(K_NONE));
	case 8:
		return nfs_write_async(nfs, fh, wbuf, 1 + arg, CB(K_NONE));
	case 9:
		return nfs_fstat64_async(nfs, fh, CB(K_STAT64));
	case 10:
		return nfs_ftruncate_async(nfs, fh, arg, CB(K_NONE));
	case 11:
		return nfs_lseek_async(nfs, fh, (int64_t)(arg >> 3) - 4,
		                       whence[arg % 5], CB(K_U64));
	case 12:
		return nfs_fsync_async(nfs, fh, CB(K_NONE));
	case SEL_CLOSE:
		/*
		 * The library owns the handle from here on, whether or not
		 * the close succeeds.
		 */
		st.fh = NULL;
		return nfs_close_async(nfs, fh, CB(K_NONE));
	case 32:
#if FUZZ_NFS_VERSION >= 40
		return nfs_lockf_async(nfs, fh, (enum nfs4_lock_op)(arg % 4),
		                       arg, CB(K_NONE));
#else
		return nfs_fchmod_async(nfs, fh, 0600, CB(K_NONE));
#endif
	case 33:
#if FUZZ_NFS_VERSION >= 40
		/*
		 * libnfs reads the flock again in its reply handler, so it
		 * has to outlive this function.
		 */
		o->fl.l_type = arg % 3 == 0 ? F_RDLCK :
		               arg % 3 == 1 ? F_WRLCK : F_UNLCK;
		o->fl.l_whence = (arg >> 2) % 3;
		o->fl.l_pid = 1;
		o->fl.l_start = arg;
		o->fl.l_len = arg >> 1;
		return nfs_fcntl_async(nfs, fh, (enum nfs4_fcntl_op)(arg >> 7),
		                       &o->fl, CB(K_NONE));
#else
		return nfs_fchown_async(nfs, fh, 3, 4, CB(K_NONE));
#endif
	case 36:
		return nfs_fstat_async(nfs, fh, CB(K_STAT));
	case 38:
		read_buf(o, 2 + arg, 1 + arg / 3); /* 2..257 bytes */
		return nfs_preadv_async(nfs, fh, o->iov, 2, off, CB(K_READ));
	case 39:
		read_buf(o, 2 + arg, 1 + arg / 3);
		return nfs_readv_async(nfs, fh, o->iov, 2, CB(K_READ));
	case 43:
		return nfs_fchmod_async(nfs, fh, 0604, CB(K_NONE));
	case 44:
		return nfs_fchown_async(nfs, fh, 7, 8, CB(K_NONE));
	case 47:
#if FUZZ_NFS_VERSION >= 40
		return nfs4_getacl_async(nfs, fh, CB(K_ACL));
#else
		return nfs3_getacl_async(nfs, fh, CB(K_ACL));
#endif
	case 48:
		return nfs_fallocate_async(nfs, fh, fmodes[arg % 4], arg >> 2,
		                           1 + (arg >> 4), CB(K_NONE));
#if FUZZ_NFS_VERSION >= 40
	case 52:
		return nfs42_read_plus_async(nfs, fh, arg, 1 + arg,
		                             CB(K_READ_PLUS));
	case 53:
		memset(&o->adb, 0, sizeof(o->adb));
		o->adb.adb_offset = arg;
		o->adb.adb_block_size = 8;
		o->adb.adb_block_count = 1 + (arg >> 4);
		o->adb.adb_pattern.adb_pattern_len = 4;
		o->adb.adb_pattern.adb_pattern_val = (char *)wbuf;
		return nfs42_write_same_async(nfs, fh, &o->adb, arg & 1,
		                              CB(K_WRITE_SAME));
	case 55:
		return nfs4_fstat64_async(nfs, fh, CB(K_STAT4));
#endif
	}
	return -1;
}

/* Queue one operation. Returns 0 if a callback is now pending. */
static int start_op(struct opctx *o, uint8_t sel, uint8_t arg)
{
	/*
	 * Counted before the call: some operations (close of an unmodified
	 * NFSv3 file) run their callback before returning.
	 */
	int before = st.pending++;
	int ret = call_op(o, sel % NUM_SEL, arg);

	if (ret != 0)
		st.pending--; /* nothing was queued, no callback will come */
	else if (o->k == K_FH && st.pending > before)
		st.opening = 1; /* an open whose callback has not run yet */
	return ret;
}

/*
 * Run the event loop until the pending callbacks have fired, the server has
 * nothing left to say, or the connection is beyond repair.
 */
static int run_until_idle(struct input *in)
{
	int iter, stalls = 0;

	for (iter = 0; iter < MAX_ITERS && st.pending; iter++) {
		struct peer *p;
		int progressed = 0;

		if (nfs_which_events(st.nfs) & POLLOUT) {
			if (nfs_service(st.nfs, POLLOUT) < 0)
				return -1;
			progressed = 1;
		}
		p = peer_by_cfd(nfs_get_fd(st.nfs));
		if (p != NULL && serve_peer(p, in) > 0) {
			if (nfs_service(st.nfs, POLLIN) < 0)
				return -1;
			progressed = 1;
		}
		if (progressed) {
			stalls = 0;
			continue;
		}
		/*
		 * A reply can take more than one read (the zero-copy READ
		 * path stops after the header), so poll again before deciding
		 * that nothing more will happen.
		 */
		if (++stalls > 3)
			return -1;
		if (p != NULL && nfs_service(st.nfs, POLLIN) < 0)
			return -1;
	}
	return st.pending ? -1 : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct input in;
	struct opctx *o;
	uint8_t opts;
	int i, drain = 0;

	if (size < HDR_SIZE)
		return 0;
	opts = data[0];
	in.p = data + HDR_SIZE;
	in.left = size - HDR_SIZE;

	memset(&st, 0, sizeof(st));
	st.nfs = nfs_init_context();
	if (st.nfs == NULL)
		return 0;
	net_active = 1;
	net_sockets = 0;

	if (nfs_set_version(st.nfs, NFS_VERSION) < 0)
		goto out;
	if (!(opts & OPT_PORTMAP)) {
		nfs_set_mountport(st.nfs, 20048);
		nfs_set_nfsport(st.nfs, 2049);
	}
	nfs_set_autoreconnect(st.nfs, (opts & OPT_AUTORECONNECT) ? 1 : 0);
	if (opts & OPT_NO_DIRCACHE)
		nfs_set_dircache(st.nfs, 0);
	if (opts & OPT_NO_TRAVERSE)
		nfs_set_auto_traverse_mounts(st.nfs, 0);
	if (opts & OPT_SMALL_READDIR)
		nfs_set_readdir_max_buffer_size(st.nfs, 512, 1024);
#if FUZZ_NFS_VERSION >= 41
	if (opts & OPT_BACKCHANNEL) {
		/* a non-NULL private_data makes bc_cb() answer NFS4_OK */
		void *accept = (opts & OPT_BC_ACCEPT) ? &st : NULL;

		rpc_nfs4_enable_backchannel(nfs_get_rpc_context(st.nfs),
		                            bc_cb, accept);
	}
#endif

	/* numeric address: getaddrinfo() does not touch DNS */
	o = &st.misc;
	st.pending = 1;
	if (nfs_mount_async(st.nfs, "127.0.0.1", "/export", CB(K_MOUNT)) != 0) {
		st.pending = 0;
		goto out;
	}
	if (run_until_idle(&in) != 0 || !st.mounted)
		goto out;
	if (opts & OPT_SMALL_IO) {
		nfs_set_readmax(st.nfs, 64);
		nfs_set_writemax(st.nfs, 64);
	}

	for (i = 0; i < NUM_OPS; i++) {
		uint8_t sel = data[1 + 2 * i];
		int op = sel % NUM_SEL;
		int exclusive = op == SEL_CLOSE || op == SEL_UMOUNT;

		/* close and umount wait for everything that is in flight */
		if (exclusive && st.pending && run_until_idle(&in) != 0)
			break;
		if (start_op(&st.ops[i], sel, data[2 + 2 * i]) != 0)
			continue; /* not applicable or refused: next one */
		if ((sel & SEL_NOWAIT) && !exclusive)
			continue; /* leave it in flight */
		if (run_until_idle(&in) != 0 || st.unmounted)
			break;
	}
	drain = (i == NUM_OPS); /* no operation ended the loop early */

out:
	if (st.pending && drain)
		run_until_idle(&in); /* replies for what is still in flight */
	/*
	 * Hand a still-open file back to the library. Its callback runs either
	 * at once or when nfs_destroy_context() cancels the queued request.
	 */
	if (st.fh != NULL) {
		struct nfsfh *fh = st.fh;

		st.fh = NULL;
		o = &st.misc;
		nfs_close_async(st.nfs, fh, CB(K_NONE));
	}
	nfs_destroy_context(st.nfs);
	net_active = 0;
	for (i = 0; i < MAX_PEERS; i++)
		if (peers[i].used)
			peer_drop(&peers[i]);
	for (i = 0; i < NUM_OPS; i++)
		free(st.ops[i].rbuf);
	return 0;
}
