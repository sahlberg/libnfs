// Copyright 2026 Kun-Wei Wu
// SPDX-License-Identifier: LGPL-2.1-or-later

// Fuzzes the libnfs server transport: the bytes an RPC client sends to a
// server built on rpc_init_server_context() (as servers/nfsd, rpcbind and
// statd do). The server context sits on one end of a socketpair and the
// fuzz input is written to the other end as the client's TCP stream.
// rpc_service() reads it through the record-marking state machine, decodes
// the CALL header (zdr_callmsg: rpcvers, prog/vers/proc, credential,
// verifier), looks up the registered program/version/procedure, decodes the
// procedure arguments with that procedure's zdr_*args decoder and runs the
// callback, which sends an empty SUCCESS reply. Unknown programs, versions
// and procedures, and undecodable arguments, get the library's error replies
// (PROG_UNAVAIL, PROG_MISMATCH, PROC_UNAVAIL, GARBAGE_ARGS).
//
// Input layout:
//   data[0]  write chunk size, 0 = write everything at once; small chunks
//            make recv() return partial record markers / payloads
//   data[1:] raw TCP stream from the "client": record marker(s) and CALLs
//
// Only the public API is used. No internal state is preset.

/* glibc needs this for caddr_t in the system headers */
#ifndef __APPLE__
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-raw-nfs4.h"
#include "libnfs-raw-nlm.h"
#include "libnfs-raw-nsm.h"
#include "libnfs-raw-portmap.h"
#include "libnfs-raw-rquota.h"

/* Stay well below the socketpair buffer so writes never block for long. */
#define MAX_STREAM (32 * 1024)

/*
 * Every procedure answers with an empty SUCCESS reply, which exercises the
 * reply encoder and send path. call->body.cbody.args is only valid during
 * this callback and is not looked at or kept.
 */
static int reply_cb(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
	(void)opaque;
	return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
}

/* A procedure with arguments of type T decoded by zdr_T, or with none. */
#define ARGS(proc, T) { proc, reply_cb, (zdrproc_t)zdr_##T, sizeof(T), NULL }
#define NOARGS(proc)  { proc, reply_cb, (zdrproc_t)zdr_void, 0, NULL }

static struct service_proc nfs2_procs[] = {
	NOARGS(NFS2_NULL),
	ARGS(NFS2_GETATTR, GETATTR2args),   ARGS(NFS2_SETATTR, SETATTR2args),
	ARGS(NFS2_LOOKUP, LOOKUP2args),     ARGS(NFS2_READLINK, READLINK2args),
	ARGS(NFS2_READ, READ2args),         ARGS(NFS2_WRITE, WRITE2args),
	ARGS(NFS2_CREATE, CREATE2args),     ARGS(NFS2_REMOVE, REMOVE2args),
	ARGS(NFS2_RENAME, RENAME2args),     ARGS(NFS2_LINK, LINK2args),
	ARGS(NFS2_SYMLINK, SYMLINK2args),   ARGS(NFS2_MKDIR, MKDIR2args),
	ARGS(NFS2_RMDIR, RMDIR2args),       ARGS(NFS2_READDIR, READDIR2args),
	ARGS(NFS2_STATFS, STATFS2args),
};

static struct service_proc nfs3_procs[] = {
	NOARGS(NFS3_NULL),
	ARGS(NFS3_GETATTR, GETATTR3args),   ARGS(NFS3_SETATTR, SETATTR3args),
	ARGS(NFS3_LOOKUP, LOOKUP3args),     ARGS(NFS3_ACCESS, ACCESS3args),
	ARGS(NFS3_READLINK, READLINK3args), ARGS(NFS3_READ, READ3args),
	ARGS(NFS3_WRITE, WRITE3args),       ARGS(NFS3_CREATE, CREATE3args),
	ARGS(NFS3_MKDIR, MKDIR3args),       ARGS(NFS3_SYMLINK, SYMLINK3args),
	ARGS(NFS3_MKNOD, MKNOD3args),       ARGS(NFS3_REMOVE, REMOVE3args),
	ARGS(NFS3_RMDIR, RMDIR3args),       ARGS(NFS3_RENAME, RENAME3args),
	ARGS(NFS3_LINK, LINK3args),         ARGS(NFS3_READDIR, READDIR3args),
	ARGS(NFS3_READDIRPLUS, READDIRPLUS3args),
	ARGS(NFS3_FSSTAT, FSSTAT3args),     ARGS(NFS3_FSINFO, FSINFO3args),
	ARGS(NFS3_PATHCONF, PATHCONF3args), ARGS(NFS3_COMMIT, COMMIT3args),
};

static struct service_proc nfs4_procs[] = {
	NOARGS(NFSPROC4_NULL),
	ARGS(NFSPROC4_COMPOUND, COMPOUND4args),
};

static struct service_proc nfsacl3_procs[] = {
	NOARGS(NFSACL3_NULL),
	ARGS(NFSACL3_GETACL, GETACL3args),  ARGS(NFSACL3_SETACL, SETACL3args),
};

static struct service_proc mount1_procs[] = {
	NOARGS(MOUNT1_NULL),
	ARGS(MOUNT1_MNT, MOUNT1MNTargs),    NOARGS(MOUNT1_DUMP),
	ARGS(MOUNT1_UMNT, MOUNT1UMNTargs),  NOARGS(MOUNT1_UMNTALL),
	NOARGS(MOUNT1_EXPORT),
};

static struct service_proc mount3_procs[] = {
	NOARGS(MOUNT3_NULL),
	ARGS(MOUNT3_MNT, MOUNT3MNTargs),    NOARGS(MOUNT3_DUMP),
	ARGS(MOUNT3_UMNT, MOUNT3UMNTargs),  NOARGS(MOUNT3_UMNTALL),
	NOARGS(MOUNT3_EXPORT),
};

/* Same tables as servers/rpcbind/rpcbind.c. */
static struct service_proc pmap2_procs[] = {
	NOARGS(PMAP2_NULL),
	ARGS(PMAP2_SET, PMAP2SETargs),      ARGS(PMAP2_UNSET, PMAP2UNSETargs),
	ARGS(PMAP2_GETPORT, PMAP2GETPORTargs), NOARGS(PMAP2_DUMP),
	ARGS(PMAP2_CALLIT, PMAP2CALLITargs),
};

static struct service_proc pmap3_procs[] = {
	NOARGS(PMAP3_NULL),
	ARGS(PMAP3_SET, PMAP3SETargs),      ARGS(PMAP3_UNSET, PMAP3UNSETargs),
	ARGS(PMAP3_GETADDR, PMAP3GETADDRargs), NOARGS(PMAP3_DUMP),
	ARGS(PMAP3_CALLIT, PMAP3CALLITargs), NOARGS(PMAP3_GETTIME),
	ARGS(PMAP3_UADDR2TADDR, PMAP3UADDR2TADDRargs),
	ARGS(PMAP3_TADDR2UADDR, PMAP3TADDR2UADDRargs),
};

static struct service_proc pmap4_procs[] = {
	NOARGS(PMAP4_NULL),
	ARGS(PMAP4_SET, PMAP4SETargs),      ARGS(PMAP4_UNSET, PMAP4UNSETargs),
	ARGS(PMAP4_GETADDR, PMAP4GETADDRargs), NOARGS(PMAP4_DUMP),
	ARGS(PMAP4_BCAST, PMAP4BCASTargs),  NOARGS(PMAP4_GETTIME),
	ARGS(PMAP4_UADDR2TADDR, PMAP4UADDR2TADDRargs),
	ARGS(PMAP4_TADDR2UADDR, PMAP4TADDR2UADDRargs),
	ARGS(PMAP4_GETVERSADDR, PMAP4GETVERSADDRargs),
	ARGS(PMAP4_INDIRECT, PMAP4INDIRECTargs),
	ARGS(PMAP4_GETADDRLIST, PMAP4GETADDRLISTargs),
	NOARGS(PMAP4_GETSTAT),
};

static struct service_proc nlm4_procs[] = {
	NOARGS(NLM4_NULL),
	ARGS(NLM4_TEST, NLM4_TESTargs),     ARGS(NLM4_LOCK, NLM4_LOCKargs),
	ARGS(NLM4_CANCEL, NLM4_CANCargs),   ARGS(NLM4_UNLOCK, NLM4_UNLOCKargs),
	ARGS(NLM4_GRANT, NLM4_GRANTEDargs),
	ARGS(NLM4_TEST_MSG, NLM4_TESTargs), ARGS(NLM4_LOCK_MSG, NLM4_LOCKargs),
	ARGS(NLM4_CANCEL_MSG, NLM4_CANCargs),
	ARGS(NLM4_UNLOCK_MSG, NLM4_UNLOCKargs),
	ARGS(NLM4_SHARE, NLM4_SHAREargs),
	/* UNSHARE has its own decoder for the same argument type */
	{ NLM4_UNSHARE, reply_cb, (zdrproc_t)zdr_NLM4_UNSHAREargs,
	  sizeof(NLM4_SHAREargs), NULL },
};

static struct service_proc nsm1_procs[] = {
	NOARGS(NSM1_NULL),
	ARGS(NSM1_STAT, NSM1_STATargs),     ARGS(NSM1_MON, NSM1_MONargs),
	ARGS(NSM1_UNMON, NSM1_UNMONargs),
	ARGS(NSM1_UNMON_ALL, NSM1_UNMONALLargs),
	NOARGS(NSM1_SIMU_CRASH),            ARGS(NSM1_NOTIFY, NSM1_NOTIFYargs),
};

static struct service_proc rquota1_procs[] = {
	NOARGS(RQUOTA1_NULL),
	ARGS(RQUOTA1_GETQUOTA, GETQUOTA1args),
	ARGS(RQUOTA1_GETACTIVEQUOTA, GETQUOTA1args),
};

static struct service_proc rquota2_procs[] = {
	NOARGS(RQUOTA2_NULL),
	ARGS(RQUOTA2_GETQUOTA, GETQUOTA2args),
	ARGS(RQUOTA2_GETACTIVEQUOTA, GETQUOTA2args),
};

#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))
static const struct {
	int program, version;
	struct service_proc *procs;
	int num_procs;
} services[] = {
	{ NFS_PROGRAM, NFS_V2, nfs2_procs, N(nfs2_procs) },
	{ NFS_PROGRAM, NFS_V3, nfs3_procs, N(nfs3_procs) },
	{ NFS4_PROGRAM, NFS_V4, nfs4_procs, N(nfs4_procs) },
	{ NFSACL_PROGRAM, NFSACL_V3, nfsacl3_procs, N(nfsacl3_procs) },
	{ MOUNT_PROGRAM, MOUNT_V1, mount1_procs, N(mount1_procs) },
	{ MOUNT_PROGRAM, MOUNT_V3, mount3_procs, N(mount3_procs) },
	{ PMAP_PROGRAM, PMAP_V2, pmap2_procs, N(pmap2_procs) },
	{ PMAP_PROGRAM, PMAP_V3, pmap3_procs, N(pmap3_procs) },
	{ PMAP_PROGRAM, PMAP_V4, pmap4_procs, N(pmap4_procs) },
	{ NLM_PROGRAM, NLM_V4, nlm4_procs, N(nlm4_procs) },
	{ NSM_PROGRAM, NSM_V1, nsm1_procs, N(nsm1_procs) },
	{ RQUOTA_PROGRAM, RQUOTA_V1, rquota1_procs, N(rquota1_procs) },
	{ RQUOTA_PROGRAM, RQUOTA_V2, rquota2_procs, N(rquota2_procs) },
};

/* Read and discard the server's replies so its writes never back up. */
static void drain(int fd)
{
	char junk[4096];

	while (read(fd, junk, sizeof(junk)) > 0)
		;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct rpc_context *rpc;
	int sv[2];
	size_t chunk, off = 0, rounds, i;

	if (size < 1 || size > MAX_STREAM + 1)
		return 0;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 0;
	fcntl(sv[0], F_SETFL, O_NONBLOCK);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);

	/* A server context starts out connected on the given fd. */
	rpc = rpc_init_server_context(sv[0]);
	if (rpc == NULL) {
		close(sv[0]);
		close(sv[1]);
		return 0;
	}
	for (i = 0; i < (size_t)N(services); i++) {
		if (rpc_register_service(rpc, services[i].program,
		                         services[i].version, services[i].procs,
		                         services[i].num_procs) != 0)
			goto out;
	}

	chunk = data[0] ? data[0] : size;
	data += 1;
	size -= 1;
	/*
	 * Each round writes one chunk, lets the server read it and send its
	 * replies, then throws the replies away.
	 */
	for (rounds = 0; off < size && rounds <= size; rounds++) {
		size_t n = size - off < chunk ? size - off : chunk;
		ssize_t w = write(sv[1], data + off, n);
		if (w > 0)
			off += (size_t)w;
		if (rpc_service(rpc, POLLIN | POLLOUT) < 0)
			goto out;
		drain(sv[1]);
	}
	/* Flush replies still queued. */
	if (rpc_service(rpc, POLLOUT) < 0)
		goto out;
	drain(sv[1]);
	/* Client hangs up: exercises the EOF / partial-record path. */
	close(sv[1]);
	sv[1] = -1;
	rpc_service(rpc, POLLIN);

out:
	rpc_destroy_context(rpc); /* closes sv[0], frees queued replies */
	if (sv[1] != -1)
		close(sv[1]);
	return 0;
}
