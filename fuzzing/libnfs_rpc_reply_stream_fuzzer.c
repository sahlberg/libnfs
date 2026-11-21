// Copyright 2026 Kun-Wei Wu
// SPDX-License-Identifier: LGPL-2.1-or-later

// Fuzzes the libnfs client transport: the bytes an NFS/mount/portmap
// server sends back over TCP. A client rpc_context is attached to one end
// of a socketpair, one request is queued and sent, then the fuzz input is
// written to the other end as the server's reply stream. rpc_service()
// reads it through the record-marking state machine (rpc_read_from_socket),
// matches the XID, decodes the RPC reply header (rpc_process_reply) and
// the per-procedure result, and runs the completion callback.
//
// Input layout:
//   data[0]  which request to send (index into the table below)
//   data[1]  write chunk size, 0 = write everything at once; small chunks
//            make recv() return partial record markers / payloads
//   data[2:] raw TCP stream from the "server": record marker(s), then the
//            RPC reply starting with XID 0x11223344
//
// Only the public API is used. No internal state is preset.

/* glibc needs this for caddr_t in the system headers */
#ifndef __APPLE__
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-raw-portmap.h"

#define FIXED_XID 0x11223344
/* Stay well below the socketpair buffer so writes never block for long. */
#define MAX_STREAM (32 * 1024)

static void dummy_cb(struct rpc_context *rpc, int status, void *data,
                     void *private_data)
{
	(void)rpc; (void)status; (void)data; (void)private_data;
}

static struct rpc_pdu *send_request(struct rpc_context *rpc, uint8_t sel)
{
	static char fh_data[] = "fuzzfh00";
	nfs_fh3 fh = { { sizeof(fh_data) - 1, fh_data } };

	switch (sel % 11) {
	case 0:
		return rpc_null_task(rpc, NFS_PROGRAM, NFS_V3, dummy_cb, NULL);
	case 1: {
		GETATTR3args a = { fh };
		return rpc_nfs3_getattr_task(rpc, dummy_cb, &a, NULL);
	}
	case 2: {
		LOOKUP3args a = { { fh, "name" } };
		return rpc_nfs3_lookup_task(rpc, dummy_cb, &a, NULL);
	}
	case 3: {
		ACCESS3args a = { fh, 0x3f };
		return rpc_nfs3_access_task(rpc, dummy_cb, &a, NULL);
	}
	case 4: {
		READLINK3args a = { fh };
		return rpc_nfs3_readlink_task(rpc, dummy_cb, &a, NULL);
	}
	case 5: {
		READDIRPLUS3args a = { fh, 0, { 0 }, 4096, 8192 };
		return rpc_nfs3_readdirplus_task(rpc, dummy_cb, &a, NULL);
	}
	case 6: {
		FSINFO3args a = { fh };
		return rpc_nfs3_fsinfo_task(rpc, dummy_cb, &a, NULL);
	}
	case 7:
		return rpc_mount3_mnt_task(rpc, dummy_cb, "/export", NULL);
	case 8:
		return rpc_mount3_export_task(rpc, dummy_cb, NULL);
	case 9:
		return rpc_pmap2_getport_task(rpc, NFS_PROGRAM, NFS_V3,
		                              IPPROTO_TCP, dummy_cb, NULL);
	default: {
		struct pmap3_mapping m = { NFS_PROGRAM, NFS_V3, "tcp", "", "" };
		return rpc_pmap3_getaddr_task(rpc, &m, dummy_cb, NULL);
	}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct rpc_context *rpc;
	int sv[2];
	char junk[4096];
	size_t chunk, off = 0, rounds;

	if (size < 2 || size > MAX_STREAM + 2)
		return 0;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 0;
	fcntl(sv[0], F_SETFL, O_NONBLOCK);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);

	rpc = rpc_init_context();
	if (rpc == NULL) {
		close(sv[0]);
		close(sv[1]);
		return 0;
	}
	/*
	 * Keep the raw API default (reconnect disabled): when the reply stream
	 * breaks, the request being read is failed and freed together with the
	 * other queued PDUs.
	 */
	rpc_set_fd(rpc, sv[0]); /* owned by rpc from now on */
	/*
	 * First POLLOUT on an unconnected fd = "connect finished", sets
	 * is_connected like a real non-blocking connect would.
	 */
	rpc_service(rpc, POLLOUT);

	rpc_set_next_xid(rpc, FIXED_XID);
	if (send_request(rpc, data[0]) == NULL)
		goto out;
	rpc_service(rpc, POLLOUT);
	while (read(sv[1], junk, sizeof(junk)) > 0)
		; /* discard the CALL the client sent */

	chunk = data[1] ? data[1] : size;
	data += 2;
	size -= 2;
	/* Each round writes one chunk and lets the client read it. */
	for (rounds = 0; off < size && rounds <= size; rounds++) {
		size_t n = size - off < chunk ? size - off : chunk;
		ssize_t w = write(sv[1], data + off, n);
		if (w > 0)
			off += (size_t)w;
		if (rpc_service(rpc, POLLIN) < 0 || rpc_get_fd(rpc) == -1)
			goto out;
	}
	/* Server hangs up: exercises the EOF / partial-record path. */
	close(sv[1]);
	sv[1] = -1;
	rpc_service(rpc, POLLIN);

out:
	rpc_destroy_context(rpc); /* closes sv[0], cancels pending PDUs */
	if (sv[1] != -1)
		close(sv[1]);
	return 0;
}
