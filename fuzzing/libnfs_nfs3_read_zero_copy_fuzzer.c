// Copyright 2026 Kun-Wei Wu
// SPDX-License-Identifier: LGPL-2.1-or-later

// Fuzzes the libnfs zero-copy NFSv3 READ reply path. A client rpc_context
// is attached to one end of a socketpair and sends one READ with
// rpc_nfs3_readv_task(), which makes libnfs place the reply data straight
// into the caller's iovecs. The fuzz input is then written to the other
// end as the server's reply. rpc_read_from_socket() reads at most ZCRP
// bytes of the first record, decodes the RPC header and READ3res with
// zdr_READ3res_zero_copy, copies the buffered data into the iovecs, then
// readv()s the rest into them (READ_IOVEC) and drains the XDR padding
// (READ_PADDING). Fragmented records take the reassembly branch instead.
//
// Input layout:
//   data[0]     number of iovecs - 1 (low 2 bits: 1..4 iovecs)
//   data[1..2]  write chunk size, big endian, 0 = write everything at once;
//               small chunks make recv()/readv() return at odd boundaries
//   data[3..6]  iovec i length = 1 + data[3+i] * 16 (1..4081 bytes each)
//   data[7:]    raw TCP stream from the "server": record marker(s), then
//               the RPC reply starting with XID 0x11223344
//
// Internal state preset: rpc->program / rpc->version (see the comment at
// the assignment). Everything else goes through the public API.

/* glibc needs this for caddr_t in the system headers */
#ifndef __APPLE__
#define _GNU_SOURCE
#endif

/* libnfs-private.h needs config.h to get the library's struct layout */
#include "config.h"

#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-private.h" /* struct rpc_context, for program/version */

#define FIXED_XID 0x11223344
#define HDR 7
#define MAX_IOV 4
/* Stay well below the socketpair buffer so writes never block for long. */
#define MAX_STREAM (32 * 1024)

static void dummy_cb(struct rpc_context *rpc, int status, void *data,
                     void *private_data)
{
	(void)rpc; (void)status; (void)data; (void)private_data;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char fh_data[] = "fuzzfh00";
	struct rpc_context *rpc;
	struct iovec iov[MAX_IOV];
	READ3args args;
	int sv[2], i, niov;
	char junk[4096];
	size_t chunk, total = 0, off = 0, rounds;

	if (size < HDR || size > MAX_STREAM + HDR)
		return 0;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 0;
	fcntl(sv[0], F_SETFL, O_NONBLOCK);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);

	/* Each iovec is its own allocation so ASan sees any overrun. */
	niov = 1 + (data[0] & 3);
	for (i = 0; i < niov; i++) {
		iov[i].iov_len = 1 + (size_t)data[3 + i] * 16;
		iov[i].iov_base = malloc(iov[i].iov_len);
		total += iov[i].iov_len;
	}
	chunk = ((size_t)data[1] << 8) | data[2];

	rpc = rpc_init_context();
	if (rpc == NULL) {
		close(sv[0]);
		goto free_iov;
	}
	/*
	 * Allow one reconnect, as libnfs does for NFS mounts (nfs_v3.c). On a
	 * broken stream the half-read PDU is requeued, the reconnect fails at
	 * once because the context has no server address, and every PDU is
	 * completed with an error and freed.
	 */
	rpc_set_resiliency(rpc, 1, 60 * 1000, 0);
	/*
	 * PRESET: rpc->program / rpc->version. A real client gets these from
	 * rpc_connect_program_async(), which needs a server. rpc_set_fd()
	 * leaves them 0, and socket.c then skips the READ3res status check
	 * and treats error replies as data. tests/prog_nfs3_read_reply.c
	 * does the same.
	 */
	rpc->program = NFS_PROGRAM;
	rpc->version = NFS_V3;
	rpc_set_fd(rpc, sv[0]); /* owned by rpc from now on */
	/* First POLLOUT on an unconnected fd = "connect finished". */
	rpc_service(rpc, POLLOUT);

	rpc_set_next_xid(rpc, FIXED_XID);
	/* A real caller asks for exactly as many bytes as its buffers hold. */
	memset(&args, 0, sizeof(args));
	args.file.data.data_len = sizeof(fh_data) - 1;
	args.file.data.data_val = fh_data;
	args.offset = 0;
	args.count = (count3)total;
	if (rpc_nfs3_readv_task(rpc, dummy_cb, iov, niov, &args, NULL) == NULL)
		goto out;
	rpc_service(rpc, POLLOUT);
	while (read(sv[1], junk, sizeof(junk)) > 0)
		; /* discard the CALL the client sent */

	data += HDR;
	size -= HDR;
	if (chunk == 0)
		chunk = size;
	/* Each round writes one chunk and lets the client read it. */
	for (rounds = 0; off < size && rounds <= size; rounds++) {
		size_t n = size - off < chunk ? size - off : chunk;
		ssize_t w = write(sv[1], data + off, n);
		if (w > 0)
			off += (size_t)w;
		if (rpc_service(rpc, POLLIN) < 0 || rpc_get_fd(rpc) == -1)
			goto out;
	}
	/* Server hangs up: exercises EOF in the middle of iovec/padding. */
	close(sv[1]);
	sv[1] = -1;
	rpc_service(rpc, POLLIN);

out:
	rpc_destroy_context(rpc); /* closes sv[0], cancels pending PDUs */
free_iov:
	if (sv[1] != -1)
		close(sv[1]);
	for (i = 0; i < niov; i++)
		free(iov[i].iov_base);
	return 0;
}
