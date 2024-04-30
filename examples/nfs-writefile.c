/*
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif


#ifdef WIN32
#include <win32/win32_compat.h>
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#else
#include <sys/stat.h>
#include <string.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"


#define MAX_CONCURRENCY 1024 /* keep up to 1024 writes in flight at a time */
#define WRITE_SIZE     65536 /* each write is this big */

struct write_file_context {
	int status; /*  0: still running,
		     *  1: finished successfully
		     * -1: finished with error.
		     */

	int fd;
	off_t offset;
	int eof;
	int num_in_flight;

	struct nfs_context *nfs;
	struct nfsfh *nfsfh;
	struct nfs_url *url;
};

struct write_data {
	struct write_file_context *ctx;
	off_t offset;
	char buf[0];
};

static void send_more_writes(struct write_file_context *ctx);

void usage(void)
{
	fprintf(stderr, "Usage: nfs-writefile <src> <dst>\n");
	fprintf(stderr, "<src> is a local file, <dst> is an nfs URL.\n");
	exit(0);
}

static void
free_write_file_context(struct write_file_context *ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->fd != -1) {
		close(ctx->fd);
	}
	if (ctx->nfsfh != NULL) {
		nfs_close(ctx->nfs, ctx->nfsfh);
	}
	if (ctx->nfs != NULL) {
		nfs_destroy_context(ctx->nfs);
	}
	nfs_destroy_url(ctx->url);
	free(ctx);
}

void
nfs_write_cb(int status, struct nfs_context *nfs, void *data,
	     void *private_data)
{
	struct write_data *wdata = private_data;
	struct write_file_context *ctx = wdata->ctx;

	free(wdata);

	if (status < 0) {
		printf("write call failed with \"%s\"\n", (char *)data);
		ctx->status = -1;
		return;
	}
	ctx->num_in_flight--;
	/*
	 * Since this write completed, see if we can send more writes
	 * to the server
	 */
	send_more_writes(ctx);
	if (ctx->num_in_flight == 0) {
		/* We couldn't queue any more writes. That means we must be
		 * done and there is nothing more to do.
		 */
		ctx->status = 1;
	}
}


static void
send_more_writes(struct write_file_context *ctx)
{
	struct write_data *wdata;
	int ret;

	if (ctx->eof) {
		return;
	}
	while (ctx->num_in_flight < MAX_CONCURRENCY) {
		/*
		 * We need to allocate a buffer for the write as
		 * the async write interface is zero-copy, thus we
		 * must leave the buffer untouched until we know that the
		 * buffer has been written to the wire.
		 * We know this implicitely when we receive a reply
		 * for this async write.
		 */
		wdata = malloc(sizeof(struct write_data) + WRITE_SIZE);
		if (wdata == NULL) {
			printf("Failed to allocate write_data structure\n");
			ctx->status = -1;
			return;
		}
		wdata->ctx = ctx;
		wdata->offset = ctx->offset;
		ret = read(ctx->fd, &wdata->buf[0], WRITE_SIZE);
		if (ret == 0) {
			ctx->eof = 1;
			free(wdata);
			return;
		}
		if (ret < 0) {
			printf("Read returned error\n");
			ctx->status = -1;
			return;
		}
		if (nfs_pwrite_async(ctx->nfs, ctx->nfsfh,
				     wdata->buf, ret, wdata->offset,
				     nfs_write_cb, wdata) != 0) {
			printf("Failed to start async nfs pwrite\n");
			free(wdata);
			ctx->status = -1;
			return;
		}

		ctx->offset += ret;
		/* Bump the number of commands we have in flight */
		ctx->num_in_flight++;
	}
}


void
nfs_creat_cb(int status, struct nfs_context *nfs, void *data,
	     void *private_data)
{
	struct write_file_context *ctx = private_data;

	if (status < 0) {
		printf("open call failed with \"%s\"\n", (char *)data);
		ctx->status = -1;
		return;
	}

	ctx->nfsfh = data;
	printf("File created\n");
        send_more_writes(ctx);
}


void
nfs_mount_cb(int status, struct nfs_context *nfs, void *data,
	     void *private_data)
{
	struct write_file_context *ctx = private_data;

	if (status < 0) {
		printf("mount/mnt call failed with \"%s\"\n", (char *)data);
		ctx->status = -1;
		return;
	}

	printf("Got reply from server for MOUNT/MNT procedure.\n");
	printf("Opening %s for writing\n", ctx->url->file);
	if (nfs_creat_async(ctx->nfs, ctx->url->file, 0666,
			    nfs_creat_cb, ctx) != 0) {
		printf("Failed to start async nfs creat\n");
		ctx->status = -1;
		return;
	}
}



int main(int argc, char *argv[])
{
	struct write_file_context *ctx = NULL;
	int ret;

#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		return 10;
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

	if (argc != 3) {
		usage();
	}

	ctx = malloc(sizeof(struct write_file_context));
	if (ctx == NULL) {
		fprintf(stderr, "Failed to allocate write-file context\n");
		exit(10);
	}
	memset(ctx, 0, sizeof(struct write_file_context));

	ctx->fd = open(argv[1], O_RDONLY);
	if (ctx->fd == -1) {
		fprintf(stderr, "Failed to open %s\n", argv[1]);
		return 10;
	}

	ctx->nfs = nfs_init_context();
	if (ctx->nfs == NULL) {
		printf("failed to init context\n");
		free_write_file_context(ctx);
		exit(10);
	}

	/* Increase the number of hash buckets for XID replies
	 * so that we can get good performance and low xid overhead
	 * even if we dial the concurrency really high.
	 */
	nfs_set_hash_size(ctx->nfs, MAX_CONCURRENCY / 100 + 10);

	ctx->url = nfs_parse_url_full(ctx->nfs, argv[2]);
	if (ctx->url == NULL) {
		printf("failed to parse url: %s: %s\n",
			argv[2], nfs_get_error(ctx->nfs));
		free_write_file_context(ctx);
		exit(10);
	}

	if (nfs_mount_async(ctx->nfs, ctx->url->server, ctx->url->path,
			    nfs_mount_cb, ctx)) {
		printf("failed to setup async mount command\n");
		free_write_file_context(ctx);
		exit(10);
	}


	/*
	 * We now have a context and we have queued up a chain of async
	 * events to mount the stare.
	 * At this point we can now run our own simple event loop
	 * to drive all I/O until we are complete.
	 * (For non-trivial applications we would rather just plug
	 *  libnfs into the existing event loop.)
	 */

	/*
	 * Run the event loop until it either completes successfully
	 * or fails.
	 */
	while (ctx->status == 0) {
		struct pollfd pfds[1]; /* nfs:0 */

		pfds[0].fd = nfs_get_fd(ctx->nfs);
		pfds[0].events = nfs_which_events(ctx->nfs);

		if (poll(&pfds[0], 1, nfs_get_poll_timeout(ctx->nfs)) < 0) {
			printf("Poll failed");
			break;
		}
		if (nfs_service(ctx->nfs, pfds[0].revents) < 0) {
			printf("nfs_service failed\n");
			break;
		}
	}


	if (ctx->status > 0) {
		printf("Finished successfully\n");
	}
	if (ctx->status < 0) {
		printf("Failed\n");
	}

	ret = (ctx->status > 0) ? 0 : -1;

	free_write_file_context(ctx);
	return ret;
}
