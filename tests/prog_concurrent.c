/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2026

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

/*
 * Issue many async reads at once and check that every one of them completes.
 *
 * This is a dialect independent test, but what it is really guarding is
 * NFSv4.2. There every COMPOUND travels in a session slot and a slot carries
 * one request at a time, so a client that does not track slots properly
 * either serialises everything or, worse, puts two requests on the same slot
 * and has the server answer NFS4ERR_SEQ_MISORDERED. The count here is
 * deliberately well above the number of slots a session is granted, so that
 * requests have to queue and wait for a slot rather than be rejected.
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libnfs.h"

struct cb_state {
        int outstanding;
        int errors;
        int completed;
};

void usage(void)
{
	fprintf(stderr, "Usage: prog_concurrent <url> <cwd> <path> "
                "<count> <size>\n");
	exit(1);
}

static void read_cb(int status, struct nfs_context *nfs, void *data,
                    void *private_data)
{
        struct cb_state *state = private_data;

        state->outstanding--;
        if (status < 0) {
                if (state->errors++ == 0) {
                        fprintf(stderr, "read failed: %s\n", (char *)data);
                }
                return;
        }
        state->completed++;
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs;
	struct nfsfh *nfsfh;
	struct nfs_url *url;
        struct cb_state state;
        char *buf;
        int i, count, size;

	if (argc != 6) {
		usage();
	}
        count = atoi(argv[4]);
        size = atoi(argv[5]);
        if (count < 1 || size < 1) {
                usage();
        }

	nfs = nfs_init_context();
	if (nfs == NULL) {
		printf("failed to init context\n");
		exit(1);
	}

	url = nfs_parse_url_full(nfs, argv[1]);
	if (url == NULL) {
		fprintf(stderr, "%s\n", nfs_get_error(nfs));
		exit(1);
	}

	if (nfs_mount(nfs, url->server, url->path) != 0) {
 		fprintf(stderr, "Failed to mount nfs share : %s\n",
			nfs_get_error(nfs));
		exit(1);
	}

	if (nfs_chdir(nfs, argv[2]) != 0) {
 		fprintf(stderr, "Failed to chdir to \"%s\" : %s\n",
			argv[2], nfs_get_error(nfs));
                exit(1);
	}

	if (nfs_open(nfs, argv[3], O_RDONLY, &nfsfh)) {
 		fprintf(stderr, "Failed to open file : %s\n",
			nfs_get_error(nfs));
		exit(1);
	}

        /*
         * One buffer for all of them. Nothing here checks the contents, only
         * that every read is answered.
         */
        buf = malloc(size);
        if (buf == NULL) {
 		fprintf(stderr, "Failed to allocate read buffer\n");
		exit(1);
        }

        memset(&state, 0, sizeof(state));

        printf("Issue %d reads of %d bytes without servicing in between\n",
               count, size);
        for (i = 0; i < count; i++) {
                if (nfs_pread_async(nfs, nfsfh, buf, size,
                                    (uint64_t)i * size, read_cb, &state)) {
                        fprintf(stderr, "Failed to queue read %d of %d: %s\n",
                                i, count, nfs_get_error(nfs));
                        exit(1);
                }
                state.outstanding++;
        }

        printf("Wait for all %d to complete\n", count);
        while (state.outstanding > 0) {
                struct pollfd pfd;

                pfd.fd = nfs_get_fd(nfs);
                pfd.events = nfs_which_events(nfs);
                pfd.revents = 0;
                if (poll(&pfd, 1, 10000) < 0) {
                        fprintf(stderr, "poll failed\n");
                        exit(1);
                }
                if (pfd.revents == 0) {
                        fprintf(stderr, "Timed out with %d reads still "
                                "outstanding\n", state.outstanding);
                        exit(1);
                }
                if (nfs_service(nfs, pfd.revents) < 0) {
                        fprintf(stderr, "nfs_service failed: %s\n",
                                nfs_get_error(nfs));
                        exit(1);
                }
        }

        if (state.errors) {
                fprintf(stderr, "%d of %d reads failed\n",
                        state.errors, count);
                exit(1);
        }
        if (state.completed != count) {
                fprintf(stderr, "Only %d of %d reads completed\n",
                        state.completed, count);
                exit(1);
        }
        printf("All %d reads completed\n", count);

        free(buf);
        nfs_close(nfs, nfsfh);
	nfs_destroy_url(url);
	nfs_destroy_context(nfs);

	return 0;
}
