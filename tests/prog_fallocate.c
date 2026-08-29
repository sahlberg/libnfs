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

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libnfs.h"

/*
 * Punch a hole in a file and check that the hole is really there: the file
 * keeps its size, the hole reads back as zeroes, and SEEK_HOLE and SEEK_DATA
 * find its edges.
 */
void usage(void)
{
	fprintf(stderr, "Usage: prog_fallocate <url> <cwd> <path> "
                "<offset> <length> <punch|zero>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs;
	struct nfsfh *nfsfh;
	struct nfs_url *url;
	struct nfs_stat_64 st;
        uint64_t offset, length, current, size_before;
        char *buf, *zero;
        const char *what;
        int i, punch;

	if (argc != 7) {
		usage();
	}
        offset = strtoull(argv[4], NULL, 10);
        length = strtoull(argv[5], NULL, 10);
        what = argv[6];
        if (!strcmp(what, "punch")) {
                punch = 1;
        } else if (!strcmp(what, "zero")) {
                punch = 0;
        } else {
                usage();
                return 1;
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

	if (nfs_open(nfs, argv[3], O_RDWR, &nfsfh)) {
 		fprintf(stderr, "Failed to open file : %s\n",
			nfs_get_error(nfs));
		exit(1);
	}

	if (nfs_fstat64(nfs, nfsfh, &st)) {
 		fprintf(stderr, "Failed to stat file : %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        size_before = st.nfs_size;

        printf("Check that an unsupported mode is rejected\n");
        /*
         * KEEP_SIZE on its own has no NFS equivalent: ALLOCATE always grows
         * the file when the range runs past the end.
         */
        if (nfs_fallocate(nfs, nfsfh, FALLOC_FL_KEEP_SIZE,
                          offset, length) == 0) {
 		fprintf(stderr, "fallocate accepted a mode it does not "
                        "implement\n");
		exit(1);
	}

        printf("Check that mode 0 reserves space without shrinking the file\n");
        if (nfs_fallocate(nfs, nfsfh, 0, offset, length)) {
 		fprintf(stderr, "fallocate(mode 0) failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}

        printf("Try fallocate(%s, %" PRIu64 ", %" PRIu64 ")\n",
               punch ? "PUNCH_HOLE|KEEP_SIZE" : "ZERO_RANGE", offset, length);
	if (nfs_fallocate(nfs, nfsfh,
                          punch ? (FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE)
                                : FALLOC_FL_ZERO_RANGE,
                          offset, length)) {
 		fprintf(stderr, "fallocate failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}

        printf("Check that the file size did not change\n");
	if (nfs_fstat64(nfs, nfsfh, &st)) {
 		fprintf(stderr, "Failed to stat file : %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (st.nfs_size != size_before) {
 		fprintf(stderr, "Punching a hole changed the file size. "
                        "Expected %" PRIu64 " but got %" PRIu64 "\n",
                        size_before, st.nfs_size);
		exit(1);
	}

        printf("Check that the hole reads back as zeroes\n");
        buf = malloc(length);
        zero = calloc(1, length);
        if (buf == NULL || zero == NULL) {
                fprintf(stderr, "Out of memory\n");
                exit(1);
        }
        memset(buf, 'x', length);
        if (nfs_pread(nfs, nfsfh, buf, length, offset) != (int)length) {
 		fprintf(stderr, "Failed to read back the hole : %s\n",
			nfs_get_error(nfs));
		exit(1);
        }
        for (i = 0; i < (int)length; i++) {
                if (buf[i] != 0) {
                        fprintf(stderr, "Hole is not zero at offset %d\n", i);
                        exit(1);
                }
        }

        if (!punch) {
                /*
                 * A zeroed range keeps its blocks, so there is no hole to
                 * find and SEEK_HOLE would run to the end of the file.
                 */
                free(buf);
                free(zero);
                nfs_close(nfs, nfsfh);
                nfs_destroy_url(url);
                nfs_destroy_context(nfs);
                return 0;
        }

        printf("Try lseek(SEEK_HOLE, 0)\n");
	if (nfs_lseek(nfs, nfsfh, 0, SEEK_HOLE, &current)) {
 		fprintf(stderr, "lseek(SEEK_HOLE) failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (current != offset) {
 		fprintf(stderr, "lseek(SEEK_HOLE) found the wrong offset. "
                        "Expected %" PRIu64 " but got %" PRIu64 "\n",
                        offset, current);
		exit(1);
	}

        printf("Try lseek(SEEK_DATA, %" PRIu64 ")\n", offset);
	if (nfs_lseek(nfs, nfsfh, offset, SEEK_DATA, &current)) {
 		fprintf(stderr, "lseek(SEEK_DATA) failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (current != offset + length) {
 		fprintf(stderr, "lseek(SEEK_DATA) found the wrong offset. "
                        "Expected %" PRIu64 " but got %" PRIu64 "\n",
                        offset + length, current);
		exit(1);
	}

	if (nfs_fstat64(nfs, nfsfh, &st)) {
 		fprintf(stderr, "Failed to stat file : %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (st.nfs_size != size_before) {
 		fprintf(stderr, "fallocate(mode 0) inside the file changed "
                        "its size. Expected %" PRIu64 " but got %" PRIu64 "\n",
                        size_before, st.nfs_size);
		exit(1);
	}

        free(buf);
        free(zero);
	nfs_close(nfs, nfsfh);
	nfs_destroy_url(url);
	nfs_destroy_context(nfs);

	return 0;
}
