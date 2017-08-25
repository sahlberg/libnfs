/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2017
   
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

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libnfs.h"

void usage(void)
{
	fprintf(stderr, "Usage: prog_lseek <url> <cwd> <path>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs;
	struct nfsfh *nfsfh;
	struct nfs_url *url;
	struct nfs_stat_64 st;
        uint64_t current;

	if (argc != 4) {
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

	if (nfs_fstat64(nfs, nfsfh, &st)) {
 		fprintf(stderr, "Failed to stat file : %s\n",
			nfs_get_error(nfs));
		exit(1);
	}

	printf("File size:%" PRIu64 "\n", st.nfs_size);

        printf("Try lseek(SEEK_SET, 512)\n");
	if (nfs_lseek(nfs, nfsfh, 512, SEEK_SET, &current)) {
 		fprintf(stderr, "lseek failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (current != 512) {
 		fprintf(stderr, "lseek returned wrong current offset."
                        "Expected %d but got %" PRIu64 "\n", 512, current);
		exit(1);
	}

        printf("Try lseek(SEEK_CUR, 0)\n");
	if (nfs_lseek(nfs, nfsfh, 0, SEEK_CUR, &current)) {
 		fprintf(stderr, "lseek failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (current != 512) {
 		fprintf(stderr, "lseek returned wrong current offset."
                        "Expected %d but got %" PRIu64 "\n", 512, current);
		exit(1);
	}

        printf("Try lseek(SEEK_CUR, 4)\n");
	if (nfs_lseek(nfs, nfsfh, 4, SEEK_CUR, &current)) {
 		fprintf(stderr, "lseek failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (current != 516) {
 		fprintf(stderr, "lseek returned wrong current offset."
                        "Expected %d but got %" PRIu64 "\n", 516, current);
		exit(1);
	}

        printf("Try lseek(SEEK_CUR, -16)\n");
	if (nfs_lseek(nfs, nfsfh, -16, SEEK_CUR, &current)) {
 		fprintf(stderr, "lseek failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (current != 500) {
 		fprintf(stderr, "lseek returned wrong current offset."
                        "Expected %d but got %" PRIu64 "\n", 500, current);
		exit(1);
	}

        printf("Try lseek(SEEK_CUR, -500)\n");
	if (nfs_lseek(nfs, nfsfh, -500, SEEK_CUR, &current)) {
 		fprintf(stderr, "lseek failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (current != 0) {
 		fprintf(stderr, "lseek returned wrong current offset."
                        "Expected %d but got %" PRIu64 "\n", 0, current);
		exit(1);
	}

        printf("Try lseek(SEEK_CUR, -1)\n");
	if (nfs_lseek(nfs, nfsfh, -1, SEEK_CUR, &current) >= 0) {
                fprintf(stderr, "lseek should have failed.\n");
		exit(1);
	}
        if (current != 0) {
 		fprintf(stderr, "lseek returned wrong current offset."
                        "Expected %d but got %" PRIu64 "\n", 0, current);
		exit(1);
	}
        
        printf("Try lseek(SEEK_END, -500)\n");
	if (nfs_lseek(nfs, nfsfh, -500, SEEK_END, &current)) {
 		fprintf(stderr, "lseek failed: %s\n",
			nfs_get_error(nfs));
		exit(1);
	}
        if (current != st.nfs_size - 500) {
 		fprintf(stderr, "lseek returned wrong current offset."
                        "Expected %" PRIu64 " but got %" PRIu64 "\n",
                        st.nfs_size - 500, current);
		exit(1);
	}

	nfs_destroy_url(url);
	nfs_close(nfs, nfsfh);
	nfs_destroy_context(nfs);

	return 0;
}
