/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2023
   
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
#include <unistd.h>

#include "libnfs.h"

void usage(void)
{
	fprintf(stderr, "Usage: prog_write_update_pos <url> <file>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs = NULL;
	struct nfs_url *url = NULL;
	int ret = 0;
        struct nfsfh *fh;
        uint64_t pos;
        char buf[1024];
        struct nfs_stat_64 st;

	if (argc != 2) {
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
		ret = 1;
		goto finished;
	}

	if (nfs_open(nfs, url->file, O_RDONLY, &fh)) {
 		fprintf(stderr, "Failed to open(): %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}

	if (nfs_fstat64(nfs, fh, &st)) {
 		fprintf(stderr, "Failed to fstat64(): %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}
        if (nfs_lseek(nfs, fh, -3, SEEK_END, &pos) < 0) {
 		fprintf(stderr, "Failed to lseek(): %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}
        if (pos != st.nfs_size - 3) {
 		fprintf(stderr, "lseek() returned wrong pos\n");
		ret = 1;
		goto finished;
        }

        if (nfs_pread(nfs, fh, buf, 1, st.nfs_size - 3) != 1) {
 		fprintf(stderr, "pread() failed to read 1 byte: %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
        }
        /* offset should not change after pread() */
        if (nfs_lseek(nfs, fh, 0, SEEK_CUR, &pos) < 0) {
 		fprintf(stderr, "Failed to lseek(): %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}
        if (pos != st.nfs_size - 3) {
 		fprintf(stderr, "offset changed after pread()\n");
		ret = 1;
		goto finished;
        }

        if (nfs_read(nfs, fh, buf, 1) != 1) {
 		fprintf(stderr, "read() failed to read 1 byte: %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
        }
        /* offset should change after read() */
        if (nfs_lseek(nfs, fh, 0, SEEK_CUR, &pos) < 0) {
 		fprintf(stderr, "Failed to lseek(): %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}
        if (pos == st.nfs_size - 3) {
 		fprintf(stderr, "offset did not change after read()\n");
		ret = 1;
		goto finished;
        }
        if (pos != st.nfs_size - 2) {
 		fprintf(stderr, "offset changed to wrong value after read()\n");
		ret = 1;
		goto finished;
        }
        
	if (nfs_close(nfs, fh)) {
 		fprintf(stderr, "Failed to close(): %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}
        
finished:
	nfs_destroy_url(url);
	nfs_destroy_context(nfs);

	return ret;
}
