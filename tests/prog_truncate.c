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
#include <sys/types.h>

#include "libnfs.h"

void usage(void)
{
	fprintf(stderr, "Usage: prog_truncate <url> <cwd> <path> <offset>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs;
	struct nfs_url *url;
        uint64_t length;
	struct nfs_stat_64 st;

	if (argc != 5) {
		usage();
	}

        length = strtol(argv[4], NULL, 10);

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

	if (nfs_truncate(nfs, argv[3], length)) {
 		fprintf(stderr, "Failed to truncate file : %s\n",
			nfs_get_error(nfs));
		exit(1);
	}

	if (nfs_stat64(nfs, argv[3], &st)) {
 		fprintf(stderr, "Failed to stat file : %s\n",
			nfs_get_error(nfs));
                exit(1);
	}

        if (st.nfs_size != length) {
 		fprintf(stderr, "Unexpected file size. Expected %d got %d\n",
                        (int)length, (int)st.nfs_size);
                exit(1);
        }
        
	nfs_destroy_url(url);
	nfs_destroy_context(nfs);

	return 0;
}
