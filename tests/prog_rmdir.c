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
#include <unistd.h>

#include "libnfs.h"

void usage(void)
{
	fprintf(stderr, "Usage: prog_rmdir <url> <cwd> <path>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs = NULL;
	struct nfs_url *url = NULL;
	int ret = 0;

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
		ret = 1;
		goto finished;
	}

	if (nfs_chdir(nfs, argv[2]) != 0) {
 		fprintf(stderr, "Failed to chdir to \"%s\" : %s\n",
			argv[2], nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}
        
	if (nfs_rmdir(nfs, argv[3])) {
 		fprintf(stderr, "Failed to rmdir: %s\n",
			nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}
        
finished:
	nfs_destroy_url(url);
	nfs_destroy_context(nfs);

	return ret;
}
