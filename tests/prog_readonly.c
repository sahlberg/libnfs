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

#include <errno.h>
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
	fprintf(stderr, "Usage: prog_readonly>"
                "\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs = NULL;
	struct nfs_url *url = NULL;
        struct nfsfh *nfsfh;
	int ret = 0;

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

        /* These should all fail since the directory is readonly */
	if (nfs_mkdir(nfs, "testdir") != -EROFS) {
 		fprintf(stderr, "Succeeded to mkdir \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_rmdir(nfs, "testdir") != -EROFS) {
 		fprintf(stderr, "Succeeded to rmdir \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_open(nfs, "testfile", O_CREAT, &nfsfh) != -EROFS) {
 		fprintf(stderr, "Succeeded to open(O_TRUNC) \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_open(nfs, "testfile", O_WRONLY, &nfsfh) != -EROFS) {
 		fprintf(stderr, "Succeeded to open(O_WRONLY) \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_open(nfs, "testfile", O_RDWR, &nfsfh) != -EROFS) {
 		fprintf(stderr, "Succeeded to open(O_RDWR) \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_open(nfs, "testfile", O_APPEND, &nfsfh) != -EROFS) {
 		fprintf(stderr, "Succeeded to open(O_APPEND) \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_open(nfs, "testfile", O_CREAT, &nfsfh) != -EROFS) {
 		fprintf(stderr, "Succeeded to open(O_CREAT) \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_truncate(nfs, "testdir", 0) != -EROFS) {
 		fprintf(stderr, "Succeeded to truncate \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_creat(nfs, "testfile", 0666, &nfsfh) != -EROFS) {
 		fprintf(stderr, "Succeeded to creat() \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
	if (nfs_unlink(nfs, "testfile") != -EROFS) {
 		fprintf(stderr, "Succeeded to unlink() \"%s\"\n",
			"testdir");
		ret = 1;
		goto finished;
	}
        
finished:
	nfs_destroy_url(url);
	nfs_destroy_context(nfs);

	return ret;
}
