/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2018
   
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
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-nfs.h"

void usage(void)
{
	fprintf(stderr, "Usage: nfs-fh <url>\n");
	fprintf(stderr, "\tPrints the NFS filehandle for a URL.\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int i;
	int ret = 0;
	struct nfs_context *nfs = NULL;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_url *url = NULL;
	
#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		return 1;
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

	if (argc < 2) {
		usage();
	}

	nfs = nfs_init_context();
	if (nfs == NULL) {
		fprintf(stderr, "failed to init context\n");
		goto finished;
	}

	url = nfs_parse_url_full(nfs, argv[1]);
	if (url == NULL) {
		fprintf(stderr, "%s\n", nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}

	if (nfs_mount(nfs, url->server, url->path) != 0) {
		fprintf(stderr, "Failed to mount nfs share : %s\n",
			       nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}
	
	if (nfs_open(nfs, url->file, O_RDONLY, &nfsfh) != 0) {
		fprintf(stderr, "Failed to open file %s: %s\n",
			url->file, nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}

	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	for (i = 0; i < fh3->data.data_len; i++) {
	  printf("%02x", (unsigned char)(fh3->data.data_val[i]));
	}
	printf("\n");

 finished:
	if (nfsfh) {
		nfs_close(nfs, nfsfh);
	}
	if (url) {
		nfs_destroy_url(url);
	}
	if (nfs) {
		nfs_destroy_context(nfs);
	}

	return ret;
}
