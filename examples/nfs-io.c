/* 
   Copyright (C) by Peter Lieven <pl@kamp.de> 2013
   
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
#include "win32_compat.h"
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#define PRId64 "ll"
#else
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#ifndef AROS
#include <sys/statvfs.h>
#endif
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"

void print_usage(void)
{
	fprintf(stderr, "Usage: nfs-io [-?|--help|--usage] [stat|creat|unlink|mkdir|rmdir] <url>\n");
}

int main(int argc, char *argv[])
{
	int ret = 1;
	struct nfs_context *nfs = NULL;
	struct nfsfh *nfsfh = NULL;
	struct nfs_url *url = NULL;

#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		exit(10);
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

	if (argc < 3) {
		fprintf(stderr, "No URL specified.\n");
		goto finished;
	}

	nfs = nfs_init_context();
	if (nfs == NULL) {
		printf("failed to init context\n");
		goto finished;
	}

	url = nfs_parse_url_full(nfs, argv[argc - 1]);
	if (url == NULL) {
		fprintf(stderr, "%s\n", nfs_get_error(nfs));
		goto finished;
	}

	if (nfs_mount(nfs, url->server, url->path) != 0) {
 		fprintf(stderr, "Failed to mount nfs share : %s\n", nfs_get_error(nfs));
		goto finished;
	}

	if (!strncmp(argv[1], "creat", 5)) {
		ret = nfs_creat(nfs, url->file, 0600, &nfsfh);
	} else if (!strncmp(argv[1], "unlink", 6)) {
		ret = nfs_unlink(nfs, url->file);
	} else if (!strncmp(argv[1], "mkdir", 5)) {
		ret = nfs_mkdir(nfs, url->file);
	} else if (!strncmp(argv[1], "rmdir", 5)) {
		ret = nfs_rmdir(nfs, url->file);
	} else if (!strncmp(argv[1], "stat", 4)) {
		struct nfs_stat_64 st;
		ret = nfs_stat64(nfs, url->file, &st);
		if (!ret) {
			switch (st.nfs_mode & S_IFMT) {
	#ifndef WIN32
			case S_IFLNK:
				printf("l");
				break;
	#endif
			case S_IFREG:
				printf("-");
				break;
			case S_IFDIR:
				printf("d");
				break;
			case S_IFCHR:
				printf("c");
				break;
			case S_IFBLK:
				printf("b");
				break;
			}
			printf("%c%c%c",
			       "-r"[!!(st.nfs_mode & S_IRUSR)],
			       "-w"[!!(st.nfs_mode & S_IWUSR)],
			       "-x"[!!(st.nfs_mode & S_IXUSR)]
			);
			printf("%c%c%c",
			       "-r"[!!(st.nfs_mode & S_IRGRP)],
			       "-w"[!!(st.nfs_mode & S_IWGRP)],
			       "-x"[!!(st.nfs_mode & S_IXGRP)]
			);
			printf("%c%c%c",
			       "-r"[!!(st.nfs_mode & S_IROTH)],
			       "-w"[!!(st.nfs_mode & S_IWOTH)],
			       "-x"[!!(st.nfs_mode & S_IXOTH)]
			);
			printf(" %2d", (int)st.nfs_nlink);
			printf(" %5d", (int)st.nfs_uid);
			printf(" %5d", (int)st.nfs_gid);
			printf(" %12" PRId64, st.nfs_size);
			printf("\n");
		}
	} else {
		goto finished;
	}
	
	if (ret) {
		fprintf(stderr, "ERROR: %s\n", nfs_get_error(nfs));
	}

finished:
	if (ret > 0) {
		print_usage();
	}
	nfs_destroy_url(url);
	if (nfs != NULL) {		
		if (nfsfh) {
			nfs_close(nfs, nfsfh);
		}
		nfs_destroy_context(nfs);
	}
	return !!ret;
}

