/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2010
   
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
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"

struct client {
       char *server;
       char *export;
       uint32_t mount_port;
       int is_finished;
};

	int recursive = 0, summary = 0;

void print_usage(void)
{
	fprintf(stderr, "Usage: nfs-ls [-?|--help|--usage] [-R|--recursive] [-s|--summary] <url>\n");
}

void process_dir(struct nfs_context *nfs, char *dir, int level) {
	int ret;
	struct nfsdirent *nfsdirent;
	struct statvfs svfs;
	struct nfsdir *nfsdir;
	struct stat st;
	
	if (!level) {
		printf("Recursion detected!\n");
		exit(10);
	}
	
	ret = nfs_opendir(nfs, dir, &nfsdir);
	if (ret != 0) {
		printf("Failed to opendir(\"%s\")\n", dir, nfs_get_error(nfs));
		exit(10);
	}
	while((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
		char path[1024];

		if (!strcmp(nfsdirent->name, ".") || !strcmp(nfsdirent->name, "..")) {
			continue;
		}

		snprintf(path, 1024, "%s/%s", dir, nfsdirent->name);
		ret = nfs_stat(nfs, path, &st);
		if (ret != 0) {
			fprintf(stderr, "Failed to stat(%s) %s\n", path, nfs_get_error(nfs));
			continue;
		}

		switch (st.st_mode & S_IFMT) {
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
			"-r"[!!(st.st_mode & S_IRUSR)],
			"-w"[!!(st.st_mode & S_IWUSR)],
			"-x"[!!(st.st_mode & S_IXUSR)]
		);
		printf("%c%c%c",
			"-r"[!!(st.st_mode & S_IRGRP)],
			"-w"[!!(st.st_mode & S_IWGRP)],
			"-x"[!!(st.st_mode & S_IXGRP)]
		);
		printf("%c%c%c",
			"-r"[!!(st.st_mode & S_IROTH)],
			"-w"[!!(st.st_mode & S_IWOTH)],
			"-x"[!!(st.st_mode & S_IXOTH)]
		);
		printf(" %2d", (int) st.st_nlink);
		printf(" %5d", st.st_uid);
		printf(" %5d", st.st_gid);
		printf(" %12" PRId64, st.st_size);

		printf(" %s\n", path + 1);
		
		if (recursive && (st.st_mode & S_IFMT) == S_IFDIR) {
			process_dir(nfs, path, level - 1);
		}
	}
	nfs_closedir(nfs, nfsdir);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs = NULL;
	int i, ret, res;
	uint64_t offset;
	struct client client;
	struct nfsfh  *nfsfh;
	struct statvfs stvfs;
	exports export, tmp;
	const char *url = NULL;
	char *server = NULL, *path = NULL, *strp;

#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		exit(10);
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

	url = argv[argc - 1];

	if (url == NULL) {
		fprintf(stderr, "No URL specified.\n");
		print_usage();
		exit(10);
	}

	for (i=1; i < argc -1; i++) {
		if (!strcmp(argv[i], "-R") || !strcmp(argv[i], "--recursive")) {
			recursive++;
		} else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--summary")) {
			summary++;
		} else {
			print_usage();
			exit(10);
		}
	}

	if (strncmp(url, "nfs://", 6)) {
		fprintf(stderr, "Invalid URL specified.\n");
		print_usage();
		exit(10);
	}

	server = strdup(url + 6);
	if (server == NULL) {
		fprintf(stderr, "Failed to strdup server string\n");
		exit(10);
	}
	if (server[0] == '/' || server[0] == '\0') {
		fprintf(stderr, "Invalid server string.\n");
		free(server);
		exit(10);
	}
	strp = strchr(server, '/');
	if (strp == NULL) {
		fprintf(stderr, "Invalid URL specified.\n");
		print_usage();
		free(server);
		exit(10);
	}
	path = strdup(strp);
	if (path == NULL) {
		fprintf(stderr, "Failed to strdup server string\n");
		free(server);
		exit(10);
	}
	if (path[0] != '/') {
		fprintf(stderr, "Invalid path.\n");
		free(server);
		free(path);
		exit(10);
	}
	*strp = 0;

	client.server = server;
	client.export = path;
	client.is_finished = 0;

	nfs = nfs_init_context();
	if (nfs == NULL) {
		printf("failed to init context\n");
		goto finished;
	}

	ret = nfs_mount(nfs, client.server, client.export);
	if (ret != 0) {
 		printf("Failed to mount nfs share : %s\n", nfs_get_error(nfs));
		goto finished;
	}

	process_dir(nfs, "", 16);

	if (summary) {
		ret = nfs_statvfs(nfs, "/", &stvfs);
		if (ret != 0) {
			goto finished;
		}
		printf("\n%12" PRId64 " of %12" PRId64 " bytes free.\n",
		       stvfs.f_frsize * stvfs.f_bfree, stvfs.f_frsize * stvfs.f_blocks);
	}
finished:
	free(server);
	free(path);
	if (nfs != NULL) {		
		nfs_destroy_context(nfs);
	}
	return 0;
}

