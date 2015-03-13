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
#ifndef AROS
#ifdef ANDROID
#define statvfs statfs
#include <sys/vfs.h>
#else
#include <sys/statvfs.h>
#endif
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

struct client {
       char *server;
       char *export;
       uint32_t mount_port;
       int is_finished;
};

int recursive = 0, summary = 0, discovery = 0;

void print_usage(void)
{
	fprintf(stderr, "Usage: nfs-ls [-?|--help|--usage] [-R|--recursive] [-s|--summary] [-D|--discovery] <url>\n");
}

int process_server(const char *server) {
	struct exportnode *exports;
	struct exportnode *export;

	exports = mount_getexports(server);
	if (exports == NULL) {
		fprintf(stderr, "Failed to get exports for server %s.\n", server);
		return -1;
	}
	for (export=exports; export; export = export->ex_next) {
		printf("nfs://%s%s\n", server, export->ex_dir);
	}
	mount_free_export_list(exports);
	return 0;
}

void process_dir(struct nfs_context *nfs, char *dir, int level) {
	int ret;
	struct nfsdirent *nfsdirent;
	struct nfsdir *nfsdir;

	if (!level) {
		printf("Recursion detected!\n");
		exit(10);
	}

	ret = nfs_opendir(nfs, dir, &nfsdir);
	if (ret != 0) {
		printf("Failed to opendir(\"%s\") %s\n", dir, nfs_get_error(nfs));
		exit(10);
	}
	while((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
		char path[1024];

		if (!strcmp(nfsdirent->name, ".") || !strcmp(nfsdirent->name, "..")) {
			continue;
		}
		snprintf(path, 1024, "%s/%s", dir, nfsdirent->name);

		switch (nfsdirent->mode & S_IFMT) {
		case S_IFLNK:
			printf("l");
			break;
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
			"-r"[!!(nfsdirent->mode & S_IRUSR)],
			"-w"[!!(nfsdirent->mode & S_IWUSR)],
			"-x"[!!(nfsdirent->mode & S_IXUSR)]
		);
		printf("%c%c%c",
			"-r"[!!(nfsdirent->mode & S_IRGRP)],
			"-w"[!!(nfsdirent->mode & S_IWGRP)],
			"-x"[!!(nfsdirent->mode & S_IXGRP)]
		);
		printf("%c%c%c",
			"-r"[!!(nfsdirent->mode & S_IROTH)],
			"-w"[!!(nfsdirent->mode & S_IWOTH)],
			"-x"[!!(nfsdirent->mode & S_IXOTH)]
		);
		printf(" %2d", (int)nfsdirent->nlink);
		printf(" %5d", (int)nfsdirent->uid);
		printf(" %5d", (int)nfsdirent->gid);
		printf(" %12" PRId64, nfsdirent->size);

		printf(" %s\n", path + 1);

		if (recursive && (nfsdirent->mode & S_IFMT) == S_IFDIR) {
			process_dir(nfs, path, level - 1);
		}
	}
	nfs_closedir(nfs, nfsdir);
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs = NULL;
	int i, ret = 1;
	struct client client;
	struct statvfs stvfs;
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

	if (argc < 2) {
		fprintf(stderr, "No URL specified.\n");
		goto finished;
	}

	for (i=1; i < argc -1; i++) {
		if (!strcmp(argv[i], "-R") || !strcmp(argv[i], "--recursive")) {
			recursive++;
		} else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--summary")) {
			summary++;
		} else if (!strcmp(argv[i], "-D") || !strcmp(argv[i], "--discovery")) {
			discovery++;
		} else{
			goto finished;
		}
	}

	nfs = nfs_init_context();
	if (nfs == NULL) {
		printf("failed to init context\n");
		goto finished;
	}

	if (discovery) {
		url = nfs_parse_url_incomplete(nfs, argv[argc - 1]);
		if (url == NULL) {
			fprintf(stderr, "%s\n", nfs_get_error(nfs));
			goto finished;
		}
		if (!url->server) {
			struct nfs_server_list *srvrs;
			struct nfs_server_list *srv;

			srvrs = nfs_find_local_servers();
			if (srvrs == NULL) {
				fprintf(stderr, "Failed to find local servers.\n");
				goto finished;
			}
			for (srv=srvrs; srv; srv = srv->next) {
				if (recursive) {
					process_server(srv->addr);
				} else {
					printf("nfs://%s\n", srv->addr);
				}
			}
			free_nfs_srvr_list(srvrs);
			ret = 0;
			goto finished;
		}
		if (url->server && !url->path) {
			ret = process_server(url->server);
			goto finished;
		}
		nfs_destroy_url(url);
	}

	url = nfs_parse_url_dir(nfs, argv[argc - 1]);
	if (url == NULL) {
		fprintf(stderr, "%s\n", nfs_get_error(nfs));
		goto finished;
	}

	client.server = url->server;
	client.export = url->path;
	client.is_finished = 0;

	if ((ret = nfs_mount(nfs, client.server, client.export)) != 0) {
 		fprintf(stderr, "Failed to mount nfs share : %s\n", nfs_get_error(nfs));
		goto finished;
	}

	process_dir(nfs, "", 16);

	if (summary) {
		if (nfs_statvfs(nfs, "", &stvfs) != 0) {
			goto finished;
		}
		printf("\n%12" PRId64 " of %12" PRId64 " bytes free.\n",
		       stvfs.f_frsize * stvfs.f_bfree, stvfs.f_frsize * stvfs.f_blocks);
	}

	ret = 0;
finished:
	if (ret > 0) {
		print_usage();
	}
	nfs_destroy_url(url);
	if (nfs != NULL) {
		nfs_destroy_context(nfs);
	}
	return ret;
}
