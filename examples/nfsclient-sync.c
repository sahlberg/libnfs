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

/* Example program using the highlevel sync interface
 */
#ifdef WIN32
#include "win32_compat.h"
#else
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#endif
 

#if defined(WIN32)
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#else
#include <sys/statvfs.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "libnfs.h"
#include <rpc/rpc.h>            /* for authunix_create() */
#include <popt.h>
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"

struct client {
       char *server;
       char *export;
       uint32_t mount_port;
       int is_finished;
};


char buf[3*1024*1024+337];

void print_usage(void)
{
	fprintf(stderr, "Usage: nfsclient-sync [-?|--help] [--usage] <url>\n");
}

void print_help(void)
{
	fprintf(stderr, "Usage: nfsclient-sync [OPTION...] <url>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Help options:\n");
	fprintf(stderr, "  -?, --help                        Show this help message\n");
	fprintf(stderr, "      --usage                       Display brief usage message\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "NFS URL format : nfs://<server>/<export-path>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "<host> is either of:\n");
	fprintf(stderr, "  \"hostname\"       nfs.example\n");
	fprintf(stderr, "  \"ipv4-address\"   10.1.1.27\n");
	fprintf(stderr, "  \"ipv6-address\"   [fce0::1]\n");
}

int main(int argc, char *argv[])
{
	struct nfs_context *nfs = NULL;
	int i, ret, res;
	uint64_t offset;
	struct client client;
	struct stat st;
	struct nfsfh  *nfsfh;
	struct nfsdir *nfsdir;
	struct nfsdirent *nfsdirent;
	struct statvfs svfs;
	exports export, tmp;
	int show_help = 0, show_usage = 0;
	poptContext pc;
	const char **extra_argv;
	int extra_argc = 0;
	const char *url = NULL;
	char *server = NULL, *path = NULL, *strp;

	struct poptOption popt_options[] = {
		{ "help", '?', POPT_ARG_NONE, &show_help, 0, "Show this help message", NULL },
		{ "usage", 0, POPT_ARG_NONE, &show_usage, 0, "Display brief usage message", NULL },
		POPT_TABLEEND
	};

#if defined(WIN32)
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		exit(10);
	}
#endif

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_POSIXMEHARDER);
	if ((res = poptGetNextOpt(pc)) < -1) {
		fprintf(stderr, "Failed to parse option : %s %s\n",
			poptBadOption(pc, 0), poptStrerror(res));
		exit(10);
	}
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		url = *extra_argv;
		extra_argv++;
		while (extra_argv[extra_argc]) {
			extra_argc++;
		}
	}
	poptFreeContext(pc);

	if (show_help != 0) {
		print_help();
		exit(0);
	}

	if (show_usage != 0) {
		print_usage();
		exit(0);
	}

	if (url == NULL) {
		fprintf(stderr, "No URL specified.\n");
		print_usage();
		exit(0);
	}

	if (strncmp(url, "nfs://", 6)) {
		fprintf(stderr, "Invalid URL specified.\n");
		print_usage();
		exit(0);
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
		exit(0);
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


	ret = nfs_opendir(nfs, "/", &nfsdir);
	if (ret != 0) {
		printf("Failed to opendir(\"/\")\n", nfs_get_error(nfs));
		exit(10);
	}
	while((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
		char path[1024];

		if (!strcmp(nfsdirent->name, ".") || !strcmp(nfsdirent->name, "..")) {
			continue;
		}

		snprintf(path, 1024, "%s/%s", "/", nfsdirent->name);
		ret = nfs_stat(nfs, path, &st);
		if (ret != 0) {
			fprintf(stderr, "Failed to stat(%s) %s\n", path, nfs_get_error(nfs));
			continue;
		}

		switch (st.st_mode & S_IFMT) {
		case S_IFLNK:
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
		printf(" %2d", st.st_nlink);
		printf(" %5d", st.st_uid);
		printf(" %5d", st.st_gid);
		printf(" %12" PRId64, st.st_size);

		printf(" %s\n", nfsdirent->name);
	}
	nfs_closedir(nfs, nfsdir);


finished:
	free(server);
	free(path);
	if (nfs != NULL) {		
		nfs_destroy_context(nfs);
	}
	printf("nfsclient finished\n");
	return 0;
}

