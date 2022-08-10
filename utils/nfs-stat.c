/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2021
   
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
#include <inttypes.h>
#include <sys/types.h>
#include <fcntl.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"

struct file_context {
	int fd;
	struct nfs_context *nfs;
	struct nfsfh *nfsfh;
	struct nfs_url *url;
};

void usage(void)
{
	fprintf(stderr, "Usage: nfs-stat <file>\n");
	fprintf(stderr, "<file> stat an nfs file.\n");
	exit(0);
}

void
free_file_context(struct file_context *file_context)
{
	if (file_context->fd != -1) {
		close(file_context->fd);
	}
	if (file_context->nfsfh != NULL) {
		nfs_close(file_context->nfs, file_context->nfsfh);
	}
	if (file_context->nfs != NULL) {
		nfs_destroy_context(file_context->nfs);
	}
	nfs_destroy_url(file_context->url);
	free(file_context);
}

struct file_context *
open_file(const char *url, int flags)
{
	struct file_context *file_context;

	file_context = malloc(sizeof(struct file_context));
	if (file_context == NULL) {
		fprintf(stderr, "Failed to malloc file_context\n");
		return NULL;
	}
	file_context->fd     = -1;
	file_context->nfs    = NULL;
	file_context->nfsfh  = NULL;
	file_context->url    = NULL;
	
	file_context->nfs = nfs_init_context();
	if (file_context->nfs == NULL) {
		fprintf(stderr, "failed to init context\n");
		free_file_context(file_context);
		return NULL;
	}

	file_context->url = nfs_parse_url_full(file_context->nfs, url);
	if (file_context->url == NULL) {
		fprintf(stderr, "%s\n", nfs_get_error(file_context->nfs));
		free_file_context(file_context);
		return NULL;
	}

	if (nfs_mount(file_context->nfs, file_context->url->server,
				file_context->url->path) != 0) {
		fprintf(stderr, "Failed to mount nfs share : %s\n",
			       nfs_get_error(file_context->nfs));
		free_file_context(file_context);
		return NULL;
	}

	if (flags == O_RDONLY) {
		if (nfs_open(file_context->nfs, file_context->url->file, flags,
				&file_context->nfsfh) != 0) {
 			fprintf(stderr, "Failed to open file %s: %s\n",
				       file_context->url->file,
				       nfs_get_error(file_context->nfs));
			free_file_context(file_context);
			return NULL;
		}
	} else {
		if (nfs_creat(file_context->nfs, file_context->url->file, 0660,
				&file_context->nfsfh) != 0) {
 			fprintf(stderr, "Failed to creat file %s: %s\n",
				       file_context->url->file,
				       nfs_get_error(file_context->nfs));
			free_file_context(file_context);
			return NULL;
		}
	}
	return file_context;
}

char *get_file_type(int mode)
{
        switch (mode & S_IFMT) {
#ifndef WIN32
	case S_IFLNK: return "symbolic link";
#endif
	case S_IFDIR: return "directory";
	case S_IFCHR: return "character device";
	case S_IFBLK: return "block device";
	default: return "regular file";
	}
}

char uidbuf[16];
char gidbuf[16];

#ifdef WIN32
char *uid_to_name(int uid)
{
	sprintf(uidbuf, "%d", uid);
	return uidbuf;
}
char *gid_to_name(int gid)
{
	sprintf(gidbuf, "%d", gid);
	return gidbuf;
}
#else
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
char *uid_to_name(int uid)
{
	struct passwd *pw;

	pw = getpwuid(uid);
	if (pw) {
		return pw->pw_name;
	} else {
		sprintf(uidbuf, "%d", uid);
		return uidbuf;
	}
}	
char *gid_to_name(int gid)
{
	struct group *gr;

	gr = getgrgid(gid);
	if (gr) {
		return gr->gr_name;
	} else {
		sprintf(gidbuf, "%d", gid);
		return gidbuf;
	}
}	
#endif

char access_bits[11];
char *get_access_bits(int mode)
{
	switch (mode & S_IFMT) {
#ifndef WIN32
	case S_IFLNK: access_bits[0] = 'l'; break;
#endif
	case S_IFREG: access_bits[0] = '-'; break;
	case S_IFDIR: access_bits[0] = 'd'; break;
	case S_IFCHR: access_bits[0] = 'c'; break;
	case S_IFBLK: access_bits[0] = 'b'; break;
	default: access_bits[0] = '*';
	}
	access_bits[1] = "-r"[!!(mode & S_IRUSR)];
	access_bits[2] = "-w"[!!(mode & S_IWUSR)];
	access_bits[3] = "-xSs"[    !!(mode & S_IXUSR)
#ifndef WIN32
				+ 2*!!(mode & S_ISUID)
#endif
			       ];
	access_bits[4] = "-r"[!!(mode & S_IRGRP)];
	access_bits[5] = "-w"[!!(mode & S_IWGRP)];
	access_bits[6] = "-xSs"[    !!(mode & S_IXGRP)
#ifndef WIN32
				+ 2*!!(mode & S_ISGID)
#endif
			       ];
	access_bits[7] = "-r"[!!(mode & S_IROTH)];
	access_bits[8] = "-w"[!!(mode & S_IWOTH)];
	access_bits[9] = "-xTt"[    !!(mode & S_IXOTH)
#ifndef WIN32
				+ 2*!!(mode & S_ISVTX)
#endif
			       ];
	return access_bits;
}

#define BUFSIZE 1024*1024
static char buf[BUFSIZE];

int main(int argc, char *argv[])
{
	int ret;
	struct file_context *nf;
	struct nfs_stat_64 st;
	uint64_t off;
	int64_t count;
	
#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		return 10;
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

	if (argc < 2) {
		usage();
	}

	nf = open_file(argv[1], O_RDONLY);
	if (nf == NULL) {
		fprintf(stderr, "Failed to open %s\n", argv[1]);
		exit(10);
	}
	if (nfs_fstat64(nf->nfs, nf->nfsfh, &st) < 0) {
		fprintf(stderr, "Failed to stat %s\n", argv[1]);
		exit(10);
	}

	printf("  File:%s\n", argv[1]);
	printf("  Size: %-16" PRIu64 "Blocks: %-11" PRIu64 " IO Block: %" PRIu64 "  %s\n",
	       st.nfs_size, st.nfs_blocks, st.nfs_blksize,
	       get_file_type(st.nfs_mode));
	printf("Inode:%-12" PRIu64 "Links %" PRIu64 "\n",
	       st.nfs_ino, st.nfs_nlink);
	printf("Access: (%04" PRIo64 "/%s)  Uid: ( %" PRIu64 "/%s)  Gid: ( %" PRIu64 "/%s)\n",
	       st.nfs_mode & 07777, get_access_bits(st.nfs_mode),
	       st.nfs_uid, uid_to_name(st.nfs_uid),
	       st.nfs_gid, gid_to_name(st.nfs_gid));

	printf("Access: %s", ctime( (const time_t *) &st.nfs_atime));
	printf("Modify: %s", ctime( (const time_t *) &st.nfs_mtime));
	printf("Change: %s", ctime( (const time_t *) &st.nfs_ctime));
	free_file_context(nf);

	return 0;
}
