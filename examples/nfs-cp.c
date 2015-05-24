/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2013
   
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
#include "libnfs-raw-mount.h"

struct file_context {
	int is_nfs;
	int fd;
	struct nfs_context *nfs;
	struct nfsfh *nfsfh;
	struct nfs_url *url;
};

void usage(void)
{
	fprintf(stderr, "Usage: nfs-cp <src> <dst>\n");
	fprintf(stderr, "<src>,<dst> can either be a local file or "
			"an nfs URL.\n");
	exit(0);
}

static void
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

static int
fstat_file(struct file_context *fc, struct stat *st)
{
	if (fc->is_nfs == 0) {
		return fstat(fc->fd, st);
	} else {
		int res;
		struct nfs_stat_64 nfs_st;
		res = nfs_fstat64(fc->nfs, fc->nfsfh, &nfs_st);
		st->st_dev          = nfs_st.nfs_dev;
		st->st_ino          = nfs_st.nfs_ino;
		st->st_mode         = nfs_st.nfs_mode;
		st->st_nlink        = nfs_st.nfs_nlink;
		st->st_uid          = nfs_st.nfs_uid;
		st->st_gid          = nfs_st.nfs_gid;
		st->st_rdev         = nfs_st.nfs_rdev;
		st->st_size         = nfs_st.nfs_size;
		st->st_blksize      = nfs_st.nfs_blksize;
		st->st_blocks       = nfs_st.nfs_blocks;
		st->st_atim.tv_sec  = nfs_st.nfs_atime;
		st->st_mtim.tv_sec  = nfs_st.nfs_mtime;
		st->st_ctim.tv_sec  = nfs_st.nfs_ctime;

		return res;
	}
}

static int64_t
file_pread(struct file_context *fc, char *buf, int64_t count, uint64_t off)
{
	if (fc->is_nfs == 0) {
		lseek(fc->fd, off, SEEK_SET);
		return read(fc->fd, buf, count);
	} else {
		return nfs_pread(fc->nfs, fc->nfsfh, off, count, buf);
	}
}

static int64_t
file_pwrite(struct file_context *fc, char *buf, int64_t count, uint64_t off)
{
	if (fc->is_nfs == 0) {
		lseek(fc->fd, off, SEEK_SET);
		return write(fc->fd, buf, count);
	} else {
		return nfs_pwrite(fc->nfs, fc->nfsfh, off, count, buf);
	}
}

static struct file_context *
open_file(const char *url, int flags)
{
	struct file_context *file_context;

	file_context = malloc(sizeof(struct file_context));
	if (file_context == NULL) {
		fprintf(stderr, "Failed to malloc file_context\n");
		return NULL;
	}
	file_context->is_nfs = 0;
	file_context->fd     = -1;
	file_context->nfs    = NULL;
	file_context->nfsfh  = NULL;
	file_context->url    = NULL;
	
	if (strncmp(url, "nfs://", 6)) {
		file_context->is_nfs = 0;
		file_context->fd = open(url, flags, 0660);
		if (file_context->fd == -1) {		
			fprintf(stderr, "Failed to open %s\n", url);
			free_file_context(file_context);
			return NULL;
		}
		return file_context;
	}

	file_context->is_nfs = 1;

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

#define BUFSIZE 1024*1024
static char buf[BUFSIZE];

int main(int argc, char *argv[])
{
	int ret;
	struct stat st;
	struct file_context *src;
	struct file_context *dst;
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

	if (argc != 3) {
		usage();
	}

	src = open_file(argv[1], O_RDONLY);
	if (src == NULL) {
		fprintf(stderr, "Failed to open %s\n", argv[1]);
		return 10;
	}

	dst = open_file(argv[2], O_WRONLY|O_CREAT|O_TRUNC);
	if (dst == NULL) {
		fprintf(stderr, "Failed to open %s\n", argv[2]);
		free_file_context(src);
		return 10;
	}

	if (fstat_file(src, &st) != 0) {
		fprintf(stderr, "Failed to fstat source file\n");
		free_file_context(src);
		free_file_context(dst);
		return 10;
	}

	off = 0;
	while (off < st.st_size) {
		count = st.st_size - off;
		if (count > BUFSIZE) {
			count = BUFSIZE;
		}
		count = file_pread(src, buf, count, off);
		if (count < 0) {
			fprintf(stderr, "Failed to read from source file\n");
			free_file_context(src);
			free_file_context(dst);
			return 10;
		}
		count = file_pwrite(dst, buf, count, off);
		if (count < 0) {
			fprintf(stderr, "Failed to write to dest file\n");
			free_file_context(src);
			free_file_context(dst);
			return 10;
		}

		off += count;
	}
	printf("copied %d bytes\n", (int)off);

	free_file_context(src);
	free_file_context(dst);

	return 0;
}
