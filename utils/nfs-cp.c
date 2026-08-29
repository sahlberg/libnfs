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
#include <win32/win32_compat.h>
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#define PRId64 "ll"
#else
#include <inttypes.h>
#include <sys/stat.h>
#include <string.h>
#endif
 
#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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
		st->st_dev          = (dev_t)nfs_st.nfs_dev;
		st->st_ino          = (ino_t)nfs_st.nfs_ino;
#ifndef WIN32
		st->st_mode         = (mode_t)nfs_st.nfs_mode;
		st->st_nlink        = (nlink_t)nfs_st.nfs_nlink;
		st->st_blksize      = nfs_st.nfs_blksize;
		st->st_blocks       = nfs_st.nfs_blocks;
#endif
		st->st_uid          = (uid_t)nfs_st.nfs_uid;
		st->st_gid          = (gid_t)nfs_st.nfs_gid;
		st->st_rdev         = (dev_t)nfs_st.nfs_rdev;
		st->st_size         = (off_t)nfs_st.nfs_size;
		st->st_atime        = nfs_st.nfs_atime;
		st->st_mtime        = nfs_st.nfs_mtime;
		st->st_ctime        = nfs_st.nfs_ctime;

		return res;
	}
}

static ssize_t
file_pread(struct file_context *fc, char *buf, size_t count, off_t off)
{
	if (fc->is_nfs == 0) {
		lseek(fc->fd, off, SEEK_SET);
		return read(fc->fd, buf, count);
	} else {
		return nfs_pread(fc->nfs, fc->nfsfh, buf, count, off);
	}
}

static ssize_t
file_pwrite(struct file_context *fc, char *buf, size_t count, off_t off)
{
	if (fc->is_nfs == 0) {
		lseek(fc->fd, off, SEEK_SET);
		return write(fc->fd, buf, count);
	} else {
		return nfs_pwrite(fc->nfs, fc->nfsfh, buf, count, off);
	}
}

/*
 * Sparse copying needs the server to tell us where the holes are, which is
 * the NFSv4.2 SEEK operation. Nothing else libnfs speaks to can answer that,
 * so a source that is not NFSv4.2 is copied the plain way.
 */
static int
file_can_seek_holes(struct file_context *fc)
{
	return fc->is_nfs && nfs_get_version(fc->nfs) == NFS_V4_2;
}

static int
file_seek(struct file_context *fc, uint64_t off, int whence, uint64_t *res)
{
	return nfs_lseek(fc->nfs, fc->nfsfh, off, whence, res);
}

static int
file_ftruncate(struct file_context *fc, uint64_t size)
{
	if (fc->is_nfs == 0) {
		return ftruncate(fc->fd, (off_t)size);
	}
	return nfs_ftruncate(fc->nfs, fc->nfsfh, size);
}

/*
 * Deallocate a range of the destination. The destination was just created and
 * then sized with ftruncate, so the range should already be unallocated; this
 * makes the hole explicit for a server that chose to allocate anyway. It is
 * best effort and a failure is not fatal, the range simply stays as it is.
 */
static void
file_punch_hole(struct file_context *fc, uint64_t off, uint64_t len)
{
	if (!fc->is_nfs || nfs_get_version(fc->nfs) != NFS_V4_2 || len == 0) {
		return;
	}
	nfs_fallocate(fc->nfs, fc->nfsfh,
		      FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, off, len);
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
		if (nfs_creat(file_context->nfs, file_context->url->file,
			       0660,
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
	struct stat st;
	struct file_context *src;
	struct file_context *dst;
	off_t off;
	ssize_t count;
	
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

	dst = open_file(argv[2], O_WRONLY|O_CREAT|O_EXCL|O_TRUNC);
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
	if (file_can_seek_holes(src)) {
		/*
		 * Walk the source from one region of data to the next and copy
		 * only those, so that the holes between them are neither read
		 * nor written. Sizing the destination up front means the gaps
		 * we skip are already holes in it.
		 */
		uint64_t pos = 0, data, hole, holes = 0;

		if (file_ftruncate(dst, (uint64_t)st.st_size) != 0) {
			fprintf(stderr, "Failed to set size of dest file (%s)\n",
				dst->is_nfs ? nfs_get_error(dst->nfs) : strerror(errno));
			free_file_context(src);
			free_file_context(dst);
			return 10;
		}

		while (pos < (uint64_t)st.st_size) {
			if (file_seek(src, pos, SEEK_DATA, &data) != 0) {
				/*
				 * No data at or after pos, so everything left
				 * is a hole. SEEK reports that as ENXIO, the
				 * same as lseek(2) does.
				 */
				file_punch_hole(dst, pos,
						(uint64_t)st.st_size - pos);
				holes += (uint64_t)st.st_size - pos;
				break;
			}
			if (data >= (uint64_t)st.st_size) {
				break;
			}
			if (data > pos) {
				file_punch_hole(dst, pos, data - pos);
				holes += data - pos;
			}
			if (file_seek(src, data, SEEK_HOLE, &hole) != 0 ||
			    hole > (uint64_t)st.st_size) {
				hole = (uint64_t)st.st_size;
			}

			for (off = (off_t)data; off < (off_t)hole; ) {
				count = (size_t)(hole - (uint64_t)off);
				if (count > BUFSIZE) {
					count = BUFSIZE;
				}
				count = file_pread(src, buf, count, off);
				if (count < 0) {
					fprintf(stderr, "Failed to read from source file (%s)\n",
						src->is_nfs ? nfs_get_error(src->nfs) : strerror(errno));
					free_file_context(src);
					free_file_context(dst);
					return 10;
				}
				if (count == 0) {
					break;
				}
				count = file_pwrite(dst, buf, count, off);
				if (count <= 0) {
					fprintf(stderr, "Failed to write to dest file (%s)\n",
						dst->is_nfs ? nfs_get_error(dst->nfs) : strerror(errno));
					free_file_context(src);
					free_file_context(dst);
					return 10;
				}
				off += count;
			}
			pos = hole;
		}

		printf("copied %" PRId64 " bytes, %" PRId64 " bytes of holes "
		       "skipped\n", (int64_t)st.st_size - (int64_t)holes,
		       (int64_t)holes);

		free_file_context(src);
		free_file_context(dst);

		return 0;
	}

	while (off < st.st_size) {
		count = (size_t)(st.st_size - off);
		if (count > BUFSIZE) {
			count = BUFSIZE;
		}
		count = file_pread(src, buf, count, off);
		if (count < 0) {
			fprintf(stderr, "Failed to read from source file (%s)\n",
				src->is_nfs ? nfs_get_error(src->nfs) : strerror(errno));
			free_file_context(src);
			free_file_context(dst);
			return 10;
		}
		if (count == 0) {
			/* Short file. The size we got from fstat is stale,
			 * for example because the file was truncated by
			 * someone else after we opened it.
			 */
			break;
		}
		count = file_pwrite(dst, buf, count, off);
		if (count <= 0) {
			fprintf(stderr, "Failed to write to dest file (%s)\n",
				dst->is_nfs ? nfs_get_error(dst->nfs) : strerror(errno));
			free_file_context(src);
			free_file_context(dst);
			return 10;
		}

		off += count;
	}
	printf("copied %" PRId64 " bytes\n", (int64_t)off);

	free_file_context(src);
	free_file_context(dst);

	return 0;
}
