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
/* A FUSE filesystem based on libnfs. */

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>

#include <nfsc/libnfs.h>

#define discard_const(ptr) ((void *)((intptr_t)(ptr)))

struct nfs_context *nfs = NULL;

static int fuse_nfs_getattr(const char *path, struct stat *stbuf)
{
	int ret = 0;
	struct nfs_stat_64 nfs_st;

	ret = nfs_stat64(nfs, path, &nfs_st);

	stbuf->st_dev          = nfs_st.nfs_dev;
	stbuf->st_ino          = nfs_st.nfs_ino;
	stbuf->st_mode         = nfs_st.nfs_mode;
	stbuf->st_nlink        = nfs_st.nfs_nlink;
	stbuf->st_uid          = nfs_st.nfs_uid;
	stbuf->st_gid          = nfs_st.nfs_gid;
	stbuf->st_rdev         = nfs_st.nfs_rdev;
	stbuf->st_size         = nfs_st.nfs_size;
	stbuf->st_blksize      = nfs_st.nfs_blksize;
	stbuf->st_blocks       = nfs_st.nfs_blocks;
	stbuf->st_atim.tv_sec  = nfs_st.nfs_atime;
	stbuf->st_atim.tv_usec = nfs_st.nfs_atime_nsec / 1000;
	stbuf->st_mtim.tv_sec  = nfs_st.nfs_mtime;
	stbuf->st_mtim.tv_usec = nfs_st.nfs_mtime_nsec / 1000;
	stbuf->st_ctim.tv_sec  = nfs_st.nfs_ctime;
	stbuf->st_ctim.tv_usec = nfs_st.nfs_ctime_nsec / 1000;

	return ret;
}

static int fuse_nfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	struct nfsdir *nfsdir;
	struct nfsdirent *nfsdirent;

	int ret = 0;

	ret = nfs_opendir(nfs, path, &nfsdir);
	if (ret < 0) {
		return ret;
	}
	while ((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
		filler(buf, nfsdirent->name, NULL, 0);
	}

	return ret;
}

static int fuse_nfs_open(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;
	struct nfsfh *nfsfh;

	fi->fh = 0;
	ret = nfs_open(nfs, path, fi->flags, &nfsfh);
	if (ret < 0) {
		return ret;
	}

	fi->fh = (uint64_t)nfsfh;

	return ret;
}

static int fuse_nfs_release(const char *path, struct fuse_file_info *fi)
{
	struct nfsfh *nfsfh = (struct nfsfh *)fi->fh;

	nfs_close(nfs, nfsfh);
	return 0;
}

static int fuse_nfs_read(const char *path, char *buf, size_t size,
       off_t offset, struct fuse_file_info *fi)
{
	int ret = 0;
	struct nfsfh *nfsfh = (struct nfsfh *)fi->fh;

	ret = nfs_pread(nfs, nfsfh, offset, size, buf);

	return ret;
}

static int fuse_nfs_write(const char *path, const char *buf, size_t size,
       off_t offset, struct fuse_file_info *fi)
{
	int ret = 0;
	struct nfsfh *nfsfh = (struct nfsfh *)fi->fh;

	ret = nfs_pwrite(nfs, nfsfh, offset, size, discard_const(buf));

	return ret;
}

static int fuse_nfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int ret = 0;
	struct nfsfh *nfsfh;

	ret = nfs_creat(nfs, path, mode, &nfsfh);
	if (ret < 0) {
		return ret;
	}

	fi->fh = (uint64_t)nfsfh;

	return ret;
}

static int fuse_nfs_utime(const char *path, struct utimbuf *times)
{
	int ret = 0;

	ret = nfs_utime(nfs, path, times);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

static int fuse_nfs_unlink(const char *path)
{
	int ret = 0;

	ret = nfs_unlink(nfs, path);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

static int fuse_nfs_rmdir(const char *path)
{
	int ret = 0;

	ret = nfs_rmdir(nfs, path);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

static int fuse_nfs_mkdir(const char *path, mode_t mode)
{
	int ret = 0;

	ret = nfs_mkdir(nfs, path);
	if (ret < 0) {
		return ret;
	}
	ret = nfs_chmod(nfs, path, mode);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

static struct fuse_operations nfs_oper = {
	.create		= fuse_nfs_create,
	.getattr	= fuse_nfs_getattr,
	.mkdir		= fuse_nfs_mkdir,
	.open		= fuse_nfs_open,
	.read		= fuse_nfs_read,
	.readdir	= fuse_nfs_readdir,
	.release	= fuse_nfs_release,
	.rmdir		= fuse_nfs_rmdir,
	.unlink		= fuse_nfs_unlink,
	.utime		= fuse_nfs_utime,
	.write		= fuse_nfs_write,
};

void print_usage(char *name)
{
	printf("Usage: %s [-?|--help] [-n|--nfs-share=nfs-url] [-m|--mountpoint=mountpoint]\n",
		name);
	exit(0);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	static struct option long_opts[] = {
		{ "help", no_argument, 0, '?' },
		{ "nfs-share", required_argument, 0, 'n' },
		{ "mountpoint", required_argument, 0, 'm' },
		{ NULL, 0, 0, 0 }
	};
	int c;
	int opt_idx = 0;
	char *url = NULL;
	char *mnt = NULL;
	char *server = NULL, *export = NULL, *strp;
	int fuse_nfs_argc = 6;
	char *fuse_nfs_argv[16] = {
		"fuse-nfs",
		"<export>",
		"-oallow_other",
		"-odefault_permissions",
		"-omax_write=32768",
		"-s",
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
        };

	while ((c = getopt_long(argc, argv, "?hm:n:", long_opts,
		    &opt_idx)) > 0) {
		switch (c) {
		case 'h':
		case '?':
			print_usage(argv[0]);
			return 0;
		case 'm':
			mnt = strdup(optarg);
			break;
		case 'n':
			url = strdup(optarg);
			break;
		}
	}

	if (url == NULL) {
		fprintf(stderr, "-n was not specified.\n");
		print_usage(argv[0]);
		ret = 10;
		goto finished;
	}
	if (mnt == NULL) {
		fprintf(stderr, "-m was not specified.\n");
		print_usage(argv[0]);
		ret = 10;
		goto finished;
	}


	if (strncmp(url, "nfs://", 6)) {
		fprintf(stderr, "Invalid URL specified.\n");
		ret = 10;
		goto finished;
	}
	server = strdup(url + 6);
	if (server == NULL) {
		fprintf(stderr, "Failed to strdup server string\n");
		ret = 10;
		goto finished;
	}
	if (server[0] == '/' || server[0] == '\0') {
		fprintf(stderr, "Invalid server string.\n");
		ret = 10;
		goto finished;
	}
	strp = strchr(server, '/');
	if (strp == NULL) {
		fprintf(stderr, "Invalid URL specified.\n");
		ret = 10;
		goto finished;
	}
	export = strdup(strp);
	if (export == NULL) {
		fprintf(stderr, "Failed to strdup server string\n");
		ret = 10;
		goto finished;
	}
	if (export[0] != '/') {
		fprintf(stderr, "Invalid export.\n");
		ret = 10;
		goto finished;
	}
	*strp = 0;

	nfs = nfs_init_context();
	if (nfs == NULL) {
		printf("failed to init context\n");
		goto finished;
	}

	ret = nfs_mount(nfs, server, export);
	if (ret != 0) {
 		printf("Failed to mount nfs share : %s\n", nfs_get_error(nfs));
		goto finished;
	}


	fuse_nfs_argv[1] = mnt;
	return fuse_main(fuse_nfs_argc, fuse_nfs_argv, &nfs_oper, NULL);

finished:
	if (nfs != NULL) {
		nfs_destroy_context(nfs);
	}
	free(server);
	free(export);
	free(url);
	free(mnt);
	return ret;
}
