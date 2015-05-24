/*
   Copyright (C) 2014 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <asm/fcntl.h>

#include <nfsc/libnfs.h>

#include <sys/syscall.h>
#include <dlfcn.h>

#define NFS_MAX_FD  255

static int debug = 0;

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

#define LD_NFS_DPRINTF(level, fmt, args...) \
	do { \
		if ((debug) >= level) { \
			fprintf(stderr,"ld_nfs: "); \
			fprintf(stderr, (fmt), ##args); \
			fprintf(stderr,"\n"); \
		} \
	} while (0);

struct nfs_fd_list {
       int is_nfs;
       struct nfs_context *nfs;
       struct nfsfh *fh;

       /* so we can reopen and emulate dup2() */
       const char *path;
       int flags;
       mode_t mode;
};

static struct nfs_fd_list nfs_fd_list[NFS_MAX_FD];

int (*real_open)(__const char *path, int flags, mode_t mode);

int open(const char *path, int flags, mode_t mode)
{
	if (!strncmp(path, "nfs:", 4)) {
		struct nfs_context *nfs;
		struct nfs_url *url;
		struct nfsfh *fh = NULL;
		int ret, fd;

		LD_NFS_DPRINTF(9, "open(%s, %x, %o)", path, flags, mode);
		nfs = nfs_init_context();
		if (nfs == NULL) {
			LD_NFS_DPRINTF(1, "Failed to create context");
			errno = ENOMEM;
			return -1;
		}

		url = nfs_parse_url_full(nfs, path);
		if (url == NULL) {
			LD_NFS_DPRINTF(1, "Failed to parse URL: %s\n",
				nfs_get_error(nfs));
			nfs_destroy_context(nfs);
			errno = EINVAL;
			return -1;
		}

		if (nfs_mount(nfs, url->server, url->path) != 0) {
			LD_NFS_DPRINTF(1, "Failed to mount nfs share : %s\n",
			       nfs_get_error(nfs));
			nfs_destroy_url(url);
			nfs_destroy_context(nfs);
			errno = EINVAL;
			return -1;
		}

		if (flags & O_CREAT) {
			if ((ret = nfs_creat(nfs, url->file, mode, &fh)) != 0) {
				LD_NFS_DPRINTF(1, "Failed to creat nfs file : "
					"%s\n", nfs_get_error(nfs));
				nfs_destroy_url(url);
				nfs_destroy_context(nfs);
				errno = -ret;
				return -1;
			}
		} else {
			if ((ret = nfs_open(nfs, url->file, flags, &fh)) != 0) {
				LD_NFS_DPRINTF(1, "Failed to open nfs file : "
					"%s\n", nfs_get_error(nfs));
				nfs_destroy_url(url);
				nfs_destroy_context(nfs);
				errno = -ret;
				return -1;
			}
		}

		fd = nfs_get_fd(nfs);
		if (fd >= NFS_MAX_FD) {
			LD_NFS_DPRINTF(1, "Too many files open");
			nfs_destroy_url(url);
			nfs_destroy_context(nfs);
			errno = ENFILE;
			return -1;
		}		

		nfs_fd_list[fd].is_nfs     = 1;
		nfs_fd_list[fd].nfs        = nfs;
		nfs_fd_list[fd].fh         = fh;
		nfs_fd_list[fd].path       = strdup(path);
		nfs_fd_list[fd].flags      = flags;
		nfs_fd_list[fd].mode       = mode;

		nfs_destroy_url(url);

		LD_NFS_DPRINTF(9, "open(%s) == %d", path, fd);
		return fd;
	}

	return real_open(path, flags, mode);
}

int open64(const char *path, int flags, mode_t mode)
{
	return open(path, flags | O_LARGEFILE, mode);
}

int (*real_close)(int fd);

int close(int fd)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int i;

		LD_NFS_DPRINTF(9, "close(%d)", fd);

		nfs_fd_list[fd].is_nfs = 0;

		nfs_close(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh);
		nfs_fd_list[fd].fh = NULL;

		nfs_destroy_context(nfs_fd_list[fd].nfs);
		nfs_fd_list[fd].nfs = NULL;

		free(discard_const(nfs_fd_list[fd].path));
		nfs_fd_list[fd].path = NULL;

		return 0;
	}

        return real_close(fd);
}

ssize_t (*real_read)(int fd, void *buf, size_t count);

ssize_t read(int fd, void *buf, size_t count)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "read(fd:%d count:%d)", fd, (int)count);
		if ((ret = nfs_read(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				count, buf)) < 0) {
			errno = -ret;
			return -1;
		}
		return ret;
	}
	return real_read(fd, buf, count);
}

ssize_t (*real_pread)(int fd, void *buf, size_t count, off_t offset); 
ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "pread(fd:%d offset:%d count:%d)", fd,
			(int)offset, (int)count);
		if ((ret = nfs_pread(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				offset, count, buf)) < 0) {
			errno = -ret;
			return -1;
		}
		return ret;
	}
	return real_pread(fd, buf, count, offset);
}

ssize_t (*real_write)(int fd, const void *buf, size_t count);

ssize_t write(int fd, const void *buf, size_t count)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "write(fd:%d count:%d)", fd, (int)count);
		if ((ret = nfs_write(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				count,
				(char *)discard_const(buf))) < 0) {
			errno = -ret;
			return -1;
		}
		return ret;
	}
	return real_write(fd, buf, count);
}

ssize_t (*real_pwrite)(int fd, const void *buf, size_t count, off_t offset); 
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "pwrite(fd:%d offset:%d count:%d)", fd,
			(int)offset, (int)count);
		if ((ret = nfs_pwrite(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				offset, count,
				(char *)discard_const(buf))) < 0) {
			errno = -ret;
			return -1;
		}
		return ret;
	}
	return real_pwrite(fd, buf, count, offset);
}

int (*real_dup2)(int oldfd, int newfd);

int dup2(int oldfd, int newfd)
{
	close(newfd);

	if (nfs_fd_list[oldfd].is_nfs == 1) {
		struct nfs_context *nfs;
		struct nfs_url *url;
		struct nfsfh *fh = NULL;
		int ret, fd;

		LD_NFS_DPRINTF(9, "dup2(%s:%d, %d)", nfs_fd_list[oldfd].path,
			oldfd, newfd);
		nfs = nfs_init_context();
		if (nfs == NULL) {
			LD_NFS_DPRINTF(1, "Failed to create context");
			errno = ENOMEM;
			return -1;
		}

		url = nfs_parse_url_full(nfs, nfs_fd_list[oldfd].path);
		if (url == NULL) {
			LD_NFS_DPRINTF(1, "Failed to parse URL: %s\n",
				nfs_get_error(nfs));
			nfs_destroy_context(nfs);
			errno = EINVAL;
			return -1;
		}

		if (nfs_mount(nfs, url->server, url->path) != 0) {
			LD_NFS_DPRINTF(1, "Failed to mount nfs share : %s\n",
			       nfs_get_error(nfs));
			nfs_destroy_url(url);
			nfs_destroy_context(nfs);
			errno = EINVAL;
			return -1;
		}

		if ((ret = nfs_open(nfs, url->file, nfs_fd_list[oldfd].mode,
				&fh)) != 0) {
			LD_NFS_DPRINTF(1, "Failed to open nfs file : %s\n",
			       nfs_get_error(nfs));
			nfs_destroy_url(url);
			nfs_destroy_context(nfs);
			errno = -ret;
			return -1;
		}

		/* We could actually end on the right descriptor by chance */
		if (nfs_get_fd(nfs) != newfd) {
			if (real_dup2(nfs_get_fd(nfs), newfd) < 0) {
				LD_NFS_DPRINTF(1, "Failed to dup2 file : %d",
					errno);
				return -1;
			}

			close(rpc_get_fd(nfs_get_rpc_context(nfs)));
			rpc_set_fd(nfs_get_rpc_context(nfs), newfd);
		}

		fd = nfs_get_fd(nfs);
		if (fd >= NFS_MAX_FD) {
			LD_NFS_DPRINTF(1, "Too many files open");
			nfs_destroy_url(url);
			nfs_destroy_context(nfs);
			errno = ENFILE;
			return -1;
		}		

		nfs_fd_list[fd].is_nfs     = 1;
		nfs_fd_list[fd].nfs        = nfs;
		nfs_fd_list[fd].fh         = fh;
		nfs_fd_list[fd].path       = strdup(nfs_fd_list[oldfd].path);
		nfs_fd_list[fd].flags      = nfs_fd_list[oldfd].flags;
		nfs_fd_list[fd].mode       = nfs_fd_list[oldfd].mode;

		nfs_destroy_url(url);

		LD_NFS_DPRINTF(9, "dup2(%s) successful",
			nfs_fd_list[oldfd].path);
		return fd;
	}

	return real_dup2(oldfd, newfd);
}

int (*real_xstat)(int ver, __const char *path, struct stat *buf);

int __xstat(int ver, const char *path, struct stat *buf)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "__xstat(%s)", path);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = __fxstat(ver, fd, buf);
		close(fd);
		return ret;
	}

	return real_xstat(ver, path, buf);
}

int (*real_xstat64)(int ver, __const char *path, struct stat64 *buf);

int __xstat64(int ver, const char *path, struct stat64 *buf)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "__xstat64(%s)", path);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = __fxstat64(ver, fd, buf);
		close(fd);
		return ret;
	}

	return real_xstat64(ver, path, buf);
}

int (*real_lxstat)(int ver, __const char *path, struct stat *buf);

int __lxstat(int ver, const char *path, struct stat *buf)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "__lxstat(%s)", path);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = __fxstat(ver, fd, buf);
		close(fd);
		return ret;
	}

	return real_lxstat(ver, path, buf);
}

int (*real_lxstat64)(int ver, __const char *path, struct stat64 *buf);

int __lxstat64(int ver, const char *path, struct stat64 *buf)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "__lxstat64(%s)", path);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = __fxstat64(ver, fd, buf);
		close(fd);
		return ret;
	}

	return real_lxstat64(ver, path, buf);
}

int (*real_fxstat)(int ver, int fd, struct stat *buf);

int __fxstat(int ver, int fd, struct stat *buf)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;
		struct nfs_stat_64 st64;

		LD_NFS_DPRINTF(9, "__fxstat(%d)", fd);
		if ((ret = nfs_fstat64(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				(void *)&st64)) < 0) {
			errno = -ret;
			return -1;
		}

		buf->st_dev     = st64.nfs_dev;
		buf->st_ino     = st64.nfs_ino;
		buf->st_mode    = st64.nfs_mode;
		buf->st_nlink   = st64.nfs_nlink;
		buf->st_uid     = st64.nfs_uid;
		buf->st_gid     = st64.nfs_gid;
		buf->st_rdev    = st64.nfs_rdev;
		buf->st_size    = st64.nfs_size;
		buf->st_blksize = st64.nfs_blksize;
		buf->st_blocks  = st64.nfs_blocks;
		buf->st_atim.tv_sec   = st64.nfs_atime;
		buf->st_atim.tv_usec  = st64.nfs_atime_nsec / 1000;
		buf->st_mtim.tv_sec   = st64.nfs_mtime;
		buf->st_mtim.tv_usec  = st64.nfs_mtime_nsec / 1000;
		buf->st_ctim.tv_sec   = st64.nfs_ctime;
		buf->st_ctim.tv_usec  = st64.nfs_ctime_nsec / 1000;

		LD_NFS_DPRINTF(9, "__fxstat(%d) success", fd);
		return ret;
	}

	return real_fxstat(ver, fd, buf);
}

int (*real_fxstat64)(int ver, int fd, struct stat64 *buf);

int __fxstat64(int ver, int fd, struct stat64 *buf)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;
		struct nfs_stat_64 st64;

		LD_NFS_DPRINTF(9, "__fxstat64(%d)", fd);
		if ((ret = nfs_fstat64(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				(void *)&st64)) < 0) {
			errno = -ret;
			return -1;
		}

		buf->st_dev     = st64.nfs_dev;
		buf->st_ino     = st64.nfs_ino;
		buf->st_mode    = st64.nfs_mode;
		buf->st_nlink   = st64.nfs_nlink;
		buf->st_uid     = st64.nfs_uid;
		buf->st_gid     = st64.nfs_gid;
		buf->st_rdev    = st64.nfs_rdev;
		buf->st_size    = st64.nfs_size;
		buf->st_blksize = st64.nfs_blksize;
		buf->st_blocks  = st64.nfs_blocks;
		buf->st_atim.tv_sec   = st64.nfs_atime;
		buf->st_atim.tv_usec  = st64.nfs_atime_nsec / 1000;
		buf->st_mtim.tv_sec   = st64.nfs_mtime;
		buf->st_mtim.tv_usec  = st64.nfs_mtime_nsec / 1000;
		buf->st_ctim.tv_sec   = st64.nfs_ctime;
		buf->st_ctim.tv_usec  = st64.nfs_ctime_nsec / 1000;

		LD_NFS_DPRINTF(9, "__fxstat64(%d) success", fd);
		return ret;
	}

	return real_fxstat64(ver, fd, buf);
}

int (*real_fallocate)(int fd, int mode, off_t offset, off_t len);

int fallocate(int fd, int mode, off_t offset, off_t len)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		LD_NFS_DPRINTF(9, "fallocate(%d)", fd);
		errno = EOPNOTSUPP;
		return -1;
	}

	return real_fallocate(fd, mode, offset, len);
}

int (*real_ftruncate)(int fd, off_t len);

int ftruncate(int fd, off_t len)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "ftruncate(%d, %d)", fd, (int)len);
		if ((ret = nfs_ftruncate(nfs_fd_list[fd].nfs,
				nfs_fd_list[fd].fh,
				len)) < 0) {
			errno = -ret;
			return -1;
		}
		return 0;
	}

	return real_ftruncate(fd, len);
}

int (*real_truncate)(const char *path, off_t len);

int truncate(const char *path, off_t len)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "truncate(%s, %d)", path, (int)len);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = ftruncate(fd, len);
		close(fd);
		return ret;
	}

	return real_truncate(path, len);
}

int (*real_fchmod)(int fd, mode_t mode);

int fchmod(int fd, mode_t mode)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "fchmod(%d, %o)", fd, (int)mode);
		if ((ret = nfs_fchmod(nfs_fd_list[fd].nfs,
				nfs_fd_list[fd].fh,
				mode)) < 0) {
			errno = -ret;
			return -1;
		}
		return 0;
	}

	return real_fchmod(fd, mode);
}

int (*real_chmod)(const char *path, mode_t mode);

int chmod(const char *path, mode_t mode)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "chmod(%s, %o)", path, (int)mode);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = fchmod(fd, mode);
		close(fd);
		return ret;
	}

	return real_chmod(path, mode);
}

static void __attribute__((constructor)) _init(void)
{
	int i;

	if (getenv("LD_NFS_DEBUG") != NULL) {
		debug = atoi(getenv("LD_NFS_DEBUG"));
	}

	real_open = dlsym(RTLD_NEXT, "open");
	if (real_open == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(open)");
		exit(10);
	}

	real_close = dlsym(RTLD_NEXT, "close");
	if (real_close == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(close)");
		exit(10);
	}

	real_read = dlsym(RTLD_NEXT, "read");
	if (real_read == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(read)");
		exit(10);
	}

	real_pread = dlsym(RTLD_NEXT, "pread");
	if (real_pread == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(pread)");
		exit(10);
	}

	real_write = dlsym(RTLD_NEXT, "write");
	if (real_write == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(write)");
		exit(10);
	}

	real_pwrite = dlsym(RTLD_NEXT, "pwrite");
	if (real_pwrite == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(pwrite)");
		exit(10);
	}

	real_xstat = dlsym(RTLD_NEXT, "__xstat");
	if (real_xstat == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(__xstat)");
		exit(10);
	}

	real_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
	if (real_xstat64 == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(__xstat64)");
	}

	real_lxstat = dlsym(RTLD_NEXT, "__lxstat");
	if (real_lxstat == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(__lxstat)");
		exit(10);
	}

	real_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
	if (real_lxstat64 == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(_lxstat64)");
		exit(10);
	}

	real_fxstat = dlsym(RTLD_NEXT, "__fxstat");
	if (real_fxstat == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(__fxstat)");
		exit(10);
	}

	real_fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
	if (real_fxstat64 == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(__fxstat64)");
		exit(10);
	}

	real_fallocate = dlsym(RTLD_NEXT, "fallocate");
	if (real_fallocate == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(fallocate)");
		exit(10);
	}

	real_dup2 = dlsym(RTLD_NEXT, "dup2");
	if (real_dup2 == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(dup2)");
		exit(10);
	}

	real_truncate = dlsym(RTLD_NEXT, "truncate");
	if (real_truncate == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(truncate)");
		exit(10);
	}

	real_ftruncate = dlsym(RTLD_NEXT, "ftruncate");
	if (real_ftruncate == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(ftruncate)");
		exit(10);
	}

	real_chmod = dlsym(RTLD_NEXT, "chmod");
	if (real_chmod == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(chmod)");
		exit(10);
	}

	real_fchmod = dlsym(RTLD_NEXT, "fchmod");
	if (real_fchmod == NULL) {
		LD_NFS_DPRINTF(0, "Failed to dlsym(fchmod)");
		exit(10);
	}
}
