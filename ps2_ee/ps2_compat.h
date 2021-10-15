/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2021 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _PS2_COMPAT_H_
#define _PS2_COMPAT_H_

#ifdef PS2_EE

#define NO_SRV_AUTOSCAN
#define IPPORT_RESERVED 1024

#include <errno.h>
#include <sys/time.h>
#include <sys/utime.h>
#include <ps2ip.h>

typedef unsigned long int fsfilcnt_t;

#define getservbyport(a,b) NULL
#define major(a) 0
#define minor(a) 0
#define O_NOFOLLOW 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

struct statvfs {
        unsigned long int f_bsize;
        unsigned long int f_frsize;
        unsigned long int f_blocks;
        unsigned long int f_bfree;
        unsigned long int f_bavail;
        unsigned long int f_files;
        unsigned long int f_ffree;
        unsigned long int f_favail;
        unsigned long int f_fsid;
        unsigned long int f_flag;
        unsigned long int f_namemax;
};

#define getpid() 0
#define getuid() 0
#define getgid() 0

#define write(a,b,c) lwip_write(a,b,c)
#define read(a,b,c) lwip_read(a,b,c)
#define gethostbyname(a) lwip_gethostbyname(a)
#define close(a) lwip_close(a)

#define getlogin_r(a,b) ENXIO

#define POLLIN      0x0001    /* There is data to read */
#define POLLPRI     0x0002    /* There is urgent data to read */
#define POLLOUT     0x0004    /* Writing now will not block */
#define POLLERR     0x0008    /* Error condition */
#define POLLHUP     0x0010    /* Hung up */

struct pollfd {
        int fd;
        short events;
        short revents;
};

int poll(struct pollfd *fds, unsigned int nfds, int timo);

struct iovec {
  void  *iov_base;
  size_t iov_len;
};

ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t readv(int fd, const struct iovec *iov, int iovcnt);

int getaddrinfo(const char *node, const char*service,
                const struct addrinfo *hints,
                struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);

long long int be64toh(long long int x);

#define SOL_TCP IPPROTO_TCP
#define EAI_AGAIN EAGAIN

/* just pretend they are the same so we compile */
#define sockaddr_in6 sockaddr_in

#endif /* PS2_EE */

#endif /* _PS2_COMPAT_H_ */
