/*
   Copyright (C) 2013 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifndef AROS_COMPAT_H
#define AROS_COMPAT_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/mount.h>
#include <proto/socket.h>
#include <proto/exec.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>

#define statvfs statfs
#define ioctl IoctlSocket
#define close CloseSocket

#define inet_pton aros_inet_pton
#define freeaddrinfo aros_freeaddrinfo
#define getnameinfo aros_getnameinfo
#define getaddrinfo aros_getaddrinfo

extern struct Library * SocketBase;

void aros_init_socket(void);

#define f_flag    f_flags
#define f_favail  f_ffree
/* we dont have these at all */
#define f_fsid    f_spare[0]
#define f_frsize  f_spare[0]
#define f_namemax f_spare[0]

#define POLLIN      0x0001    /* There is data to read */
#define POLLPRI     0x0002    /* There is urgent data to read */
#define POLLOUT     0x0004    /* Writing now will not block */
#define POLLERR     0x0008    /* Error condition */
#define POLLHUP     0x0010    /* Hung up */
#define POLLNVAL    0x0020    /* Invalid request: fd not open */

struct utimbuf {
       int actime;
       int modtime;
};

struct pollfd {
    int fd;           /* file descriptor */
    short events;     /* requested events */
    short revents;    /* returned events */
};

#define poll(x, y, z)        aros_poll(x, y, z)

#endif
