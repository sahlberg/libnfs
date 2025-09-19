/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2025
   
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
/*
 * A non-blocking and eventdriven implementation of rpcbind using libnfs.
 * TODO: Call NULL periodically and reap dead services from the database.
 */

#ifndef _MOUNT_H_
#define _MOUNT_H_

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"

struct mountd_export {
        struct mountd_export *next;
        char *path;
        struct nfs_fh3 fh;
};
        
struct mountd_client {
        struct mountd_client *next;
        char *client;
        char *path;
};

struct mountd_state {
        struct tevent_context *tevent;
        struct rpc_context *rpc;
        struct mountd_export *exports;
        struct mountd_client *clients;
};

struct mountd_state *mountd_init(TALLOC_CTX *ctx, struct tevent_context *tevent);
struct mountd_export *mountd_add_export(struct mountd_state *mountd, char *path, int fh_len, char *fh);

#endif /* _MOUNT_H_ */
