/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2026
   
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
#ifndef _LIBNFS_SERVER_H_
#define _LIBNFS_SERVER_H_

#include <tevent.h>

struct libnfs_server {
        struct rpc_context *rpc;
        struct tevent_fd *tfd;
};

struct libnfs_server_procs {
        uint32_t program;
        uint32_t version;
        struct service_proc *procs;
        int num_procs;
};

struct libnfs_servers {
        struct tevent_context *tevent;
        struct libnfs_server_procs *server_procs;
        int listen_fd;
};

struct libnfs_servers *libnfs_create_server(TALLOC_CTX *ctx,
                                            struct tevent_context *tevent,
                                            int port, char *name,
                                            struct libnfs_server_procs *server_procs);


#endif /* _LIBNFS_SERVER_H_ */

