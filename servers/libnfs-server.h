/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
  Copyright 2025 Ronnie Sahlberg

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the “Software”),
  to deal in the Software without restriction, including without
  limitation the rights to use, copy, modify, merge, publish, distribute,
  sublicense, and/or sell copies of the Software, and to permit persons
  to whom the Software is furnished to do so, subject to the following
  conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#ifndef _LIBNFS_SERVER_H_
#define _LIBNFS_SERVER_H_

#include <talloc.h>
#include <tevent.h>

struct libnfs_server_procs {
        uint32_t program;
        uint32_t version;
        struct service_proc *procs;
        int num_procs;
};

struct libnfs_servers;

#define TRANSPORT_TCP  1
#define TRANSPORT_UDP  2
#define TRANSPORT_TCP6 3
#define TRANSPORT_UDP6 4

struct libnfs_servers *libnfs_create_server(TALLOC_CTX *ctx,
                                            struct tevent_context *tevent,
                                            int port, char *name,
                                            int transports,
                                            struct libnfs_server_procs *server_procs);


#endif /* _LIBNFS_SERVER_H_ */

