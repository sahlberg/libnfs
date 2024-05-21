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

#ifdef PS2_EE

#define NEED_READV
#define NEED_WRITEV
#define NEED_POLL
#define NEED_BE64TOH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ps2_compat.h"

int getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
                char *host, socklen_t hostlen,
                char *serv, socklen_t servlen, int flags)
{
        /* not implemented yet */
        return -1;
}

int nfs_getaddrinfo(const char *node, const char*service,
const struct addrinfo *hints,
struct addrinfo **res)
{
  struct sockaddr_in *sin;

  sin = malloc(sizeof(struct sockaddr_in));
  sin->sin_len = sizeof(struct sockaddr_in);
  sin->sin_family=AF_INET;

  /* Some error checking would be nice */
  sin->sin_addr.s_addr = inet_addr(node);

  sin->sin_port=0;
  if (service) {
    sin->sin_port=htons(atoi(service));
  } 

  *res = malloc(sizeof(struct addrinfo));
  memset(*res, 0, sizeof(struct addrinfo));

  (*res)->ai_family = AF_INET;
  (*res)->ai_addrlen = sizeof(struct sockaddr_in);
  (*res)->ai_addr = (struct sockaddr *)sin;

  return 0;
}

void nfs_freeaddrinfo(struct addrinfo *res)
{
  free(res->ai_addr);
  free(res);
}

#endif /* PS2_EE */
