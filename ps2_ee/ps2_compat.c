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

int getaddrinfo(const char *node, const char*service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
        struct sockaddr_in *sin;
        struct hostent *host;
        int i, ip[4];

        sin = malloc(sizeof(struct sockaddr_in));
        sin->sin_len = sizeof(struct sockaddr_in);
        sin->sin_family=AF_INET;

        /* Some error checking would be nice */
        if (sscanf(node, "%d.%d.%d.%d", ip, ip+1, ip+2, ip+3) == 4) {
                for (i = 0; i < 4; i++) {
                        ((char *)&sin->sin_addr.s_addr)[i] = ip[i];
                }
        } else {
                host = gethostbyname(node);
                if (host == NULL) {
                        return -1;
                }
                if (host->h_addrtype != AF_INET) {
                        return -2;
                }
                memcpy(&sin->sin_addr.s_addr, host->h_addr, 4);
        }

        sin->sin_port=0;
        if (service) {
                sin->sin_port=htons(atoi(service));
        } 

        *res = malloc(sizeof(struct addrinfo));

        (*res)->ai_family = AF_INET;
        (*res)->ai_addrlen = sizeof(struct sockaddr_in);
        (*res)->ai_addr = (struct sockaddr *)sin;

        return 0;
}

void freeaddrinfo(struct addrinfo *res)
{
        free(res->ai_addr);
        free(res);
}

int getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
                char *host, socklen_t hostlen,
                char *serv, socklen_t servlen, int flags)
{
        /* not implemented yet */
        return -1;
}

#endif /* PS2_EE */
