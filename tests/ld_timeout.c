/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2017 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#include <asm/fcntl.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nfsc/libnfs.h>

#include <sys/syscall.h>
#include <dlfcn.h>

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

#define PRINTF(fmt, args...) \
	do { \
		fprintf(stderr,"ld_nfs: ");			\
		fprintf(stderr, (fmt), ##args);			\
		fprintf(stderr,"\n");				\
	} while (0);

int timeout_start = 0;

int (*real_rpc_service)(struct rpc_context *rpc, int revents);

int rpc_service(struct rpc_context *rpc, int revents)
{
        static int call_idx = 0;

        call_idx++;
        if (call_idx >= timeout_start) {
                PRINTF("sleep for 1 seconds causing a timeout");
                sleep(1);
                /* Strip off all the POLLINs so that we will not try
                 * to process them in rpc_service and instead fall-through
                 * to the rpc_timeout_scan() and handle the PDUs there
                 * instead.
                 */
                revents &= ~POLLIN;
        }
        return real_rpc_service(rpc, revents);
}


static void __attribute__((constructor))
_init(void)
{
        /* Start timing out calls at this index */
	if (getenv("TIMEOUT_START") != NULL) {
		timeout_start = atoi(getenv("TIMEOUT_START"));
	}

	real_rpc_service = dlsym(RTLD_NEXT, "rpc_service");
}
