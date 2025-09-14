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
/*
 * A non-blocking and eventdriven implementation of rpcbind using libnfs.
 * TODO: Call NULL periodically and reap dead services from the database.
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE


#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <talloc.h>
#include <tevent.h>
#include <time.h>
#include <unistd.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-nsm.h"
#include "../libnfs-server.h"


struct statd_state {
        struct tevent_context *tevent;
        struct rpc_context *rpc;
};

static int nsm1_null_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);

        return 0;
}

static int statd_destructor(struct statd_state *statd)
{
        if (statd->rpc) {
                rpc_destroy_context(statd->rpc);
        }
        return 0;
}

int main(int argc, char *argv[])
{
        struct statd_state *statd = talloc(NULL, struct statd_state);
        struct libnfs_servers *servers;
        int rc = 1;

        struct service_proc nsm1_pt[] = {
                {NSM1_NULL, nsm1_null_proc,
                 (zdrproc_t)zdr_void, 0, statd},
#if 0                
                {NSM1_STAT, nsm1_stat_proc,
                 (zdrproc_t)zdr_NSM1_STATargs, sizeof(NSM1_STATargs), statd},
                {NSM1_MON, nsm1_mon_proc,
                 (zdrproc_t)zdr_NSM1_MONargs, sizeof(NSM1_MONargs), statd},
                {NSM1_UNMON, nsm1_unmon_proc,
                 (zdrproc_t)zdr_NSM1_UNMONargs, sizeof(NSM1_UNMONargs), statd},
                {NSM1_UNMONALL, nsm1_unmonall_proc,
                 (zdrproc_t)zdr_NSM1_UNMONALLargs, sizeof(NSM1_UNMONALLargs), statd},
                {NSM1_SIMU_CRASH, nsm1_simu_crash_proc,
                 (zdrproc_t)zdr_void, 0, statd},
                {NSM1_NOTIFY, nsm1_notify_proc,
                 (zdrproc_t)zdr_NSM1_NOTIFYargs, sizeof(NSM1_NOTIFYargs), statd},
#endif                
        };
        struct libnfs_server_procs server_procs[] = {
                { NSM_PROGRAM, NSM_V1, nsm1_pt, sizeof(nsm1_pt) / sizeof(nsm1_pt[0]) },
                { 0, 0, 0, 0}
        };
        
        if (statd == NULL) {
                printf("Failed to talloc statd\n");
                goto out;
        }
        statd->rpc = NULL;
        statd->tevent = tevent_context_init(statd);
        if (statd->tevent == NULL) {
                printf("Failed create tevent context\n");
                goto out;
        }
        talloc_set_destructor(statd, statd_destructor);

#if 0
        statd->rpc = rpc_init_udp_context();
        if (statd->rpc == NULL) {
                printf("Failed to create RPC context for outgoing statd calls\n");
                goto out;
        }
	if (rpc_bind_udp(statd->rpc, "0.0.0.0", 0) < 0) {
                printf("Failed to bind RPC context\n");
                goto out;
	}

        if (tevent_add_fd(statd->tevent, statd, rpc_get_fd(statd->rpc), TEVENT_FD_READ,
                          _callit_io, statd->rpc) == NULL) {
                printf("Failed to create read event for outgoing socket\n");
                goto out;
	}
#endif

        servers = libnfs_create_server(statd, statd->tevent, 0, "libnfs rpc.statd", &server_procs[0]);
        if (servers == NULL) {
                printf("Failed to set set up server\n");
                goto out;
        }
        printf("Ready to serve\n");
        //qqq daemon(0, 1);

        /*
         * Everything is now set up. Start the event loop.
         */
        tevent_loop_wait(statd->tevent);

        rc = 0;
 out:
        talloc_free(statd);
        return rc;
}
