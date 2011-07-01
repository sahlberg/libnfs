/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2011
   
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

/* Example program using the lowlevel raw broadcast interface.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-portmap.h"
#include "libnfs-private.h"

void pm_cb(struct rpc_context *rpc _U_, int status, void *data, void *private_data _U_)
{
	pmap_call_result *res = (pmap_call_result *)data;
	struct sockaddr *sin;
	char hostdd[16];

	if (status != 0) {
		printf("callback for CALLIT failed\n");
		exit(10);
	}

	sin = rpc_get_recv_sockaddr(rpc);
	if (sin == NULL) {
		printf("failed to get sockaddr for received pdu\n");
		exit(10);
	}

	if (getnameinfo(sin, sizeof(struct sockaddr_in), &hostdd[0], sizeof(hostdd), NULL, 0, NI_NUMERICHOST) < 0) {
		printf("getnameinfo failed\n");
		exit(10);
	}

	printf("NFS server at %s\n", hostdd);
}

int main(int argc _U_, char *argv[] _U_)
{
	struct rpc_context *rpc;
	struct pollfd pfd;
	
	rpc = rpc_init_udp_context();
	if (rpc == NULL) {
		printf("failed to init context\n");
		exit(10);
	}

	if (rpc_bind_udp(rpc, "0.0.0.0", 0) < 0) {
		printf("failed to bind to udp %s\n", rpc_get_error(rpc));
		exit(10);
	}

	if (rpc_set_udp_destination(rpc, "10.1.1.255", 111, 1) < 0) {
		printf("failed to set udp destination %s\n", rpc_get_error(rpc));
		exit(10);
	}

	if (rpc_pmap_callit_async(rpc, 100005, 2, 0, NULL, 0, pm_cb, NULL) < 0) {
		printf("Failed to set up callit function\n");
		exit(10);
	}
	if (rpc_set_udp_destination(rpc, "10.9.2.255", 111, 1) < 0) {
		printf("failed to set udp destination %s\n", rpc_get_error(rpc));
		exit(10);
	}

	if (rpc_pmap_callit_async(rpc, 100005, 2, 0, NULL, 0, pm_cb, NULL) < 0) {
		printf("Failed to set up callit function\n");
		exit(10);
	}

	alarm(3);

	for(;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed");
			exit(10);
		}
		if (rpc_service(rpc, pfd.revents) < 0) {
			printf("rpc_service failed with %s\n", rpc_get_error(rpc));
			break;
		}
	}
	
	rpc_destroy_context(rpc);
	rpc=NULL;
	printf("nfsclient finished\n");
	return 0;
}
