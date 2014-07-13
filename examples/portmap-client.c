/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2014
   
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

/* Example program using the lowlevel raw interface.
 * This allow accurate control of the exact commands that are being used.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include "win32_compat.h"
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-raw-portmap.h"
#include "libnfs-raw-rquota.h"

struct client {
       int is_finished;
};

void pmap2_dump_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct pmap2_dump_result *dr = data;
	struct pmap2_mapping_list *list = dr->list;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP2/DUMP call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP2/DUMP call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP2/DUMP:\n");
	while (list) {
		printf("	Prog:%d Vers:%d Protocol:%d Port:%d\n",
			list->map.prog,
			list->map.vers,
			list->map.prot,
			list->map.port);
		list = list->next;
	}
	client->is_finished = 1;
}

void pmap3_dump_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct pmap3_dump_result *dr = data;
	struct pmap3_mapping_list *list = dr->list;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP3/DUMP call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP3/DUMP call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP3/DUMP:\n");
	while (list) {
		printf("	Prog:%d Vers:%d Netid:%s Addr:%s Owner:%s\n",
			list->map.prog,
			list->map.vers,
			list->map.netid,
			list->map.addr,
			list->map.owner);
		list = list->next;
	}
	client->is_finished = 1;
}

void pmap3_getaddr_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct pmap3_string_result *gar = data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP3/GETADDR call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP3/GETADDR call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP3/GETADDR:\n");
	printf("	Addr:%s\n", gar->addr);

	client->is_finished = 1;
}

void pmap3_set_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	uint32_t res = *(uint32_t *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP3/SET call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP3/SET call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP3/SET:\n");
	printf("	Res:%d\n", res);

	client->is_finished = 1;
}

void pmap3_unset_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	uint32_t res = *(uint32_t *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP3/UNSET call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP3/UNSET call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP3/UNSET:\n");
	printf("	Res:%d\n", res);

	client->is_finished = 1;
}

void pmap3_gettime_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	time_t t = *(uint32_t *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP3/GETTIME call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP3/GETTIME call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP3/GETTIME:\n");
	printf("	Time:%d %s\n", (int)t, ctime(&t));

	client->is_finished = 1;
}

void pmap3_uaddr2taddr_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct pmap3_netbuf *nb = data;
	struct sockaddr_storage *ss;
	char host[256], port[6];
	int i;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP3/UADDR2TADDR call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP3/UADDR2TADDR call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP3/UADDR2TADDR:\n");
	printf("	MaxLen:%d\n", nb->maxlen);
	printf("        ");
	for (i = 0; i < nb->maxlen; i++) {
		printf("%02x ", nb->buf.buf_val[i]);
		if (i %16 == 15) {
			printf("\n        ");
		}
	}
	printf("\n");
	printf("        ---\n");
	ss = (struct sockaddr_storage *)&nb->buf.buf_val[0];
	getnameinfo((struct sockaddr *)ss, sizeof(struct sockaddr_storage),
		&host[0], sizeof(host), &port[0], sizeof(port),
		NI_NUMERICHOST|NI_NUMERICSERV);
	switch (ss->ss_family) {
	case AF_INET:
		printf("        IPv4: %s:%s\n", &host[0], &port[0]);
		break;
	case AF_INET6:
		printf("        IPv6: %s:%s\n", &host[0], &port[0]);
		break;
	}
	client->is_finished = 1;
}

void pmap2_null_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP2/NULL call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP2/NULL call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP2/NULL responded and server is alive\n");
	client->is_finished = 1;
}

void pmap3_null_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP3/NULL call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP3/NULL call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP3/NULL responded and server is alive\n");
	client->is_finished = 1;
}

void pmap_null_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP/NULL call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP/NULL call failed, status:%d\n", status);
		exit(10);
	}

	client->is_finished = 1;
}

void pmap_connect_cb(struct rpc_context *rpc, int status, void *data _U_, void *private_data)
{
	struct client *client = private_data;

	if (status != RPC_STATUS_SUCCESS) {
		printf("connection to portmapper failed\n");
		exit(10);
	}

	if (rpc_pmap2_null_async(rpc, pmap_null_cb, client) != 0) {
		printf("Failed to send null request\n");
		exit(10);
	}
}


static void wait_until_finished(struct rpc_context *rpc, struct client *client)
{
	struct pollfd pfd;

	client->is_finished = 0;
	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed");
			exit(10);
		}
		if (rpc_service(rpc, pfd.revents) < 0) {
			printf("rpc_service failed\n");
			break;
		}
		if (client->is_finished) {
			break;
		}
	}
}

int main(int argc _U_, char *argv[] _U_)
{
	struct rpc_context *rpc;
	struct client client;
	char *server = NULL;
	int i;
	int null2 = 0;
	int dump2 = 0;
	int null3 = 0;
	int set3 = 0;
	int unset3 = 0;
	int getaddr3 = 0;
	int dump3 = 0;
	int gettime3 = 0;
	int u2t3 = 0;
	int command_found = 0;

	int set3prog, set3vers;
	char *set3netid, *set3addr, *set3owner;
	int unset3prog, unset3vers;
	char *unset3netid, *unset3addr, *unset3owner;
	int getaddr3prog, getaddr3vers;
	char *getaddr3netid, *getaddr3addr, *getaddr3owner;
	char *u2t3string;

	rpc = rpc_init_context();
	if (rpc == NULL) {
		printf("failed to init context\n");
		exit(10);
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "dump2")) {
			dump2 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "null2")) {
			null2 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "dump3")) {
			dump3 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "gettime3")) {
			gettime3 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "u2t3")) {
			u2t3 = 1;
			u2t3string = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "getaddr3")) {
			getaddr3 = 1;
			getaddr3prog = atoi(argv[++i]);
			getaddr3vers = atoi(argv[++i]);
			getaddr3netid = argv[++i];
			getaddr3addr  = argv[++i];
			getaddr3owner = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "set3")) {
			set3 = 1;
			set3prog = atoi(argv[++i]);
			set3vers = atoi(argv[++i]);
			set3netid = argv[++i];
			set3addr  = argv[++i];
			set3owner = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "null3")) {
			null3 = 1;
			command_found++;
		} else {
			server = argv[i];
		}
	}
	if (command_found == 0 || server == NULL) {
		fprintf(stderr, "Usage: portmap-client <command*> <server>\n");
		exit(10);
	}

	if (rpc_connect_async(rpc, server, 111, pmap_connect_cb, &client) != 0) {
		printf("Failed to start connection\n");
		exit(10);
	}
	wait_until_finished(rpc, &client);

	if (null2) {
		if (rpc_pmap2_null_async(rpc, pmap2_null_cb, &client) != 0) {
			printf("Failed to send NULL2 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (dump2) {
		if (rpc_pmap2_dump_async(rpc, pmap2_dump_cb, &client) != 0) {
			printf("Failed to send DUMP2 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (null3) {
		if (rpc_pmap3_null_async(rpc, pmap3_null_cb, &client) != 0) {
			printf("Failed to send NULL3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (dump3) {
		if (rpc_pmap3_dump_async(rpc, pmap3_dump_cb, &client) != 0) {
			printf("Failed to send DUMP3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (gettime3) {
		if (rpc_pmap3_gettime_async(rpc, pmap3_gettime_cb, &client) != 0) {
			printf("Failed to send GETTIME3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (u2t3) {
		if (rpc_pmap3_uaddr2taddr_async(rpc, u2t3string, pmap3_uaddr2taddr_cb, &client) != 0) {
			printf("Failed to send UADDR2TADDR3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (getaddr3) {
		struct pmap3_mapping map;

		map.prog  = getaddr3prog;
		map.vers  = getaddr3vers;
		map.netid = getaddr3netid;
		map.addr  = getaddr3addr;
		map.owner = getaddr3owner;
		if (rpc_pmap3_getaddr_async(rpc, &map, pmap3_getaddr_cb, &client) != 0) {
			printf("Failed to send GETADDR3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (set3) {
		struct pmap3_mapping map;

		map.prog  = set3prog;
		map.vers  = set3vers;
		map.netid = set3netid;
		map.addr  = set3addr;
		map.owner = set3owner;
		if (rpc_pmap3_set_async(rpc, &map, pmap3_set_cb, &client) != 0) {
			printf("Failed to send SET3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (unset3) {
		struct pmap3_mapping map;

		map.prog  = unset3prog;
		map.vers  = unset3vers;
		map.netid = unset3netid;
		map.addr  = unset3addr;
		map.owner = unset3owner;
		if (rpc_pmap3_unset_async(rpc, &map, pmap3_unset_cb, &client) != 0) {
			printf("Failed to send UNSET3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}

	
	rpc_destroy_context(rpc);
	rpc=NULL;
	return 0;
}
