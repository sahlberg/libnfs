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
#include <win32/win32_compat.h>
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <time.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-raw-portmap.h"
#include "libnfs-raw-rquota.h"

struct client {
       int is_finished;
       int gal4prog, gal4vers;
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

void pmap4_dump_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct pmap4_dump_result *dr = data;
	struct pmap4_mapping_list *list = dr->list;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP4/DUMP call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP4/DUMP call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP4/DUMP:\n");
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

void pmap2_set_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	uint32_t res = *(uint32_t *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP2/SET call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP2/SET call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP2/SET:\n");
	printf("	Res:%d\n", res);

	client->is_finished = 1;
}

void pmap2_get_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	uint32_t res = *(uint32_t *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP2/GET call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP2/GET call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP2/GET:\n");
	printf("	Port:%d\n", res);

	client->is_finished = 1;
}

void pmap2_unset_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	uint32_t res = *(uint32_t *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP2/UNSET call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP2/UNSET call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP2/UNSET:\n");
	printf("	Res:%d\n", res);

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

void pmap4_unset_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	uint32_t res = *(uint32_t *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP4/UNSET call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP4/UNSET call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP4/UNSET:\n");
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

void pmap4_gettime_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	time_t t = *(uint32_t *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP4/GETTIME call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP4/GETTIME call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP4/GETTIME:\n");
	printf("	Time:%d %s\n", (int)t, ctime(&t));

	client->is_finished = 1;
}

void pmap4_getstat_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	pmap4_stat_byvers *st = data;
	int v;
	
	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP4/GETTIME call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP4/GETTIME call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP4/GETSTAT:\n");
	for (v = 0; v < 3; v++) {
		int s;
		rpcbs_rmtcalllist_ptr rmt;
		rpcbs_addrlist_ptr adi;

		printf("PORTMAP%d: ", v + 2);
		printf("NULL: %d  ", (*st)[v].info[0]);
		printf("SET: %d/%d  ", (*st)[v].setinfo, (*st)[v].info[1]);
		printf("UNSET: %d/%d  ", (*st)[v].unsetinfo, (*st)[v].info[2]);
		for(s = 0, adi = (*st)[v].addrinfo; adi; adi = adi->next) {
			s += rmt->success;
		}
		printf("GETADDR: %d/%d  ", s, (*st)[v].info[3]);
		printf("DUMP: %d  ", (*st)[v].info[4]);
		for(s = 0, rmt = (*st)[v].rmtinfo; rmt; rmt = rmt->next) {
			s += rmt->success;
		}
		printf("CALLIT: %d/%d  ", s, (*st)[v].info[5]);
		if (v == 0) {
			printf("\n");
			continue;
		}
		printf("TIME: %d  ", (*st)[v].info[6]);
		printf("U2T: %d  ", (*st)[v].info[7]);
		printf("T2U: %d  ", (*st)[v].info[8]);
		if (v == 1) {
			printf("\n");
			continue;
		}
		printf("VERADDR: %d  ", (*st)[v].info[9]);
		printf("INDIRECT: %d  ", (*st)[v].info[10]);
		printf("GETLIST: %d  ", (*st)[v].info[11]);
		printf("GETSTAT: %d  ", (*st)[v].info[12]);
		printf("\n");
	}
	client->is_finished = 1;
}

void pmap4_getaddrlist_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct rpcb_entry_list *el = *(pmap4_entry_list_ptr *)data;
	rpcb_entry *e;
	char *semantics = NULL;
	char *tnc;
	
	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP4/GETTIME call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP4/GETTIME call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP4/GETADDRLIST:\n");
	printf("%10s %4s %20s %20s\n",
	       "program", "vers", "tp_family/name/class", "address");
	while (el) {
		e = &el->rpcb_entry_map;
		switch (e->r_nc_semantics) {
		case NC_TPI_CLTS:
			semantics = "clts";
			break;
		case NC_TPI_COTS:
			semantics = "cots";
			break;
		case NC_TPI_COTS_ORD:
			semantics = "cots_ord";
			break;
		case NC_TPI_RAW:
			semantics = "raw";
			break;
		}
		asprintf(&tnc, "%s/%s/%s", e->r_nc_protofmly, e->r_nc_proto, semantics);
		printf("%10d %4d %20s %20s\n",
		       client->gal4prog, client->gal4vers, tnc, e->r_maddr);
		free(tnc);
		el = el->next;
	}
	
	client->is_finished = 1;
}

void pmap3_taddr2uaddr_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct pmap3_string_result *res = (struct pmap3_string_result *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("PORTMAP3/TADDR2UADDR call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("PORTMAP3/TADDR2UADDR call failed, status:%d\n", status);
		exit(10);
	}

	printf("PORTMAP3/TADDR2UADDR:\n");
	printf("    %s\n", res->addr);

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
	memset(host, 0, sizeof(host));
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

	if (rpc_pmap2_null_task(rpc, pmap_null_cb, client) == NULL) {
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
	int set2 = 0;
	int unset2 = 0;
	int set3 = 0, set4 = 0;
	int unset3 = 0, unset4 = 0;
	int getport2 = 0;
	int getaddr3 = 0, getaddr4 = 0;
	int dump3 = 0, dump4 = 0;
	int gettime3 = 0, gettime4 = 0;
	int u2t3 = 0;
	int t2u3 = 0;
	int getstat4 = 0;
	int getaddrlist4 = 0;
	int command_found = 0;

	PMAP2GETPORTargs get2args;
	PMAP3SETargs set3args;
	PMAP4SETargs set4args;
	PMAP3UNSETargs unset3args;
	PMAP4UNSETargs unset4args;
	PMAP3GETADDRargs getaddr3args;
	PMAP4GETADDRargs getaddr4args;
	int set2prog, set2vers, set2prot, set2port;
	int unset2prog, unset2vers, unset2prot, unset2port;
	char *u2t3string;

#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		exit(10);
	}
#endif

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
		} else if (!strcmp(argv[i], "set2")) {
			set2 = 1;
			set2prog = atoi(argv[++i]);
			set2vers = atoi(argv[++i]);
			set2prot = atoi(argv[++i]);
			set2port = atoi(argv[++i]);
			command_found++;
		} else if (!strcmp(argv[i], "unset2")) {
			unset2 = 1;
			unset2prog = atoi(argv[++i]);
			unset2vers = atoi(argv[++i]);
			unset2prot = atoi(argv[++i]);
			unset2port = atoi(argv[++i]);
			command_found++;
		} else if (!strcmp(argv[i], "getport2")) {
			getport2 = 1;
			get2args.prog = atoi(argv[++i]);
			get2args.vers = atoi(argv[++i]);
			i++;
			if (!strcmp(argv[i], "tcp")) {
				get2args.prot = 6;
			} else if (!strcmp(argv[i], "udp")) {
				get2args.prot = 17;
			} else {
				get2args.prot = atoi(argv[i]);
			}
			command_found++;
		} else if (!strcmp(argv[i], "dump3")) {
			dump3 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "dump4")) {
			dump4 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "gettime3")) {
			gettime3 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "gettime4")) {
			gettime4 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "u2t3")) {
			u2t3 = 1;
			u2t3string = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "t2u3")) {
			t2u3 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "getaddr3")) {
			getaddr3 = 1;
			getaddr3args.prog = atoi(argv[++i]);
			getaddr3args.vers = atoi(argv[++i]);
			getaddr3args.netid = argv[++i];
			getaddr3args.addr  = argv[++i];
			getaddr3args.owner = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "getaddr4")) {
			getaddr4 = 1;
			getaddr4args.prog = atoi(argv[++i]);
			getaddr4args.vers = atoi(argv[++i]);
			getaddr4args.netid = argv[++i];
			getaddr4args.addr  = argv[++i];
			getaddr4args.owner = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "set3")) {
			set3 = 1;
			set3args.prog = atoi(argv[++i]);
			set3args.vers = atoi(argv[++i]);
			set3args.netid = argv[++i];
			set3args.addr  = argv[++i];
			set3args.owner = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "set4")) {
			set4 = 1;
			set4args.prog = atoi(argv[++i]);
			set4args.vers = atoi(argv[++i]);
			set4args.netid = argv[++i];
			set4args.addr  = argv[++i];
			set4args.owner = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "null3")) {
			null3 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "unset3")) {
			unset3 = 1;
			unset3args.prog = atoi(argv[++i]);
			unset3args.vers = atoi(argv[++i]);
			unset3args.netid = argv[++i];
			unset3args.addr = argv[++i];
			unset3args.owner = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "unset4")) {
			unset4 = 1;
			unset4args.prog = atoi(argv[++i]);
			unset4args.vers = atoi(argv[++i]);
			unset4args.netid = argv[++i];
			unset4args.addr = argv[++i];
			unset4args.owner = argv[++i];
			command_found++;
		} else if (!strcmp(argv[i], "getstat4")) {
			getstat4 = 1;
			command_found++;
		} else if (!strcmp(argv[i], "getaddrlist4")) {
			getaddrlist4 = 1;
			client.gal4prog = atoi(argv[++i]);
			client.gal4vers = atoi(argv[++i]);
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

	if (dump4) {
		if (rpc_pmap4_dump_task(rpc, pmap4_dump_cb, &client) == NULL) {
			printf("Failed to send DUMP4 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (null2) {
		if (rpc_pmap2_null_task(rpc, pmap2_null_cb, &client) == NULL) {
			printf("Failed to send NULL2 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (dump2) {
		if (rpc_pmap2_dump_task(rpc, pmap2_dump_cb, &client) == NULL) {
			printf("Failed to send DUMP2 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (null3) {
		if (rpc_pmap3_null_task(rpc, pmap3_null_cb, &client) == NULL) {
			printf("Failed to send NULL3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (dump3) {
		if (rpc_pmap3_dump_task(rpc, pmap3_dump_cb, &client) == NULL) {
			printf("Failed to send DUMP3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (gettime3) {
		if (rpc_pmap3_gettime_task(rpc, pmap3_gettime_cb, &client) == NULL) {
			printf("Failed to send GETTIME3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (gettime4) {
		if (rpc_pmap4_gettime_task(rpc, pmap4_gettime_cb, &client) == NULL) {
			printf("Failed to send GETTIME4 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (getstat4) {
		if (rpc_pmap4_getstat_task(rpc, pmap4_getstat_cb, &client) == NULL) {
			printf("Failed to send GETSTAT4 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (u2t3) {
		if (rpc_pmap3_uaddr2taddr_task(rpc, u2t3string, pmap3_uaddr2taddr_cb, &client) == NULL) {
			printf("Failed to send UADDR2TADDR3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (t2u3) {
		struct sockaddr_storage ss;
		socklen_t ss_len = sizeof(struct sockaddr_storage);
		PMAP3TADDR2UADDRargs t2u3args;
		
		if (getsockname(rpc_get_fd(rpc), (struct sockaddr *)&ss, &ss_len)) {
			printf("Failed to get socket name for rpc context\n");
			exit(10);
		}
		t2u3args.maxlen = ss_len;
		t2u3args.buf.buf_len = ss_len;
		t2u3args.buf.buf_val = (char *)&ss;
		if (rpc_pmap3_taddr2uaddr_task(rpc, &t2u3args, pmap3_taddr2uaddr_cb, &client) == NULL) {
			printf("Failed to send TADDR2UADDR3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (getaddr3) {
		if (rpc_pmap3_getaddr_task(rpc, &getaddr3args, pmap3_getaddr_cb, &client) == NULL) {
			printf("Failed to send GETADDR3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (getaddr4) {
		if (rpc_pmap4_getaddr_task(rpc, &getaddr4args, pmap3_getaddr_cb, &client) == NULL) {
			printf("Failed to send GETADDR4 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (set2) {
		if (rpc_pmap2_set_task(rpc, set2prog, set2vers, set2prot, set2port, pmap2_set_cb, &client) == NULL) {
			printf("Failed to send SET2 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (unset2) {
		if (rpc_pmap2_unset_task(rpc, unset2prog, unset2vers, unset2prot, unset2port, pmap2_unset_cb, &client) == NULL) {
			printf("Failed to send UNSET2 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (getport2) {
		if (rpc_pmap2_getport_task(rpc, get2args.prog, get2args.vers, get2args.prot, pmap2_get_cb, &client) == NULL) {
			printf("Failed to send GETPORT2 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (set3) {
		if (rpc_pmap3_set_task(rpc, &set3args, pmap3_set_cb, &client) == NULL) {
			printf("Failed to send SET3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (unset3) {
		if (rpc_pmap3_unset_task(rpc, &unset3args, pmap3_unset_cb, &client) == NULL) {
			printf("Failed to send UNSET3 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (set4) {
		if (rpc_pmap4_set_task(rpc, &set4args, pmap3_set_cb, &client) == NULL) {
			printf("Failed to send SET4 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (unset4) {
		if (rpc_pmap4_unset_task(rpc, &unset4args, pmap4_unset_cb, &client) == NULL) {
			printf("Failed to send UNSET4 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}
	if (getaddrlist4) {
		struct pmap4_mapping map;

		map.prog  = client.gal4prog;
		map.vers  = client.gal4vers;
		map.netid = "";
		map.addr  = "";
		map.owner = "";
		if (rpc_pmap4_getaddrlist_task(rpc, &map, pmap4_getaddrlist_cb, &client) == NULL) {
			printf("Failed to send GETADDRLIST4 request\n");
			exit(10);
		}
		wait_until_finished(rpc, &client);
	}

	
	rpc_destroy_context(rpc);
	rpc=NULL;
	return 0;
}
