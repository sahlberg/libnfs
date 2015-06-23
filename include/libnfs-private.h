/*
   Copyright (C) 2010 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifndef _LIBNFS_PRIVATE_H_
#define _LIBNFS_PRIVATE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"  /* HAVE_SOCKADDR_STORAGE ? */
#endif

#ifndef WIN32
#include <sys/socket.h>  /* struct sockaddr_storage */
#endif

#include "libnfs-zdr.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(HAVE_SOCKADDR_STORAGE) && !defined(WIN32)
/*
 * RFC 2553: protocol-independent placeholder for socket addresses
 */
#define _SS_MAXSIZE	128
#define _SS_ALIGNSIZE	(sizeof(double))
#define _SS_PAD1SIZE	(_SS_ALIGNSIZE - sizeof(unsigned char) * 2)
#define _SS_PAD2SIZE	(_SS_MAXSIZE - sizeof(unsigned char) * 2 - \
				_SS_PAD1SIZE - _SS_ALIGNSIZE)

struct sockaddr_storage {
#ifdef HAVE_SOCKADDR_LEN
	unsigned char ss_len;		/* address length */
	unsigned char ss_family;	/* address family */
#else
	unsigned short ss_family;
#endif
	char	__ss_pad1[_SS_PAD1SIZE];
	double	__ss_align;	/* force desired structure storage alignment */
	char	__ss_pad2[_SS_PAD2SIZE];
};
#endif


struct rpc_fragment {
	struct rpc_fragment *next;
	uint64_t size;
	char *data;
};

#define RPC_CONTEXT_MAGIC 0xc6e46435
#define RPC_PARAM_UNDEFINED -1

/*
 * Queue is singly-linked but we hold on to the tail
 */
struct rpc_queue {
	struct rpc_pdu *head, *tail;
};

#define HASHES 1024
#define NFS_RA_TIMEOUT 5
#define NFS_MAX_XFER_SIZE (1024 * 1024)

struct rpc_context {
	uint32_t magic;
	int fd;
	int is_connected;

	char *error_string;

	rpc_cb connect_cb;
	void *connect_data;

	struct AUTH *auth;
	uint32_t xid;

	/* buffer used for encoding RPC PDU */
	char *encodebuf;
	int encodebuflen;

	struct rpc_queue outqueue;
	struct sockaddr_storage udp_src;
	struct rpc_queue waitpdu[HASHES];

	uint32_t inpos;
	char *inbuf;
	uint32_t inbuflen;

	/* special fields for UDP, which can sometimes be BROADCASTed */
	int is_udp;
	struct sockaddr *udp_dest;
	int is_broadcast;

	/* track the address we connect to so we can auto-reconnect on session failure */
	struct sockaddr_storage s;
	int auto_reconnect;

	/* fragment reassembly */
	struct rpc_fragment *fragments;

	/* parameters passable via URL */
	int tcp_syncnt;
	int uid;
	int gid;
	uint32_t readahead;
	int debug;
};

struct rpc_pdu {
	struct rpc_pdu *next;

	uint32_t xid;
	ZDR zdr;

	uint32_t written;
	struct rpc_data outdata;

	rpc_cb cb;
	void *private_data;

	/* function to decode the zdr reply data and buffer to decode into */
	zdrproc_t zdr_decode_fn;
	caddr_t zdr_decode_buf;
	uint32_t zdr_decode_bufsize;
};

void rpc_reset_queue(struct rpc_queue *q);
void rpc_enqueue(struct rpc_queue *q, struct rpc_pdu *pdu);
void rpc_return_to_queue(struct rpc_queue *q, struct rpc_pdu *pdu);
unsigned int rpc_hash_xid(uint32_t xid);

struct rpc_pdu *rpc_allocate_pdu(struct rpc_context *rpc, int program, int version, int procedure, rpc_cb cb, void *private_data, zdrproc_t zdr_decode_fn, int zdr_bufsize);
void rpc_free_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu);
int rpc_queue_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu);
int rpc_get_pdu_size(char *buf);
int rpc_process_pdu(struct rpc_context *rpc, char *buf, int size);
void rpc_error_all_pdus(struct rpc_context *rpc, const char *error);

void rpc_set_error(struct rpc_context *rpc, const char *error_string, ...)
#ifdef __GNUC__
 __attribute__((format(printf, 2, 3)))
#endif
;

void nfs_set_error(struct nfs_context *nfs, char *error_string, ...)
#ifdef __GNUC__
 __attribute__((format(printf, 2, 3)))
#endif
;

#define RPC_LOG(rpc, level, format, ...) \
	do { \
		if (level <= rpc->debug) { \
			fprintf(stderr, "libnfs:%d " format "\n", level, ## __VA_ARGS__); \
		} \
	} while (0)

const char *nfs_get_server(struct nfs_context *nfs);
const char *nfs_get_export(struct nfs_context *nfs);

/* we dont want to expose UDP to normal applications/users  this is private to libnfs to use exclusively for broadcast RPC */
int rpc_bind_udp(struct rpc_context *rpc, char *addr, int port);
int rpc_set_udp_destination(struct rpc_context *rpc, char *addr, int port, int is_broadcast);
struct rpc_context *rpc_init_udp_context(void);
struct sockaddr *rpc_get_recv_sockaddr(struct rpc_context *rpc);

void rpc_set_autoreconnect(struct rpc_context *rpc);
void rpc_unset_autoreconnect(struct rpc_context *rpc);

void rpc_set_tcp_syncnt(struct rpc_context *rpc, int v);
void rpc_set_uid(struct rpc_context *rpc, int uid);
void rpc_set_gid(struct rpc_context *rpc, int gid);
void rpc_set_readahead(struct rpc_context *rpc, uint32_t v);
void rpc_set_debug(struct rpc_context *rpc, int level);

int rpc_add_fragment(struct rpc_context *rpc, char *data, uint64_t size);
void rpc_free_all_fragments(struct rpc_context *rpc);

const struct nfs_fh3 *nfs_get_rootfh(struct nfs_context *nfs);

#ifdef __cplusplus
}
#endif

#endif /* !_LIBNFS_PRIVATE_H_ */
