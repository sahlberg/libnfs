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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif

#ifdef WIN32
#include "win32_compat.h"
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "slist.h"
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

void rpc_reset_queue(struct rpc_queue *q)
{
	q->head = NULL;
	q->tail = NULL;
}

/*
 * Push to the tail end of the queue
 */
void rpc_enqueue(struct rpc_queue *q, struct rpc_pdu *pdu)
{
	if (q->head == NULL)
		q->head = pdu;
	else
		q->tail->next = pdu;
	q->tail = pdu;
	pdu->next = NULL;
}

/*
 * Push to the front/head of the queue
 */
void rpc_return_to_queue(struct rpc_queue *q, struct rpc_pdu *pdu)
{
	pdu->next = q->head;
	q->head = pdu;
	if (q->tail == NULL)
		q->tail = pdu;
}

unsigned int rpc_hash_xid(uint32_t xid)
{
	return (xid * 7919) % HASHES;
}

struct rpc_pdu *rpc_allocate_pdu(struct rpc_context *rpc, int program, int version, int procedure, rpc_cb cb, void *private_data, zdrproc_t zdr_decode_fn, int zdr_decode_bufsize)
{
	struct rpc_pdu *pdu;
	struct rpc_msg msg;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	pdu = malloc(sizeof(struct rpc_pdu));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate pdu structure");
		return NULL;
	}
	memset(pdu, 0, sizeof(struct rpc_pdu));
	pdu->xid                = rpc->xid++;
	pdu->cb                 = cb;
	pdu->private_data       = private_data;
	pdu->zdr_decode_fn      = zdr_decode_fn;
	pdu->zdr_decode_bufsize = zdr_decode_bufsize;

	zdrmem_create(&pdu->zdr, rpc->encodebuf, rpc->encodebuflen, ZDR_ENCODE);
	if (rpc->is_udp == 0) {
		zdr_setpos(&pdu->zdr, 4); /* skip past the record marker */
	}

	memset(&msg, 0, sizeof(struct rpc_msg));
	msg.xid                = pdu->xid;
        msg.direction          = CALL;
	msg.body.cbody.rpcvers = RPC_MSG_VERSION;
	msg.body.cbody.prog    = program;
	msg.body.cbody.vers    = version;
	msg.body.cbody.proc    = procedure;
	msg.body.cbody.cred    = rpc->auth->ah_cred;
	msg.body.cbody.verf    = rpc->auth->ah_verf;

	if (zdr_callmsg(rpc, &pdu->zdr, &msg) == 0) {
		rpc_set_error(rpc, "zdr_callmsg failed with %s",
			      rpc_get_error(rpc));
		zdr_destroy(&pdu->zdr);
		free(pdu);
		return NULL;
	}

	return pdu;
}

void rpc_free_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (pdu->outdata.data != NULL) {
		free(pdu->outdata.data);
		pdu->outdata.data = NULL;
	}

	if (pdu->zdr_decode_buf != NULL) {
		zdr_free(pdu->zdr_decode_fn, pdu->zdr_decode_buf);
		free(pdu->zdr_decode_buf);
		pdu->zdr_decode_buf = NULL;
	}

	zdr_destroy(&pdu->zdr);

	free(pdu);
}

void rpc_set_next_xid(struct rpc_context *rpc, uint32_t xid)
{
	rpc->xid = xid;
}

int rpc_queue_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
	int size, recordmarker;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	size = zdr_getpos(&pdu->zdr);

	/* for udp we dont queue, we just send it straight away */
	if (rpc->is_udp != 0) {
		unsigned int hash;

// XXX add a rpc->udp_dest_sock_size  and get rid of sys/socket.h and netinet/in.h
		if (sendto(rpc->fd, rpc->encodebuf, size, MSG_DONTWAIT, rpc->udp_dest, sizeof(struct sockaddr_in)) < 0) {
			rpc_set_error(rpc, "Sendto failed with errno %s", strerror(errno));
			rpc_free_pdu(rpc, pdu);
			return -1;
		}

		hash = rpc_hash_xid(pdu->xid);
		rpc_enqueue(&rpc->waitpdu[hash], pdu);
		return 0;
	}

	/* write recordmarker */
	zdr_setpos(&pdu->zdr, 0);
	recordmarker = (size - 4) | 0x80000000;
	zdr_int(&pdu->zdr, &recordmarker);

	pdu->outdata.size = size;
	pdu->outdata.data = malloc(pdu->outdata.size);
	if (pdu->outdata.data == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate buffer for pdu\n");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	memcpy(pdu->outdata.data, rpc->encodebuf, pdu->outdata.size);
	rpc_enqueue(&rpc->outqueue, pdu);

	return 0;
}

int rpc_get_pdu_size(char *buf)
{
	uint32_t size;

	size = ntohl(*(uint32_t *)buf);

	return (size & 0x7fffffff) + 4;
}

static int rpc_process_reply(struct rpc_context *rpc, struct rpc_pdu *pdu, ZDR *zdr)
{
	struct rpc_msg msg;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&msg, 0, sizeof(struct rpc_msg));
	msg.body.rbody.reply.areply.verf = _null_auth;
	if (pdu->zdr_decode_bufsize > 0) {
		if (pdu->zdr_decode_buf != NULL) {
			free(pdu->zdr_decode_buf);
		}
		pdu->zdr_decode_buf = malloc(pdu->zdr_decode_bufsize);
		if (pdu->zdr_decode_buf == NULL) {
			rpc_set_error(rpc, "Failed to allocate memory for "
				      "zdr_encode_buf in rpc_process_reply");
			pdu->cb(rpc, RPC_STATUS_ERROR, "Failed to allocate "
				"buffer for decoding of ZDR reply",
				pdu->private_data);
			return 0;
		}
		memset(pdu->zdr_decode_buf, 0, pdu->zdr_decode_bufsize);
	}
	msg.body.rbody.reply.areply.reply_data.results.where = pdu->zdr_decode_buf;
	msg.body.rbody.reply.areply.reply_data.results.proc  = pdu->zdr_decode_fn;

	if (zdr_replymsg(rpc, zdr, &msg) == 0) {
		rpc_set_error(rpc, "zdr_replymsg failed in rpc_process_reply: "
			      "%s", rpc_get_error(rpc));
		pdu->cb(rpc, RPC_STATUS_ERROR, "Message rejected by server",
			pdu->private_data);
		if (pdu->zdr_decode_buf != NULL) {
			free(pdu->zdr_decode_buf);
			pdu->zdr_decode_buf = NULL;
		}
		return 0;
	}
	if (msg.body.rbody.stat != MSG_ACCEPTED) {
		pdu->cb(rpc, RPC_STATUS_ERROR, "RPC Packet not accepted by the server", pdu->private_data);
		return 0;
	}
	switch (msg.body.rbody.reply.areply.stat) {
	case SUCCESS:
		pdu->cb(rpc, RPC_STATUS_SUCCESS, pdu->zdr_decode_buf, pdu->private_data);
		break;
	case PROG_UNAVAIL:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: Program not available", pdu->private_data);
		break;
	case PROG_MISMATCH:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: Program version mismatch", pdu->private_data);
		break;
	case PROC_UNAVAIL:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: Procedure not available", pdu->private_data);
		break;
	case GARBAGE_ARGS:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: Garbage arguments", pdu->private_data);
		break;
	case SYSTEM_ERR:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Server responded: System Error", pdu->private_data);
		break;
	default:
		pdu->cb(rpc, RPC_STATUS_ERROR, "Unknown rpc response from server", pdu->private_data);
		break;
	}

	return 0;
}

int rpc_process_pdu(struct rpc_context *rpc, char *buf, int size)
{
	struct rpc_pdu *pdu, *prev_pdu;
	struct rpc_queue *q;
	ZDR zdr;
	int pos, recordmarker = 0;
	unsigned int hash;
	uint32_t xid;
	char *reasbuf = NULL;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&zdr, 0, sizeof(ZDR));

	zdrmem_create(&zdr, buf, size, ZDR_DECODE);
	if (rpc->is_udp == 0) {
		if (zdr_int(&zdr, &recordmarker) == 0) {
			rpc_set_error(rpc, "zdr_int reading recordmarker failed");
			zdr_destroy(&zdr);
			return -1;
		}
		if (!(recordmarker&0x80000000)) {
			zdr_destroy(&zdr);
			if (rpc_add_fragment(rpc, buf+4, size-4) != 0) {
				rpc_set_error(rpc, "Failed to queue fragment for reassembly.");
				return -1;
			}
			return 0;
		}
	}

	/* reassembly */
	if (recordmarker != 0 && rpc->fragments != NULL) {
		struct rpc_fragment *fragment;
		uint32_t total = size - 4;
		char *ptr;

		zdr_destroy(&zdr);
		for (fragment = rpc->fragments; fragment; fragment = fragment->next) {
			total += fragment->size;
		}

		reasbuf = malloc(total);
		if (reasbuf == NULL) {
			rpc_set_error(rpc, "Failed to reassemble PDU");
			rpc_free_all_fragments(rpc);
			return -1;
		}
		ptr = reasbuf;
		for (fragment = rpc->fragments; fragment; fragment = fragment->next) {
			memcpy(ptr, fragment->data, fragment->size);
			ptr += fragment->size;
		}
		memcpy(ptr, buf + 4, size - 4);
		zdrmem_create(&zdr, reasbuf, total, ZDR_DECODE);
		rpc_free_all_fragments(rpc);
	}

	pos = zdr_getpos(&zdr);
	if (zdr_int(&zdr, (int *)&xid) == 0) {
		rpc_set_error(rpc, "zdr_int reading xid failed");
		zdr_destroy(&zdr);
		if (reasbuf != NULL) {
			free(reasbuf);
		}
		return -1;
	}
	zdr_setpos(&zdr, pos);

	/* Look up the transaction in a hash table of our requests */
	hash = rpc_hash_xid(xid);
	q = &rpc->waitpdu[hash];

	/* Follow the hash chain.  Linear traverse singly-linked list,
	 * but track previous entry for optimised removal */
	prev_pdu = NULL;
	for (pdu=q->head; pdu; pdu=pdu->next) {
		if (pdu->xid != xid) {
			prev_pdu = pdu;
			continue;
		}
		if (rpc->is_udp == 0 || rpc->is_broadcast == 0) {
			/* Singly-linked but we track head and tail */
			if (pdu == q->head)
				q->head = pdu->next;
			if (pdu == q->tail)
				q->tail = prev_pdu;
			if (prev_pdu != NULL)
				prev_pdu->next = pdu->next;
		}
		if (rpc_process_reply(rpc, pdu, &zdr) != 0) {
			rpc_set_error(rpc, "rpc_procdess_reply failed");
		}
		zdr_destroy(&zdr);
		if (rpc->is_udp == 0 || rpc->is_broadcast == 0) {
			rpc_free_pdu(rpc, pdu);
		}
		if (reasbuf != NULL) {
			free(reasbuf);
		}
		return 0;
	}
	rpc_set_error(rpc, "No matching pdu found for xid:%d", xid);
	zdr_destroy(&zdr);
	if (reasbuf != NULL) {
		free(reasbuf);
	}
	return -1;
}

