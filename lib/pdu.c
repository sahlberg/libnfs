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

#define PAD_TO_8_BYTES(x) ((x + 0x07) & ~0x07)

static struct rpc_pdu *rpc_allocate_reply_pdu(struct rpc_context *rpc,
                                              struct rpc_msg *res,
                                              size_t alloc_hint)
{
	struct rpc_pdu *pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	pdu = malloc(sizeof(struct rpc_pdu));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate pdu structure");
		return NULL;
	}
	memset(pdu, 0, sizeof(struct rpc_pdu));
        pdu->flags              = PDU_DISCARD_AFTER_SENDING;
	pdu->xid                = 0;
	pdu->cb                 = NULL;
	pdu->private_data       = NULL;
	pdu->zdr_decode_fn      = NULL;
	pdu->zdr_decode_bufsize = 0;

	pdu->outdata.data = malloc(ZDR_ENCODEBUF_MINSIZE + alloc_hint);
	if (pdu->outdata.data == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate encode buffer");
		free(pdu);
		return NULL;
	}

        /* Add an iovector for the record marker. Ignored for UDP */
        rpc_add_iovector(rpc, &pdu->out, pdu->outdata.data, 4, NULL);

	zdrmem_create(&pdu->zdr, &pdu->outdata.data[4],
                      ZDR_ENCODEBUF_MINSIZE + alloc_hint, ZDR_ENCODE);

	if (zdr_replymsg(rpc, &pdu->zdr, res) == 0) {
		rpc_set_error(rpc, "zdr_replymsg failed with %s",
			      rpc_get_error(rpc));
		zdr_destroy(&pdu->zdr);
		free(pdu->outdata.data);
		free(pdu);
		return NULL;
	}

        /* Add an iovector for the header */
        rpc_add_iovector(rpc, &pdu->out, &pdu->outdata.data[4],
                         zdr_getpos(&pdu->zdr), NULL);

	return pdu;
}

struct rpc_pdu *rpc_allocate_pdu2(struct rpc_context *rpc, int program, int version, int procedure, rpc_cb cb, void *private_data, zdrproc_t zdr_decode_fn, int zdr_decode_bufsize, size_t alloc_hint)
{
	struct rpc_pdu *pdu;
	struct rpc_msg msg;
	int pdu_size;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Since we already know how much buffer we need for the decoding
	 * we can just piggyback in the same alloc as for the pdu.
	 */
	pdu_size = PAD_TO_8_BYTES(sizeof(struct rpc_pdu));
	pdu_size += PAD_TO_8_BYTES(zdr_decode_bufsize);

	pdu = malloc(pdu_size);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate pdu structure");
		return NULL;
	}
	memset(pdu, 0, pdu_size);
	pdu->xid                = rpc->xid++;
	pdu->cb                 = cb;
	pdu->private_data       = private_data;
	pdu->zdr_decode_fn      = zdr_decode_fn;
	pdu->zdr_decode_bufsize = zdr_decode_bufsize;

	pdu->outdata.data = malloc(ZDR_ENCODEBUF_MINSIZE + alloc_hint);
	if (pdu->outdata.data == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate encode buffer");
		free(pdu);
		return NULL;
	}

        /* Add an iovector for the record marker. Ignored for UDP */
        rpc_add_iovector(rpc, &pdu->out, pdu->outdata.data, 4, NULL);

        zdrmem_create(&pdu->zdr, &pdu->outdata.data[4],
                      ZDR_ENCODEBUF_MINSIZE + alloc_hint, ZDR_ENCODE);

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
		free(pdu->outdata.data);
		free(pdu);
		return NULL;
	}

        /* Add an iovector for the header */
        rpc_add_iovector(rpc, &pdu->out, &pdu->outdata.data[4],
                         zdr_getpos(&pdu->zdr), NULL);

	return pdu;
}

struct rpc_pdu *rpc_allocate_pdu(struct rpc_context *rpc, int program, int version, int procedure, rpc_cb cb, void *private_data, zdrproc_t zdr_decode_fn, int zdr_decode_bufsize)
{
	return rpc_allocate_pdu2(rpc, program, version, procedure, cb, private_data, zdr_decode_fn, zdr_decode_bufsize, 0);
}

void rpc_free_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	free(pdu->outdata.data);
        rpc_free_iovector(rpc, &pdu->out);

	if (pdu->zdr_decode_buf != NULL) {
		zdr_free(pdu->zdr_decode_fn, pdu->zdr_decode_buf);
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
	int i, size = 0, pos = zdr_getpos(&pdu->zdr);
        uint32_t recordmarker;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

        for (i = 1; i < pdu->out.niov; i++) {
                size += pdu->out.iov[i].len;
        }
        pdu->out.total_size = size + 4;

        /* If we need to add any additional iovectors
         *
         * We expect to almost always add an iovector here for the remainder
         * of the outdata marshalling buffer.
         * The exception is WRITE where we add an explicit iovector instead
         * of marshalling it in ZDR. This so that we can do zero-copy for
         * the WRITE path.
         */
        if (pos > size) {
                int count = pos - size;

                rpc_add_iovector(rpc, &pdu->out,
                                 &pdu->outdata.data[pdu->out.total_size],
                                 count, NULL);
                pdu->out.total_size += count;
                size = pos;
        }

	/* write recordmarker */
        recordmarker = htonl(size | 0x80000000);
	memcpy(pdu->out.iov[0].buf, &recordmarker, 4);

	/* for udp we dont queue, we just send it straight away */
	if (rpc->is_udp != 0) {
		unsigned int hash;

                if (rpc->is_broadcast) {
                        if (sendto(rpc->fd, pdu->zdr.buf, size, MSG_DONTWAIT,
                                   (struct sockaddr *)&rpc->udp_dest,
                                   sizeof(rpc->udp_dest)) < 0) {
                                rpc_set_error(rpc, "Sendto failed with errno %s", strerror(errno));
                                rpc_free_pdu(rpc, pdu);
                                return -1;
                        }
                } else {
                        struct iovec iov[RPC_MAX_VECTORS];
                        int niov = pdu->out.niov;

                        for (i = 0; i < niov; i++) {
                                iov[i].iov_base = pdu->out.iov[i].buf;
                                iov[i].iov_len = pdu->out.iov[i].len;
                        }
                        if (writev(rpc->fd, &iov[1], niov - 1) < 0) {
                                rpc_set_error(rpc, "Sendto failed with errno %s", strerror(errno));
                                rpc_free_pdu(rpc, pdu);
                                return -1;
                        }
                }

		hash = rpc_hash_xid(pdu->xid);
		rpc_enqueue(&rpc->waitpdu[hash], pdu);
		rpc->waitpdu_len++;
		return 0;
	}

	pdu->outdata.size = size;
	rpc_enqueue(&rpc->outqueue, pdu);

	return 0;
}

uint32_t rpc_get_pdu_size(char *buf)
{
	uint32_t size;

	size = ntohl(*(uint32_t *)(void *)buf);

	return (size & 0x7fffffff) + 4;
}

static int rpc_process_reply(struct rpc_context *rpc, struct rpc_pdu *pdu, ZDR *zdr)
{
	struct rpc_msg msg;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&msg, 0, sizeof(struct rpc_msg));
	msg.body.rbody.reply.areply.verf = _null_auth;
	if (pdu->zdr_decode_bufsize > 0) {
		pdu->zdr_decode_buf = (char *)pdu + PAD_TO_8_BYTES(sizeof(struct rpc_pdu));
	}
	msg.body.rbody.reply.areply.reply_data.results.where = pdu->zdr_decode_buf;
	msg.body.rbody.reply.areply.reply_data.results.proc  = pdu->zdr_decode_fn;
	if (zdr_replymsg(rpc, zdr, &msg) == 0) {
		rpc_set_error(rpc, "zdr_replymsg failed in rpc_process_reply: "
			      "%s", rpc_get_error(rpc));
		pdu->cb(rpc, RPC_STATUS_ERROR, "Message rejected by server",
			pdu->private_data);
		if (pdu->zdr_decode_buf != NULL) {
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

static int rpc_send_error_reply(struct rpc_context *rpc,
                                struct rpc_msg *call,
                                enum accept_stat err,
                                int min_vers, int max_vers)
{
        struct rpc_pdu *pdu;
        struct rpc_msg res;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&res, 0, sizeof(struct rpc_msg));
	res.xid                                      = call->xid;
        res.direction                                = REPLY;
        res.body.rbody.stat                          = MSG_ACCEPTED;
        res.body.rbody.reply.areply.reply_data.mismatch_info.low  = min_vers;
        res.body.rbody.reply.areply.reply_data.mismatch_info.high = max_vers;
	res.body.rbody.reply.areply.verf             = _null_auth;
	res.body.rbody.reply.areply.stat             = err;

        if (rpc->is_udp) {
                /* send the reply back to the client */
                memcpy(&rpc->udp_dest, &rpc->udp_src, sizeof(rpc->udp_dest));
        }

        pdu  = rpc_allocate_reply_pdu(rpc, &res, 0);
        if (pdu == NULL) {
                rpc_set_error(rpc, "Failed to send error_reply: %s",
                              rpc_get_error(rpc));
                return -1;
        }
        rpc_queue_pdu(rpc, pdu);

        return 0;
}

int rpc_send_reply(struct rpc_context *rpc,
                   struct rpc_msg *call,
                   void *reply,
                   zdrproc_t encode_fn,
                   int alloc_hint)
{
        struct rpc_pdu *pdu;
        struct rpc_msg res;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&res, 0, sizeof(struct rpc_msg));
	res.xid                                      = call->xid;
        res.direction                                = REPLY;
        res.body.rbody.stat                          = MSG_ACCEPTED;
	res.body.rbody.reply.areply.verf             = _null_auth;
	res.body.rbody.reply.areply.stat             = SUCCESS;

        res.body.rbody.reply.areply.reply_data.results.where = reply;
	res.body.rbody.reply.areply.reply_data.results.proc  = encode_fn;

        if (rpc->is_udp) {
                /* send the reply back to the client */
                memcpy(&rpc->udp_dest, &rpc->udp_src, sizeof(rpc->udp_dest));
        }

        pdu  = rpc_allocate_reply_pdu(rpc, &res, alloc_hint);
        if (pdu == NULL) {
                rpc_set_error(rpc, "Failed to send error_reply: %s",
                              rpc_get_error(rpc));
                return -1;
        }
        rpc_queue_pdu(rpc, pdu);

        return 0;
}

static int rpc_process_call(struct rpc_context *rpc, ZDR *zdr)
{
	struct rpc_msg call;
        struct rpc_endpoint *endpoint;
        int i, min_version = 0, max_version = 0, found_program = 0;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&call, 0, sizeof(struct rpc_msg));
	if (zdr_callmsg(rpc, zdr, &call) == 0) {
		rpc_set_error(rpc, "Failed to decode CALL message. %s",
                              rpc_get_error(rpc));
                return rpc_send_error_reply(rpc, &call, GARBAGE_ARGS, 0, 0);
        }
        for (endpoint = rpc->endpoints; endpoint; endpoint = endpoint->next) {
                if (call.body.cbody.prog == endpoint->program) {
                        if (!found_program) {
                                min_version = max_version = endpoint->version;
                        }
                        if (endpoint->version < min_version) {
                                min_version = endpoint->version;
                        }
                        if (endpoint->version > max_version) {
                                max_version = endpoint->version;
                        }
                        found_program = 1;
                        if (call.body.cbody.vers == endpoint->version) {
                                break;
                        }
                }
        }
        if (endpoint == NULL) {
		rpc_set_error(rpc, "No endpoint found for CALL "
                              "program:0x%08x version:%d\n",
                              call.body.cbody.prog, call.body.cbody.vers);
                if (!found_program) {
                        return rpc_send_error_reply(rpc, &call, PROG_UNAVAIL,
                                                    0, 0);
                }
                return rpc_send_error_reply(rpc, &call, PROG_MISMATCH,
                                            min_version, max_version);
        }
        for (i = 0; i < endpoint->num_procs; i++) {
                if (endpoint->procs[i].proc == call.body.cbody.proc) {
                        if (endpoint->procs[i].decode_buf_size) {
                                call.body.cbody.args = zdr_malloc(zdr, endpoint->procs[i].decode_buf_size);
                        }
                        if (!endpoint->procs[i].decode_fn(zdr, call.body.cbody.args)) {
                                rpc_set_error(rpc, "Failed to unmarshall "
                                              "call payload");
                                return rpc_send_error_reply(rpc, &call, GARBAGE_ARGS, 0 ,0);
                        }
                        return endpoint->procs[i].func(rpc, &call);
                }
        }

        return rpc_send_error_reply(rpc, &call, PROC_UNAVAIL, 0 ,0);
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

        if (rpc->is_server_context) {
                int ret;

                ret = rpc_process_call(rpc, &zdr);
                zdr_destroy(&zdr);
                if (reasbuf != NULL) {
                        free(reasbuf);
                }
                return ret;
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
			rpc->waitpdu_len--;
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

