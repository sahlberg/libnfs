/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
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

#ifdef PS2_EE
#include "ps2_compat.h"
#endif

#ifdef PS3_PPU
#include "ps3_compat.h"
#endif

#ifdef WIN32
#include <win32/win32_compat.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if defined(HAVE_SYS_UIO_H) || (defined(__APPLE__) && defined(__MACH__))
#include <sys/uio.h>
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

#ifdef HAVE_LIBKRB5
#include "krb5-wrapper.h"
#endif

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

unsigned int rpc_hash_xid(struct rpc_context *rpc, uint32_t xid)
{
	return (xid * 7919) % rpc->num_hashes;
}

#define PAD_TO_8_BYTES(x) ((x + 0x07) & ~0x07)

static struct rpc_pdu *rpc_allocate_reply_pdu(struct rpc_context *rpc,
                                              struct rpc_msg *res,
                                              size_t alloc_hint)
{
	struct rpc_pdu *pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	pdu = malloc(sizeof(struct rpc_pdu) + ZDR_ENCODEBUF_MINSIZE + alloc_hint);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate pdu structure and encode buffer");
		return NULL;
	}
	memset(pdu, 0, sizeof(struct rpc_pdu));
        pdu->flags              = PDU_DISCARD_AFTER_SENDING;
	pdu->xid                = 0;
	pdu->cb                 = NULL;
	pdu->private_data       = NULL;
	pdu->zdr_decode_fn      = NULL;
	pdu->zdr_decode_bufsize = 0;

	pdu->outdata.data = (char *)(pdu + 1);

        /* Add an iovector for the record marker. Ignored for UDP */
        rpc_add_iovector(rpc, &pdu->out, pdu->outdata.data, 4, NULL);

	zdrmem_create(&pdu->zdr, &pdu->outdata.data[4],
                      ZDR_ENCODEBUF_MINSIZE + alloc_hint, ZDR_ENCODE);

	if (zdr_replymsg(rpc, &pdu->zdr, res) == 0) {
		rpc_set_error(rpc, "zdr_replymsg failed with %s",
			      rpc_get_error(rpc));
		zdr_destroy(&pdu->zdr);
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
#ifdef HAVE_LIBKRB5
        uint32_t val;
#endif

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Since we already know how much buffer we need for the decoding
	 * we can just piggyback in the same alloc as for the pdu.
	 */
	pdu_size = PAD_TO_8_BYTES(sizeof(struct rpc_pdu));
	pdu_size += PAD_TO_8_BYTES(zdr_decode_bufsize);

	pdu = malloc(pdu_size + ZDR_ENCODEBUF_MINSIZE + alloc_hint);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory: Failed to allocate pdu structure and encode buffer");
		return NULL;
	}
	memset(pdu, 0, pdu_size);
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	pdu->xid                = rpc->xid++;
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	pdu->cb                 = cb;
	pdu->private_data       = private_data;
	pdu->zdr_decode_fn      = zdr_decode_fn;
	pdu->zdr_decode_bufsize = zdr_decode_bufsize;

	pdu->outdata.data = ((char *)pdu + pdu_size);

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
#ifdef HAVE_LIBKRB5
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
        if (rpc->sec != RPC_SEC_UNDEFINED) {
                ZDR tmpzdr;
                int level = RPC_GSS_SVC_NONE;

                pdu->gss_seqno = rpc->gss_seqno;

                zdrmem_create(&tmpzdr, pdu->creds, 64, ZDR_ENCODE);
                switch (rpc->sec) {
                case RPC_SEC_UNDEFINED:
                        break;
                case RPC_SEC_KRB5:
                        level = RPC_GSS_SVC_NONE;
                        break;
                case RPC_SEC_KRB5I:
                        if (pdu->gss_seqno > 0) {
                                level = RPC_GSS_SVC_INTEGRITY;
                        }
                        break;
                case RPC_SEC_KRB5P:
                        if (pdu->gss_seqno > 0) {
                                level = RPC_GSS_SVC_PRIVACY;
                        }
                        break;
                }
                if (libnfs_authgss_gen_creds(rpc, &tmpzdr, level) < 0) {
                        zdr_destroy(&tmpzdr);
                        rpc_set_error(rpc, "zdr_callmsg failed with %s",
                                      rpc_get_error(rpc));
                        goto failed;
                }
                msg.body.cbody.cred.oa_flavor = AUTH_GSS;
                msg.body.cbody.cred.oa_length = tmpzdr.pos;
                msg.body.cbody.cred.oa_base = pdu->creds;
                zdr_destroy(&tmpzdr);

                rpc->gss_seqno++;
                if (rpc->gss_seqno > 1) {
                        msg.body.cbody.verf.oa_flavor = AUTH_GSS;
                        msg.body.cbody.verf.gss_context = rpc->gss_context;
                }
        }
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
#endif /* HAVE_LIBKRB5 */

	if (zdr_callmsg(rpc, &pdu->zdr, &msg) == 0) {
		rpc_set_error(rpc, "zdr_callmsg failed with %s",
			      rpc_get_error(rpc));
                goto failed;
	}
        
#ifdef HAVE_LIBKRB5
        switch (rpc->sec) {
        case RPC_SEC_UNDEFINED:
        case RPC_SEC_KRB5:
                break;
        case RPC_SEC_KRB5P:
        case RPC_SEC_KRB5I:
                if (pdu->gss_seqno > 0) {
                        pdu->start_of_payload = zdr_getpos(&pdu->zdr);
                        val = 0; /* dummy length, will fill in below once we know */
                        if (!libnfs_zdr_u_int(&pdu->zdr, &val)) {
                                goto failed;
                       }
                        val = pdu->gss_seqno;
                        if (!libnfs_zdr_u_int(&pdu->zdr, &val)) {
                                goto failed;
                        }
                }
                break;
        }
#endif /* HAVE_LIBKRB5 */

        /* Add an iovector for the header */
        rpc_add_iovector(rpc, &pdu->out, &pdu->outdata.data[4],
                         zdr_getpos(&pdu->zdr), NULL);

	return pdu;
 failed:
        rpc_set_error(rpc, "zdr_callmsg failed with %s",
                      rpc_get_error(rpc));
        zdr_destroy(&pdu->zdr);
        free(pdu);
        return NULL;
}

struct rpc_pdu *rpc_allocate_pdu(struct rpc_context *rpc, int program, int version, int procedure, rpc_cb cb, void *private_data, zdrproc_t zdr_decode_fn, int zdr_decode_bufsize)
{
	return rpc_allocate_pdu2(rpc, program, version, procedure, cb, private_data, zdr_decode_fn, zdr_decode_bufsize, 0);
}

void rpc_free_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        uint32_t min;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (pdu->zdr_decode_buf != NULL) {
		zdr_free(pdu->zdr_decode_fn, pdu->zdr_decode_buf);
	}

        gss_release_buffer(&min, &pdu->output_buffer);
	zdr_destroy(&pdu->zdr);

        rpc_free_iovector(rpc, &pdu->out);
	free(pdu);
}

void rpc_set_next_xid(struct rpc_context *rpc, uint32_t xid)
{
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	rpc->xid = xid;
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
}

int rpc_queue_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
	int i, size = 0, pos;
        uint32_t recordmarker;
#ifdef HAVE_LIBKRB5
        uint32_t maj, min, val, len;
        gss_buffer_desc message_buffer, output_token;
        char *buf;
#endif /* HAVE_LIBKRB5 */

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

#ifdef HAVE_LIBKRB5
        switch (rpc->sec) {
        case RPC_SEC_UNDEFINED:
        case RPC_SEC_KRB5:
                break;
        case RPC_SEC_KRB5I:
                if (pdu->gss_seqno == 0) {
                        break;
                }
                pos = zdr_getpos(&pdu->zdr);
                zdr_setpos(&pdu->zdr, pdu->start_of_payload);
                val = pos - pdu->start_of_payload - 4;
                if (!libnfs_zdr_u_int(&pdu->zdr, &val)) {
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                zdr_setpos(&pdu->zdr, pos);
                        
                /* checksum */
                message_buffer.length = zdr_getpos(&pdu->zdr) - pdu->start_of_payload - 4;
                message_buffer.value = zdr_getptr(&pdu->zdr) + pdu->start_of_payload + 4;
                maj = gss_get_mic(&min, rpc->gss_context,
                                  GSS_C_QOP_DEFAULT,
                                  &message_buffer,
                                  &output_token);
                if (maj != GSS_S_COMPLETE) {
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                buf = output_token.value;
                len = output_token.length;
                if (!libnfs_zdr_bytes(&pdu->zdr, &buf, &len, len)) {
                        gss_release_buffer(&min, &output_token);
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                gss_release_buffer(&min, &output_token);
                break;
        case RPC_SEC_KRB5P:
                if (pdu->gss_seqno == 0) {
                        break;
                }
                pos = zdr_getpos(&pdu->zdr);
                message_buffer.length = zdr_getpos(&pdu->zdr) - pdu->start_of_payload - 4;
                message_buffer.value = zdr_getptr(&pdu->zdr) + pdu->start_of_payload + 4;
                maj = gss_wrap (&min, rpc->gss_context, 1,
                                GSS_C_QOP_DEFAULT,
                                &message_buffer,
                                NULL,
                                &output_token);
                if (maj != GSS_S_COMPLETE) {
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                zdr_setpos(&pdu->zdr, pdu->start_of_payload);
                buf = output_token.value;
                len = output_token.length;
                if (!libnfs_zdr_bytes(&pdu->zdr, &buf, &len, len)) {
                        gss_release_buffer(&min, &output_token);
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
                gss_release_buffer(&min, &output_token);
                break;
        }
#endif /* HAVE_LIBKRB5 */

        pos = zdr_getpos(&pdu->zdr);
	if (rpc->timeout > 0) {
		pdu->timeout = rpc_current_time() + rpc->timeout;
#ifndef HAVE_CLOCK_GETTIME
		/* If we do not have GETTIME we fallback to time() which
		 * has 1s granularity for its timestamps.
		 * We thus need to bump the timeout by 1000ms
		 * so that the PDU will timeout within 1.0 - 2.0 seconds.
		 * Otherwise setting a 1s timeout would trigger within
		 * 0.001 - 1.0s.
		 */
		pdu->timeout += 1000;
#endif
	} else {
		pdu->timeout = 0;
	}

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

                if (rpc_add_iovector(rpc, &pdu->out,
                                     &pdu->outdata.data[pdu->out.total_size],
                                     count, NULL) < 0) {
                        rpc_free_pdu(rpc, pdu);
                        return -1;
                }
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

		hash = rpc_hash_xid(rpc, pdu->xid);
#ifdef HAVE_MULTITHREADING
                if (rpc->multithreading_enabled) {
                        nfs_mt_mutex_lock(&rpc->rpc_mutex);
                }
#endif /* HAVE_MULTITHREADING */
		rpc_enqueue(&rpc->waitpdu[hash], pdu);
		rpc->waitpdu_len++;
#ifdef HAVE_MULTITHREADING
                if (rpc->multithreading_enabled) {
                        nfs_mt_mutex_unlock(&rpc->rpc_mutex);
                }
#endif /* HAVE_MULTITHREADING */
		return 0;
	}

	pdu->outdata.size = size;
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
        rpc_enqueue(&rpc->outqueue, pdu);
#ifdef HAVE_MULTITHREADING
        if (rpc->outqueue.head == pdu) {
                if (rpc->multithreading_enabled) {
                        nfs_mt_mutex_unlock(&rpc->rpc_mutex);
                }
                rpc_write_to_socket(rpc);
        } else {
                if (rpc->multithreading_enabled) {
                        nfs_mt_mutex_unlock(&rpc->rpc_mutex);
                }
        }
#endif /* HAVE_MULTITHREADING */
        
	return 0;
}

static int rpc_process_reply(struct rpc_context *rpc, ZDR *zdr)
{
	struct rpc_msg msg;
        struct rpc_pdu *pdu = rpc->pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&msg, 0, sizeof(struct rpc_msg));
	msg.body.rbody.reply.areply.verf = _null_auth;
	if (pdu->zdr_decode_bufsize > 0) {
		pdu->zdr_decode_buf = (char *)pdu + PAD_TO_8_BYTES(sizeof(struct rpc_pdu));
	}
	msg.body.rbody.reply.areply.reply_data.results.where = pdu->zdr_decode_buf;
	msg.body.rbody.reply.areply.reply_data.results.proc  = pdu->zdr_decode_fn;
#ifdef HAVE_LIBKRB5
        if (rpc->sec == RPC_SEC_KRB5I && pdu->gss_seqno > 0) {
                msg.body.rbody.reply.areply.reply_data.results.krb5i = 1;
        }
        if (rpc->sec == RPC_SEC_KRB5P && pdu->gss_seqno > 0) {
                msg.body.rbody.reply.areply.reply_data.results.krb5p = 1;
                msg.body.rbody.reply.areply.reply_data.results.output_buffer = &pdu->output_buffer;
                msg.body.rbody.reply.areply.verf.gss_context = rpc->gss_context;
        }
#endif
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
                if (pdu->in.buf) {
                        rpc->pdu->free_pdu = 1;
                        break;
                }
#ifdef HAVE_LIBKRB5
                if (msg.body.rbody.reply.areply.verf.oa_flavor == AUTH_GSS) {
                        uint32_t maj, min;
                        gss_buffer_desc message_buffer, token_buffer;
                        uint32_t seqno;

                        /* This is the the gss token from the NULL reply
                         * that finished authentication.
                         */
                        if (pdu->gss_seqno == 0) {
                                struct rpc_gss_init_res *gir = (struct rpc_gss_init_res *)pdu->zdr_decode_buf;

                                rpc->context_len = gir->handle.handle_len;
                                free(rpc->context);
                                rpc->context = malloc(rpc->context_len);
                                if (rpc->context == NULL) {
                                        pdu->cb(rpc, RPC_STATUS_ERROR, "Failed to allocate rpc->context", pdu->private_data);
                                        break;
                                }
                                memcpy(rpc->context, gir->handle.handle_val, rpc->context_len);

                                if (krb5_auth_request(rpc, rpc->auth_data,
                                                      (unsigned char *)gir->gss_token.gss_token_val,
                                                      gir->gss_token.gss_token_len) < 0) {
                                        pdu->cb(rpc, RPC_STATUS_ERROR, "krb5_auth_request returned error", pdu->private_data);
                                        break;
                                }
                        }

                        if (pdu->gss_seqno > 0) {
                                seqno = htonl(pdu->gss_seqno);
                                message_buffer.value = (char *)&seqno;
                                message_buffer.length = 4;

                                token_buffer.value = msg.body.rbody.reply.areply.verf.oa_base;
                                token_buffer.length = msg.body.rbody.reply.areply.verf.oa_length;
                                maj = gss_verify_mic(&min,
                                                     rpc->gss_context,
                                                     &message_buffer,
                                                     &token_buffer,
                                                     GSS_C_QOP_DEFAULT);
                                if (maj) {
                                        pdu->cb(rpc, RPC_STATUS_ERROR, "gss_verify_mic failed for the verifier", pdu->private_data);
                                        break;
                                }
                        }
                }
#endif
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
                              (int)call.body.cbody.prog,
                              (int)call.body.cbody.vers);
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
                        return endpoint->procs[i].func(rpc, &call, endpoint->procs[i].opaque);
                }
        }

        return rpc_send_error_reply(rpc, &call, PROC_UNAVAIL, 0 ,0);
}

struct rpc_pdu *rpc_find_pdu(struct rpc_context *rpc, uint32_t xid)
{
	struct rpc_pdu *pdu, *prev_pdu;
	struct rpc_queue *q;
	unsigned int hash;

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */

	/* Look up the transaction in a hash table of our requests */
	hash = rpc_hash_xid(rpc, rpc->rm_xid[1]);
	q = &rpc->waitpdu[hash];

	/* Follow the hash chain.  Linear traverse singly-linked list,
	 * but track previous entry for optimised removal */
	prev_pdu = NULL;
	for (pdu=q->head; pdu; pdu=pdu->next) {
		if (pdu->xid != rpc->rm_xid[1]) {
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
                break;
        }

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */

        return pdu;
}

int rpc_cancel_pdu(struct rpc_context *rpc, struct rpc_pdu *pdu)
{
        /*
         * Use rpc_find_pdu() to locate it and remove it from the input list.
         */
        pdu = rpc_find_pdu(rpc, pdu->xid);
        if (pdu) {
                rpc_free_pdu(rpc, pdu);
                return 0;
        }

        return -ENOENT;
}

int rpc_process_pdu(struct rpc_context *rpc, char *buf, int size)
{
	ZDR zdr;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	memset(&zdr, 0, sizeof(ZDR));

	zdrmem_create(&zdr, buf, size, ZDR_DECODE);
        if (rpc->is_server_context) {
                int ret;

                ret = rpc_process_call(rpc, &zdr);
                zdr_destroy(&zdr);
                return ret;
        }

        if (rpc_process_reply(rpc, &zdr) != 0) {
                rpc_set_error(rpc, "rpc_procdess_reply failed");
        }

        if (rpc->fragments == NULL && rpc->pdu && rpc->pdu->in.buf) {
                memcpy(&rpc->pdu->zdr, &zdr, sizeof(zdr));
                rpc->pdu->free_zdr = 1;
        } else {
                zdr_destroy(&zdr);
        }
        return 0;
}

