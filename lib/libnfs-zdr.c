/*
   Copyright (C) 2012 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
/*
 * This file contains definitions for the built in ZDR implementation.
 * This is a very limited ZDR subset that can only marshal to/from a momory buffer,
 * i.e. zdrmem_create() buffers.
 * It aims to be compatible with normal rpcgen generated functions.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include "win32_compat.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

struct opaque_auth _null_auth;

bool_t libnfs_zdr_setpos(ZDR *zdrs, uint32_t pos)
{
	zdrs->pos = pos;

	return TRUE;
}

uint32_t libnfs_zdr_getpos(ZDR *zdrs)
{
	return zdrs->pos;
}

void libnfs_zdrmem_create(ZDR *zdrs, const caddr_t addr, uint32_t size, enum zdr_op xop)
{
	zdrs->x_op = xop;
	zdrs->buf  = addr;
	zdrs->size = size;
	zdrs->pos  = 0;
	zdrs->mem = NULL;
}

static void *zdr_malloc(ZDR *zdrs, uint32_t size)
{
	struct zdr_mem *mem;

	mem = malloc(sizeof(struct zdr_mem));
	mem->next = zdrs->mem;
	mem->size = size;
	mem->buf  = malloc(mem->size);
	zdrs->mem = mem;

	return mem->buf;
}
	
void libnfs_zdr_destroy(ZDR *zdrs)
{
	while (zdrs->mem != NULL) {
		struct zdr_mem *mem = zdrs->mem->next;
		free(zdrs->mem->buf);
		free(zdrs->mem);
		zdrs->mem = mem;
	}
}

bool_t libnfs_zdr_u_int(ZDR *zdrs, uint32_t *u)
{
	if (zdrs->pos + 4 > zdrs->size) {
		return FALSE;
	}

	switch (zdrs->x_op) {
	case ZDR_ENCODE:
		*(uint32_t *)&zdrs->buf[zdrs->pos] = htonl(*u);
		zdrs->pos += 4;
		return TRUE;
		break;
	case ZDR_DECODE:
		*u = ntohl(*(uint32_t *)&zdrs->buf[zdrs->pos]);
		zdrs->pos += 4;
		return TRUE;
		break;
	}

	return FALSE;
}

bool_t libnfs_zdr_int(ZDR *zdrs, int32_t *i)
{
	return libnfs_zdr_u_int(zdrs, (uint32_t *)i);
}

bool_t libnfs_zdr_uint64_t(ZDR *zdrs, uint64_t *u)
{
	if (zdrs->pos + 8 > zdrs->size) {
		return FALSE;
	}

	switch (zdrs->x_op) {
	case ZDR_ENCODE:
		*(uint32_t *)&zdrs->buf[zdrs->pos] = htonl((*u >> 32));
		zdrs->pos += 4;
		*(uint32_t *)&zdrs->buf[zdrs->pos] = htonl((*u & 0xffffffff));
		zdrs->pos += 4;
		return TRUE;
		break;
	case ZDR_DECODE:
		*u = ntohl(*(uint32_t *)&zdrs->buf[zdrs->pos]);
		zdrs->pos += 4;
		*u <<= 32;
		*u |= (uint32_t)ntohl(*(uint32_t *)&zdrs->buf[zdrs->pos]);
		zdrs->pos += 4;
		return TRUE;
		break;
	}

	return FALSE;
}

bool_t libnfs_zdr_int64_t(ZDR *zdrs, int64_t *i)
{
	return libnfs_zdr_uint64_t(zdrs, (uint64_t *)i);
}

bool_t libnfs_zdr_bytes(ZDR *zdrs, char **bufp, uint32_t *size, uint32_t maxsize)
{
	if (!libnfs_zdr_u_int(zdrs, size)) {
		return FALSE;
	}

	if (zdrs->pos + *size > zdrs->size) {
		return FALSE;
	}

	switch (zdrs->x_op) {
	case ZDR_ENCODE:
		memcpy(&zdrs->buf[zdrs->pos], *bufp, *size);
		zdrs->pos += *size;
		zdrs->pos = (zdrs->pos + 3) & ~3;
		return TRUE;
	case ZDR_DECODE:
		if (*bufp == NULL) {
			*bufp = zdr_malloc(zdrs, *size);
		}
		memcpy(*bufp, &zdrs->buf[zdrs->pos], *size);
		zdrs->pos += *size;
		zdrs->pos = (zdrs->pos + 3) & ~3;
		return TRUE;
	}

	return FALSE;
}


bool_t libnfs_zdr_enum(ZDR *zdrs, enum_t *e)
{
	bool_t ret;
	int32_t i = *e;

	ret = libnfs_zdr_u_int(zdrs, (uint32_t *)&i);
	*e = i;

	return ret;	
}

bool_t libnfs_zdr_bool(ZDR *zdrs, bool_t *b)
{
	return libnfs_zdr_u_int(zdrs, (uint32_t *)b);
}

bool_t libnfs_zdr_void(void)
{
	return TRUE;
}

bool_t libnfs_zdr_pointer(ZDR *zdrs, char **objp, uint32_t size, zdrproc_t proc)
{
	bool_t more_data;

	more_data = (*objp != NULL);

	if (!libnfs_zdr_bool(zdrs, &more_data)) {
		return FALSE;
	}
	if (more_data == 0) {
		*objp = NULL;
		return TRUE;
	}

	if (zdrs->x_op == ZDR_DECODE) {
		*objp = zdr_malloc(zdrs, size);
		if (*objp == NULL) {
			return FALSE;
		}
		memset(*objp, 0, size);
	}
	return proc(zdrs, *objp);
}

bool_t libnfs_zdr_opaque(ZDR *zdrs, char *objp, uint32_t size)
{
	switch (zdrs->x_op) {
	case ZDR_ENCODE:
		memcpy(&zdrs->buf[zdrs->pos], objp, size);
		zdrs->pos += size;
		if (zdrs->pos & 3) {
			memset(&zdrs->buf[zdrs->pos], 0x00, 4 - (zdrs->pos & 3));
		}
		zdrs->pos = (zdrs->pos + 3) & ~3;
		return TRUE;
	case ZDR_DECODE:
		memcpy(objp, &zdrs->buf[zdrs->pos], size);
		zdrs->pos += size;
		zdrs->pos = (zdrs->pos + 3) & ~3;
		return TRUE;
	}

	return FALSE;
}

bool_t libnfs_zdr_string(ZDR *zdrs, char **strp, uint32_t maxsize)
{
	uint32_t size;

	if (zdrs->x_op == ZDR_ENCODE) {
		size = strlen(*strp);
	}

	if (!libnfs_zdr_u_int(zdrs, &size)) {
		return FALSE;
	}

	if (zdrs->pos + size > zdrs->size) {
		return FALSE;
	}

	switch (zdrs->x_op) {
	case ZDR_ENCODE:
		return libnfs_zdr_opaque(zdrs, *strp, size);
	case ZDR_DECODE:
		*strp = zdr_malloc(zdrs, size + 1);
		if (*strp == NULL) {
			return FALSE;
		}
		(*strp)[size] = 0;
		return libnfs_zdr_opaque(zdrs, *strp, size);
	}

	return FALSE;
}

bool_t libnfs_zdr_array(ZDR *zdrs, char **arrp, uint32_t *size, uint32_t maxsize, uint32_t elsize, zdrproc_t proc)
{
	int  i;

	if (!libnfs_zdr_u_int(zdrs, size)) {
		return FALSE;
	}

	if (zdrs->pos + *size * elsize > zdrs->size) {
		return FALSE;
	}

	if (zdrs->x_op == ZDR_DECODE) {
		*arrp = zdr_malloc(zdrs, *size * elsize);
		if (*arrp == NULL) {
			return FALSE;
		}
		memset(*arrp, 0, *size * elsize);
	}

	for (i = 0; i < *size; i++) {
		if (!proc(zdrs, *arrp + i * elsize)) {
			return FALSE;
		}
	}
	return TRUE;
}

void libnfs_zdr_free(zdrproc_t proc, char *objp)
{
}

static bool_t libnfs_opaque_auth(ZDR *zdrs, struct opaque_auth *auth)
{
	if (!libnfs_zdr_u_int(zdrs, &auth->oa_flavor)) {
		return FALSE;
	}

	if (!libnfs_zdr_bytes(zdrs, &auth->oa_base, &auth->oa_length, auth->oa_length)) {
		return FALSE;
	}

	return TRUE;
}

static bool_t libnfs_rpc_call_body(struct rpc_context *rpc, ZDR *zdrs, struct call_body *cmb)
{
	if (!libnfs_zdr_u_int(zdrs, &cmb->rpcvers)) {
		rpc_set_error(rpc, "libnfs_rpc_call_body failed to encode "
			"RPCVERS");
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &cmb->prog)) {
		rpc_set_error(rpc, "libnfs_rpc_call_body failed to encode "
			"PROG");
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &cmb->vers)) {
		rpc_set_error(rpc, "libnfs_rpc_call_body failed to encode "
			"VERS");
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &cmb->proc)) {
		rpc_set_error(rpc, "libnfs_rpc_call_body failed to encode "
			"PROC");
		return FALSE;
	}

	if (!libnfs_opaque_auth(zdrs, &cmb->cred)) {
		rpc_set_error(rpc, "libnfs_rpc_call_body failed to encode "
			"CRED");
		return FALSE;
	}

	if (!libnfs_opaque_auth(zdrs, &cmb->verf)) {
		rpc_set_error(rpc, "libnfs_rpc_call_body failed to encode "
			"VERF");
		return FALSE;
	}

	return TRUE;
}

static bool_t libnfs_accepted_reply(ZDR *zdrs, struct accepted_reply *ar)
{
	if (!libnfs_opaque_auth(zdrs, &ar->verf)) {
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &ar->stat)) {
		return FALSE;
	}

	switch (ar->stat) {
	case SUCCESS:
		if (!ar->reply_data.results.proc(zdrs, ar->reply_data.results.where)) {
			return FALSE;
		}
		return TRUE;
	case PROG_MISMATCH:
		if (!libnfs_zdr_u_int(zdrs, &ar->reply_data.mismatch_info.low)) {
			return FALSE;
		}
		if (!libnfs_zdr_u_int(zdrs, &ar->reply_data.mismatch_info.high)) {
			return FALSE;
		}
		return TRUE;
	default:
		return TRUE;
	}

	return FALSE;
}

static bool_t libnfs_rejected_reply(ZDR *zdrs, struct rejected_reply *rr)
{
	if (!libnfs_zdr_u_int(zdrs, &rr->stat)) {
		return FALSE;
	}

	switch (rr->stat) {
	case RPC_MISMATCH:
		if (!libnfs_zdr_u_int(zdrs, &rr->reject_data.mismatch_info.low)) {
			return FALSE;
		}
		if (!libnfs_zdr_u_int(zdrs, &rr->reject_data.mismatch_info.high)) {
			return FALSE;
		}
		return TRUE;
	case AUTH_ERROR:
		if (!libnfs_zdr_u_int(zdrs, &rr->reject_data.stat)) {
			return FALSE;
		}
		return TRUE;
	default:
		return TRUE;
	}

	return FALSE;
}

static bool_t libnfs_rpc_reply_body(struct rpc_context *rpc, ZDR *zdrs, struct reply_body *rmb)
{
	if (!libnfs_zdr_u_int(zdrs, &rmb->stat)) {
		rpc_set_error(rpc, "libnfs_rpc_reply_body failed to decode "
			"STAT");
		return FALSE;
	}

	switch (rmb->stat) {
	case MSG_ACCEPTED:
		if (!libnfs_accepted_reply(zdrs, &rmb->reply.areply)) {
			rpc_set_error(rpc, "libnfs_rpc_reply_body failed to "
				"decode ACCEPTED");
			return FALSE;
		}
		return TRUE;
	case MSG_DENIED:
		if (!libnfs_rejected_reply(zdrs, &rmb->reply.rreply)) {
			rpc_set_error(rpc, "libnfs_rpc_reply_body failed to "
				"decode DENIED");
			return FALSE;
		}
		return TRUE;
	}

	rpc_set_error(rpc, "libnfs_rpc_reply_body failed to "
		"decode. Neither ACCEPTED nor DENIED");
	return FALSE;
}

static bool_t libnfs_rpc_msg(struct rpc_context *rpc, ZDR *zdrs, struct rpc_msg *msg)
{
	int ret;

	if (!libnfs_zdr_u_int(zdrs, &msg->xid)) {
		rpc_set_error(rpc, "libnfs_rpc_msg failed to decode XID");
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &msg->direction)) {
		rpc_set_error(rpc, "libnfs_rpc_msg failed to decode DIRECTION");
		return FALSE;
	}

	switch (msg->direction) {
	case CALL:
		ret = libnfs_rpc_call_body(rpc, zdrs, &msg->body.cbody);
		if (!ret) { 
			rpc_set_error(rpc, "libnfs_rpc_msg failed to encode "
				"CALL, ret=%d: %s", ret, rpc_get_error(rpc));
		}
		return ret;
	case REPLY:
		ret = libnfs_rpc_reply_body(rpc, zdrs, &msg->body.rbody);
		if (!ret) { 
			rpc_set_error(rpc, "libnfs_rpc_msg failed to decode "
				"REPLY, ret=%d: %s", ret, rpc_get_error(rpc));
		}
		return ret;
	default:
		rpc_set_error(rpc, "libnfs_rpc_msg failed to decode. "
			"Neither CALL not REPLY");
		return FALSE;
	}
}

bool_t libnfs_zdr_callmsg(struct rpc_context *rpc, ZDR *zdrs, struct rpc_msg *msg)
{
	return libnfs_rpc_msg(rpc, zdrs, msg);
}

bool_t libnfs_zdr_replymsg(struct rpc_context *rpc, ZDR *zdrs, struct rpc_msg *msg)
{
	return libnfs_rpc_msg(rpc, zdrs, msg);
}

struct AUTH *authnone_create(void)
{
	struct AUTH *auth;

	auth = malloc(sizeof(struct AUTH));

	auth->ah_cred.oa_flavor = AUTH_NONE;
	auth->ah_cred.oa_length = 0;
	auth->ah_cred.oa_base = NULL;

	auth->ah_verf.oa_flavor = AUTH_NONE;
	auth->ah_verf.oa_length = 0;
	auth->ah_verf.oa_base = NULL;

	auth->ah_private = NULL;

	return auth;
}

struct AUTH *libnfs_authunix_create(const char *host, uint32_t uid, uint32_t gid, uint32_t len, uint32_t *groups)
{
	struct AUTH *auth;
	int size;
	uint32_t *buf;
	int idx;

	size = 4 + 4 + ((strlen(host) + 3) & ~3) + 4 + 4 + 4 + len * 4;
	auth = malloc(sizeof(struct AUTH));
	memset(auth, 0x00, sizeof(struct AUTH));
	auth->ah_cred.oa_flavor = AUTH_UNIX;
	auth->ah_cred.oa_length = size;
	auth->ah_cred.oa_base = malloc(size);

	memset(auth->ah_cred.oa_base, 0x00, size);
	buf = (uint32_t *)auth->ah_cred.oa_base;
	idx = 0;
	buf[idx++] = htonl(time(NULL));
	buf[idx++] = htonl(strlen(host));
	memcpy(&buf[2], host, strlen(host));

	idx += (strlen(host) + 3) >> 2;	
	buf[idx++] = htonl(uid);
	buf[idx++] = htonl(gid);
	buf[idx++] = htonl(len);
	while (len-- > 0) {
		buf[idx++] = htonl(*groups++);
	}

	auth->ah_verf.oa_flavor = AUTH_NONE;
	auth->ah_verf.oa_length = 0;
	auth->ah_verf.oa_base = NULL;

	auth->ah_private = NULL;

	return auth;
}

struct AUTH *libnfs_authunix_create_default(void)
{
#ifdef WIN32
	return libnfs_authunix_create("libnfs", 65534, 65534, 0, NULL);
#else
	return libnfs_authunix_create("libnfs", getuid(), getgid(), 0, NULL);
#endif
}

void libnfs_auth_destroy(struct AUTH *auth)
{
	if (auth->ah_cred.oa_base) {
		free(auth->ah_cred.oa_base);
	}
	if (auth->ah_verf.oa_base) {
		free(auth->ah_verf.oa_base);
	}
	free(auth);
}

