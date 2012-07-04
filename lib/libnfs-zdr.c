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

#include <stdlib.h>
#include <string.h>
#include "libnfs-zdr.h"

struct opaque_auth _null_auth;

bool_t libnfs_zdr_setpos(ZDR *zdrs, uint32_t pos)
{
	zdrs->pos = pos;
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

bool_t libnfs_zdr_u_quad_t(ZDR *zdrs, uint64_t *u)
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
		*u |= ntohl(*(uint32_t *)&zdrs->buf[zdrs->pos]);
		zdrs->pos += 4;
		return TRUE;
		break;
	}

	return FALSE;
}

bool_t libnfs_zdr_quad_t(ZDR *zdrs, int64_t *i)
{
	return libnfs_zdr_u_quad_t(zdrs, (uint64_t *)i);
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


bool_t libnfs_zdr_enum(ZDR *zdrs, int32_t *e)
{
	return libnfs_zdr_u_int(zdrs, (uint32_t *)e);
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
		if (proc(zdrs, *arrp + i * elsize)) {
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

	if (!libnfs_zdr_bytes(zdrs, &auth->oa_base, &auth->oa_length, &auth->oa_length)) {
		return FALSE;
	}

	return TRUE;
}

static bool_t libnfs_rpc_call_body(ZDR *zdrs, struct call_body *cmb)
{
	if (!libnfs_zdr_u_int(zdrs, &cmb->cb_rpcvers)) {
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &cmb->cb_prog)) {
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &cmb->cb_vers)) {
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &cmb->cb_proc)) {
		return FALSE;
	}

	if (!libnfs_opaque_auth(zdrs, &cmb->cb_cred)) {
		return FALSE;
	}

	if (!libnfs_opaque_auth(zdrs, &cmb->cb_verf)) {
		return FALSE;
	}
}

static bool_t libnfs_accepted_reply(ZDR *zdrs, struct accepted_reply *ar)
{
	if (!libnfs_opaque_auth(zdrs, &ar->ar_verf)) {
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &ar->ar_stat)) {
		return FALSE;
	}

	switch (ar->ar_stat) {
	case SUCCESS:
		if (!ar->ar_results.proc(zdrs, ar->ar_results.where)) {
			return FALSE;
		}
		return TRUE;
	case PROG_MISMATCH:
		if (!libnfs_zdr_u_int(zdrs, &ar->ar_vers.low)) {
			return FALSE;
		}
		if (!libnfs_zdr_u_int(zdrs, &ar->ar_vers.high)) {
			return FALSE;
		}
		return TRUE;
	default:
		return TRUE;
	}

	return FALSE;
}

static bool_t libnfs_rejected_reply(ZDR *zdrs, struct rejected_reply *RP_dr)
{
printf("rejected reply\n");
exit(10);
}

static bool_t libnfs_rpc_reply_body(ZDR *zdrs, struct reply_body *rmb)
{
	if (!libnfs_zdr_u_int(zdrs, &rmb->rp_stat)) {
		return FALSE;
	}

	switch (rmb->rp_stat) {
	case MSG_ACCEPTED:
		if (!libnfs_accepted_reply(zdrs, &rmb->rp_acpt)) {
			return FALSE;
		}
		return TRUE;
	case MSG_DENIED:
		if (!libnfs_rejected_reply(zdrs, &rmb->rp_rjct)) {
			return FALSE;
		}
		return TRUE;
	}

	return FALSE;
}

static bool_t libnfs_rpc_msg(ZDR *zdrs, struct rpc_msg *msg)
{
	if (!libnfs_zdr_u_int(zdrs, &msg->rm_xid)) {
		return FALSE;
	}

	if (!libnfs_zdr_u_int(zdrs, &msg->rm_direction)) {
		return FALSE;
	}

	switch (msg->rm_direction) {
	case CALL:
		return libnfs_rpc_call_body(zdrs, &msg->ru.RM_cmb);
		break;
	case REPLY:
		return libnfs_rpc_reply_body(zdrs, &msg->ru.RM_rmb);
		break;
	default:
		return FALSE;
	}
}

bool_t libnfs_zdr_callmsg(ZDR *zdrs, struct rpc_msg *msg)
{
	return libnfs_rpc_msg(zdrs, msg);
}

bool_t libnfs_zdr_replymsg(ZDR *zdrs, struct rpc_msg *msg)
{
	return libnfs_rpc_msg(zdrs, msg);
}

AUTH *authnone_create(void)
{
	AUTH *auth;

	auth = malloc(sizeof(AUTH));

	auth->ah_cred.oa_flavor = AUTH_NONE;
	auth->ah_cred.oa_length = 0;
	auth->ah_cred.oa_base = NULL;

	auth->ah_verf.oa_flavor = AUTH_NONE;
	auth->ah_verf.oa_length = 0;
	auth->ah_verf.oa_base = NULL;

	auth->ah_private = NULL;

	return auth;
}

AUTH *libnfs_authunix_create(char *host, uint32_t uid, uint32_t gid, uint32_t len, uint32_t *groups)
{
	AUTH *auth;
	int size;
	uint32_t *buf;
	int idx;

	size = 4 + 4 + ((strlen(host) + 3) & ~3) + 4 + 4 + 4 + len * 4;
	auth = malloc(sizeof(AUTH));
	auth->ah_cred.oa_flavor = AUTH_UNIX;
	auth->ah_cred.oa_length = size;
	auth->ah_cred.oa_base = malloc(size);

	buf = auth->ah_cred.oa_base;
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

AUTH *libnfs_authunix_create_default(void)
{
	return libnfs_authunix_create("libnfs", getuid(), -1, 0, NULL);
}

void libnfs_auth_destroy(AUTH *auth)
{
	if (auth->ah_cred.oa_base) {
		free(auth->ah_cred.oa_base);
	}
	if (auth->ah_verf.oa_base) {
		free(auth->ah_verf.oa_base);
	}
	free(auth);
}

