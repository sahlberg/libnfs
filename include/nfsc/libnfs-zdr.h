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

/************************************************************
 * Definitions copied from RFC 5531
 * and slightly modified.
 ************************************************************/

#ifndef _LIBNFS_ZDR_H_
#define _LIBNFS_ZDR_H_

#ifdef WIN32
#ifndef CADDR_T_DEFINED
#define CADDR_T_DEFINED
typedef char *caddr_t;
#endif
#endif

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _RPC_RPC_H 1
#define _RPC_ZDR_H 1
#define _RPC_AUTH_H 1

/* we dont need these */
typedef void CLIENT;
struct svc_req {
	int _dummy_;
};
typedef void SVCXPRT;





#define ZDR_INLINE(...) NULL
#define IZDR_PUT_U_LONG(...)		assert(0)
#define IZDR_GET_U_LONG(...)		(assert(0), 0)
#define IZDR_PUT_LONG(...)		assert(0)
#define IZDR_GET_LONG(...)		(assert(0), 0)
#define IZDR_PUT_BOOL(...)		assert(0)
#define IZDR_GET_BOOL(...)		(assert(0), 0)

#ifndef TRUE
#define TRUE		1
#endif
#ifndef FALSE
#define FALSE		0
#endif

enum zdr_op {
	ZDR_ENCODE = 0,
	ZDR_DECODE = 1
};

struct zdr_mem {
       struct zdr_mem *next;
       caddr_t buf;
       uint32_t size;
};

struct ZDR {
	enum zdr_op x_op;
	caddr_t buf;
	int size;
	int pos;
	struct zdr_mem *mem;
};
typedef struct ZDR ZDR;


typedef uint32_t u_int;
typedef uint32_t enum_t;
typedef uint32_t bool_t;

typedef int (*zdrproc_t) (ZDR *, void *,...);

#define AUTH_NONE 0
#define AUTH_NULL 0
#define AUTH_UNIX 1

struct opaque_auth {
	uint32_t oa_flavor;
	caddr_t  oa_base;
	uint32_t oa_length;
};
extern struct opaque_auth _null_auth;

struct AUTH {
	struct opaque_auth	ah_cred;
	struct opaque_auth	ah_verf;
	caddr_t ah_private;
};

#define RPC_MSG_VERSION	2

enum msg_type {
	CALL  = 0,
	REPLY = 1
};

enum reply_stat {
	MSG_ACCEPTED=0,
	MSG_DENIED=1
};

enum accept_stat {
	SUCCESS       = 0,
	PROG_UNAVAIL  = 1,
	PROG_MISMATCH = 2,
	PROC_UNAVAIL  = 3,
	GARBAGE_ARGS  = 4,
	SYSTEM_ERR    = 5
};

enum reject_stat {
	RPC_MISMATCH = 0,
	AUTH_ERROR   = 1
};

enum auth_stat {
	AUTH_OK=0,
	/*
	 * failed at remote end
	 */
	AUTH_BADCRED      = 1,		/* bogus credentials (seal broken) */
	AUTH_REJECTEDCRED = 2,		/* client should begin new session */
	AUTH_BADVERF      = 3,		/* bogus verifier (seal broken) */
	AUTH_REJECTEDVERF = 4,		/* verifier expired or was replayed */
	AUTH_TOOWEAK      = 5,		/* rejected due to security reasons */
	/*
	 * failed locally
	*/
	AUTH_INVALIDRESP  = 6,		/* bogus response verifier */
	AUTH_FAILED       = 7		/* some unknown reason */
};

struct call_body {
	uint32_t rpcvers;
	uint32_t prog;
	uint32_t vers;
	uint32_t proc;
	struct opaque_auth cred;
	struct opaque_auth verf;
};

struct accepted_reply {
	struct opaque_auth	verf;
	uint32_t		stat;
	union {
		struct {
			caddr_t	where;
			zdrproc_t proc;
		} results;
		struct {
			uint32_t	low;
			uint32_t	high;
		} mismatch_info;
	} reply_data;
};

struct rejected_reply {
	enum reject_stat stat;
	union {
		struct {
			uint32_t low;
			uint32_t high;
		} mismatch_info;
		enum auth_stat stat;
	} reject_data;
};

struct reply_body {
	uint32_t stat;
	union {
		struct accepted_reply areply;
		struct rejected_reply rreply;
	} reply;
};

struct rpc_msg {
	uint32_t		  xid;

	uint32_t		  direction;
	union {
		struct call_body  cbody;
		struct reply_body rbody;
	} body;
};

#define zdrmem_create libnfs_zdrmem_create
void libnfs_zdrmem_create(ZDR *zdrs, const caddr_t addr, uint32_t size, enum zdr_op xop);

#define zdr_destroy libnfs_zdr_destroy
void libnfs_zdr_destroy(ZDR *zdrs);

#define zdr_bytes libnfs_zdr_bytes
bool_t libnfs_zdr_bytes(ZDR *zdrs, char **bufp, uint32_t *size, uint32_t maxsize);

#define zdr_u_int libnfs_zdr_u_int
bool_t libnfs_zdr_u_int(ZDR *zdrs, uint32_t *u);

#define zdr_int libnfs_zdr_int
bool_t libnfs_zdr_int(ZDR *zdrs, int32_t *i);

#define zdr_uint64_t libnfs_zdr_uint64_t
bool_t libnfs_zdr_uint64_t(ZDR *zdrs, uint64_t *u);

#define zdr_int64_t libnfs_zdr_int64_t
bool_t libnfs_zdr_int64_t(ZDR *zdrs, int64_t *i);

#define zdr_enum libnfs_zdr_enum
bool_t libnfs_zdr_enum(ZDR *zdrs, enum_t *e);

#define zdr_bool libnfs_zdr_bool
bool_t libnfs_zdr_bool(ZDR *zdrs, bool_t *b);

#define zdr_void libnfs_zdr_void
bool_t libnfs_zdr_void(void);

#define zdr_pointer libnfs_zdr_pointer
bool_t libnfs_zdr_pointer(ZDR *zdrs, char **objp, uint32_t size, zdrproc_t proc);

#define zdr_opaque libnfs_zdr_opaque
bool_t libnfs_zdr_opaque(ZDR *zdrs, char *objp, uint32_t size);

#define zdr_string libnfs_zdr_string
bool_t libnfs_zdr_string(ZDR *zdrs, char **strp, uint32_t maxsize);

#define zdr_array libnfs_zdr_array
bool_t libnfs_zdr_array(ZDR *zdrs, char **arrp, uint32_t *size, uint32_t maxsize, uint32_t elsize, zdrproc_t proc);

#define zdr_setpos libnfs_zdr_setpos
bool_t libnfs_zdr_setpos(ZDR *zdrs, uint32_t pos);

#define zdr_getpos libnfs_zdr_getpos
uint32_t libnfs_zdr_getpos(ZDR *zdrs);

#define zdr_free libnfs_zdr_free
void libnfs_zdr_free(zdrproc_t proc, char *objp);

struct rpc_context;

#define zdr_callmsg libnfs_zdr_callmsg
bool_t libnfs_zdr_callmsg(struct rpc_context *rpc, ZDR *zdrs, struct rpc_msg *msg);

#define zdr_replymsg libnfs_zdr_replymsg
bool_t libnfs_zdr_replymsg(struct rpc_context *rpc, ZDR *zdrs, struct rpc_msg *msg);

#define authnone_create libnfs_authnone_create
struct AUTH *libnfs_authnone_create(void);

#define authunix_create libnfs_authunix_create
struct AUTH *libnfs_authunix_create(const char *host, uint32_t uid, uint32_t gid, uint32_t len, uint32_t *groups);

#define authunix_create_default libnfs_authunix_create_default
struct AUTH *libnfs_authunix_create_default(void);

#define auth_destroy libnfs_auth_destroy
void libnfs_auth_destroy(struct AUTH *auth);

#ifdef __cplusplus
}
#endif

#endif
