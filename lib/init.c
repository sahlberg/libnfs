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

#define _GNU_SOURCE

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include "slist.h"
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

struct rpc_context *rpc_init_context(void)
{
	struct rpc_context *rpc;
	static uint32_t salt = 0;
	unsigned int i;

	rpc = malloc(sizeof(struct rpc_context));
	if (rpc == NULL) {
		return NULL;
	}
	memset(rpc, 0, sizeof(struct rpc_context));

	rpc->magic = RPC_CONTEXT_MAGIC;

 	rpc->auth = authunix_create_default();
	if (rpc->auth == NULL) {
		free(rpc);
		return NULL;
	}
	rpc->xid = salt + time(NULL) + (getpid() << 16);
	salt += 0x01000000;
	rpc->fd = -1;
	rpc->tcp_syncnt = RPC_PARAM_UNDEFINED;
	rpc->pagecache_ttl = NFS_PAGECACHE_DEFAULT_TTL;
#if defined(WIN32) || defined(ANDROID)
	rpc->uid = 65534;
	rpc->gid = 65534;
#else
	rpc->uid = getuid();
	rpc->gid = getgid();
#endif
	rpc_reset_queue(&rpc->outqueue);
	for (i = 0; i < HASHES; i++)
		rpc_reset_queue(&rpc->waitpdu[i]);

	/* Default is no timeout */
	rpc->timeout = -1;

	return rpc;
}

uint32_t static round_to_power_of_two(uint32_t x) {
	uint32_t power = 1;
	while (power < x) {
		power <<= 1;
	}
	return power;
}

void rpc_set_pagecache(struct rpc_context *rpc, uint32_t v)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);
	v = MAX(rpc->pagecache, round_to_power_of_two(v));
	RPC_LOG(rpc, 2, "pagecache set to %d pages of size %d", v, NFS_BLKSIZE);
	rpc->pagecache = v;
}

void rpc_set_pagecache_ttl(struct rpc_context *rpc, uint32_t v) {
	if (v) {
		RPC_LOG(rpc, 2, "set pagecache ttl to %d seconds\n", v);
	} else {
		RPC_LOG(rpc, 2, "set pagecache ttl to infinite");
	}
	rpc->pagecache_ttl = v;
}

void rpc_set_readahead(struct rpc_context *rpc, uint32_t v)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);
	uint32_t min_pagecache;
	if (v) {
		v = MAX(NFS_BLKSIZE, round_to_power_of_two(v));
	}
	RPC_LOG(rpc, 2, "readahead set to %d byte", v);
	rpc->readahead = v;
	min_pagecache = (2 * v) / NFS_BLKSIZE;
	if (rpc->pagecache < min_pagecache) {
		/* current pagecache implementation needs a pagecache bigger
		 * than the readahead size to avoid collisions */
		rpc_set_pagecache(rpc, min_pagecache);
	}
}

void rpc_set_interface(struct rpc_context *rpc, const char *ifname)
{
	/*
	 * This only copies the interface information into the RPC
	 * structure.  It doesn't stop whatever interface is being used. The
	 * connection needs to be restarted for that happen. In other words,
	 * set this before you connect.
	 */
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (ifname) {
		/*
		 * Allow at one-less character just-in-case IFNAMSIZ for
		 * the defined platform does not include the NUL-terminator.
		 */
		strncpy(rpc->ifname, ifname, sizeof(rpc->ifname) - 1);
	}
}

void rpc_set_debug(struct rpc_context *rpc, int level)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc->debug = level;
}

struct rpc_context *rpc_init_udp_context(void)
{
	struct rpc_context *rpc;

	rpc = rpc_init_context();
	if (rpc != NULL) {
		rpc->is_udp = 1;
	}
	
	return rpc;
}

void rpc_set_auth(struct rpc_context *rpc, struct AUTH *auth)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->auth != NULL) {
		auth_destroy(rpc->auth);
	}
	rpc->auth = auth;
}

static void rpc_set_uid_gid(struct rpc_context *rpc, int uid, int gid) {
	if (uid != rpc->uid || gid != rpc->gid) {
		struct AUTH *auth = libnfs_authunix_create("libnfs", uid, gid, 0, NULL);
		if (auth != NULL) {
			rpc_set_auth(rpc, auth);
			rpc->uid = uid;
			rpc->gid = gid;
		}
	}
}

void rpc_set_uid(struct rpc_context *rpc, int uid) {
	rpc_set_uid_gid(rpc, uid, rpc->gid);
}

void rpc_set_gid(struct rpc_context *rpc, int gid) {
	rpc_set_uid_gid(rpc, rpc->uid, gid);
}

void rpc_set_error(struct rpc_context *rpc, const char *error_string, ...)
{
        va_list ap;
	char *old_error_string = rpc->error_string;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

        va_start(ap, error_string);
	rpc->error_string = malloc(1024);
	vsnprintf(rpc->error_string, 1024, error_string, ap);
        va_end(ap);

	RPC_LOG(rpc, 1, "error: %s", rpc->error_string);

	if (old_error_string != NULL) {
		free(old_error_string);
	}
}

char *rpc_get_error(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	return rpc->error_string;
}

void rpc_error_all_pdus(struct rpc_context *rpc, const char *error)
{
	struct rpc_pdu *pdu;
	unsigned int i;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	while ((pdu = rpc->outqueue.head) != NULL) {
          pdu->cb(rpc, RPC_STATUS_ERROR, (void *)error, pdu->private_data);
		rpc->outqueue.head = pdu->next;
		rpc_free_pdu(rpc, pdu);
	}
	rpc->outqueue.tail = NULL;

	for (i = 0; i < HASHES; i++) {
		struct rpc_queue *q = &rpc->waitpdu[i];

		while((pdu = q->head) != NULL) {
                  pdu->cb(rpc, RPC_STATUS_ERROR, (void *)error,
                          pdu->private_data);
			q->head = pdu->next;
			rpc_free_pdu(rpc, pdu);
		}
		q->tail = NULL;
	}
}

static void rpc_free_fragment(struct rpc_fragment *fragment)
{
	if (fragment->data != NULL) {
		free(fragment->data);
	}
	free(fragment);
}

void rpc_free_all_fragments(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	while (rpc->fragments != NULL) {
	      struct rpc_fragment *fragment = rpc->fragments;

	      rpc->fragments = fragment->next;
	      rpc_free_fragment(fragment);
	}
}

int rpc_add_fragment(struct rpc_context *rpc, char *data, uint64_t size)
{
	struct rpc_fragment *fragment;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	fragment = malloc(sizeof(struct rpc_fragment));
	if (fragment == NULL) {
		return -1;
	}

	fragment->size = size;
	fragment->data = malloc(fragment->size);
	if(fragment->data == NULL) {
		free(fragment);
		return -1;
	}

	memcpy(fragment->data, data, fragment->size);
	LIBNFS_LIST_ADD_END(&rpc->fragments, fragment);
	return 0;
}

void rpc_destroy_context(struct rpc_context *rpc)
{
	struct rpc_pdu *pdu;
	unsigned int i;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	while((pdu = rpc->outqueue.head) != NULL) {
		pdu->cb(rpc, RPC_STATUS_CANCEL, NULL, pdu->private_data);
		LIBNFS_LIST_REMOVE(&rpc->outqueue.head, pdu);
		rpc_free_pdu(rpc, pdu);
	}

	for (i = 0; i < HASHES; i++) {
		struct rpc_queue *q = &rpc->waitpdu[i];

		while((pdu = q->head) != NULL) {
			pdu->cb(rpc, RPC_STATUS_CANCEL, NULL, pdu->private_data);
			LIBNFS_LIST_REMOVE(&q->head, pdu);
			rpc_free_pdu(rpc, pdu);
		}
	}

	rpc_free_all_fragments(rpc);

	auth_destroy(rpc->auth);
	rpc->auth =NULL;

	if (rpc->fd != -1) {
 		close(rpc->fd);
	}

	if (rpc->error_string != NULL) {
		free(rpc->error_string);
		rpc->error_string = NULL;
	}

	if (rpc->udp_dest != NULL) {
		free(rpc->udp_dest);
		rpc->udp_dest = NULL;
	}

	rpc->magic = 0;
	free(rpc);
}

void rpc_set_timeout(struct rpc_context *rpc, int timeout)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc->timeout = timeout;
}

int rpc_get_timeout(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	return rpc->timeout;
}
