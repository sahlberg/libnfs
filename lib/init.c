/*
   Copyright (C) 2010 by Ronnie Sahlberg <ronniesahlberg@gmail.com>



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

#ifdef WIN32
#include "win32_compat.h"
#else
#include <strings.h>
#endif/*WIN32*/
#define _GNU_SOURCE

#ifdef HAVE_UNISTD_H
#include <unistd.h>
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

#ifdef AROS
#include "aros_compat.h"
#endif

struct rpc_context *rpc_init_context(void)
{
	struct rpc_context *rpc;
	static uint32_t salt = 0;

	rpc = malloc(sizeof(struct rpc_context));
	if (rpc == NULL) {
		return NULL;
	}
	memset(rpc, 0, sizeof(struct rpc_context));

	rpc->magic = RPC_CONTEXT_MAGIC;
	rpc->encodebuflen = 65536;
	rpc->encodebuf = malloc(rpc->encodebuflen);
	if (rpc->encodebuf == NULL) {
		free(rpc);
		return NULL;
	}

#if defined(WIN32)
	rpc->auth = authunix_create("LibNFS", 65535, 65535, 0, NULL);
#else
 	rpc->auth = authunix_create_default();
#endif
	if (rpc->auth == NULL) {
		free(rpc->encodebuf);
		free(rpc);
		return NULL;
	}
	rpc->xid = salt + time(NULL);
	salt += 0x01000000;
	rpc->fd = -1;

	return rpc;
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


void rpc_set_error(struct rpc_context *rpc, char *error_string, ...)
{
        va_list ap;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->error_string != NULL) {
		free(rpc->error_string);
	}
        va_start(ap, error_string);
	rpc->error_string = malloc(1024);
	vsnprintf(rpc->error_string, 1024, error_string, ap);
        va_end(ap);
}

char *rpc_get_error(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	return rpc->error_string;
}

void rpc_error_all_pdus(struct rpc_context *rpc, char *error)
{
	struct rpc_pdu *pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	while((pdu = rpc->outqueue) != NULL) {
		pdu->cb(rpc, RPC_STATUS_ERROR, error, pdu->private_data);
		SLIST_REMOVE(&rpc->outqueue, pdu);
		rpc_free_pdu(rpc, pdu);
	}
	while((pdu = rpc->waitpdu) != NULL) {
		pdu->cb(rpc, RPC_STATUS_ERROR, error, pdu->private_data);
		SLIST_REMOVE(&rpc->waitpdu, pdu);
		rpc_free_pdu(rpc, pdu);
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

	      SLIST_REMOVE(&rpc->fragments, fragment);
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
	SLIST_ADD_END(&rpc->fragments, fragment);
	return 0;
}

void rpc_destroy_context(struct rpc_context *rpc)
{
	struct rpc_pdu *pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	while((pdu = rpc->outqueue) != NULL) {
		pdu->cb(rpc, RPC_STATUS_CANCEL, NULL, pdu->private_data);
		SLIST_REMOVE(&rpc->outqueue, pdu);
		rpc_free_pdu(rpc, pdu);
	}
	while((pdu = rpc->waitpdu) != NULL) {
		pdu->cb(rpc, RPC_STATUS_CANCEL, NULL, pdu->private_data);
		SLIST_REMOVE(&rpc->waitpdu, pdu);
		rpc_free_pdu(rpc, pdu);
	}

	rpc_free_all_fragments(rpc);

	auth_destroy(rpc->auth);
	rpc->auth =NULL;

	if (rpc->fd != -1) {
 		close(rpc->fd);
	}

	if (rpc->encodebuf != NULL) {
		free(rpc->encodebuf);
		rpc->encodebuf = NULL;
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


