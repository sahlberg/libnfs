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
#ifdef WIN32
#include <win32/win32_compat.h>
#endif/*WIN32*/

#include <stdio.h>
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#include "libnfs-raw-portmap.h"

/*
 * PORTMAP v2
 */
int rpc_pmap2_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V2, PMAP2_NULL, cb, private_data, (zdrproc_t)zdr_void, 0);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP2/NULL call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for PORTMAP2/NULL call");
		return -1;
	}

	return 0;
}

int rpc_pmap2_getport_async(struct rpc_context *rpc, int program, int version, int protocol, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;
	struct pmap2_mapping m;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V2, PMAP2_GETPORT, cb, private_data, (zdrproc_t)zdr_int, sizeof(uint32_t));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP2/GETPORT call");
		return -1;
	}

	m.prog = program;
	m.vers = version;
	m.prot = protocol;
	m.port = 0;
	if (zdr_pmap2_mapping(&pdu->zdr, &m) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP2/GETPORT call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP2/GETPORT pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap2_set_async(struct rpc_context *rpc, int program, int version, int protocol, int port, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;
	struct pmap2_mapping m;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V2, PMAP2_SET, cb, private_data, (zdrproc_t)zdr_int, sizeof(uint32_t));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP2/SET call");
		return -1;
	}

	m.prog = program;
	m.vers = version;
	m.prot = protocol;
	m.port = port;
	if (zdr_pmap2_mapping(&pdu->zdr, &m) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP2/SET call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP2/SET pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap2_unset_async(struct rpc_context *rpc, int program, int version, int protocol, int port, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;
	struct pmap2_mapping m;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V2, PMAP2_UNSET, cb, private_data, (zdrproc_t)zdr_int, sizeof(uint32_t));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP2/UNSET call");
		return -1;
	}

	m.prog = program;
	m.vers = version;
	m.prot = protocol;
	m.port = port;
	if (zdr_pmap2_mapping(&pdu->zdr, &m) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP2/UNSET call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP2/UNSET pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap2_dump_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V2, PMAP2_DUMP, cb, private_data, (zdrproc_t)zdr_pmap2_dump_result, sizeof(pmap2_dump_result));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP2/DUMP call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP2/DUMP pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap2_callit_async(struct rpc_context *rpc, int program, int version, int procedure, char *data, int datalen, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;
	struct pmap2_call_args ca;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V2, PMAP2_CALLIT, cb, private_data, (zdrproc_t)zdr_pmap2_call_result, sizeof(pmap2_call_result));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP2/CALLIT call");
		return -1;
	}

	ca.prog = program;
	ca.vers = version;
	ca.proc = procedure;
	ca.args.args_len = datalen;
	ca.args.args_val = data;

	if (zdr_pmap2_call_args(&pdu->zdr, &ca) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP2/CALLIT call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP2/CALLIT pdu: %s", rpc_get_error(rpc));
		return -1;
	}

	return 0;
}

/*
 * PORTMAP v3
 */
int rpc_pmap3_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_NULL, cb, private_data, (zdrproc_t)zdr_void, 0);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/NULL call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for PORTMAP3/NULL call");
		return -1;
	}

	return 0;
}

int rpc_pmap3_set_async(struct rpc_context *rpc, struct pmap3_mapping *map, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_SET, cb, private_data, (zdrproc_t)zdr_int, sizeof(uint32_t));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/SET call");
		return -1;
	}

	if (zdr_pmap3_mapping(&pdu->zdr, map) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP3/SET call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP3/SET pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap3_unset_async(struct rpc_context *rpc, struct pmap3_mapping *map, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_UNSET, cb, private_data, (zdrproc_t)zdr_int, sizeof(uint32_t));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/UNSET call");
		return -1;
	}

	if (zdr_pmap3_mapping(&pdu->zdr, map) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP3/UNSET call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP3/UNSET pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap3_getaddr_async(struct rpc_context *rpc, struct pmap3_mapping *map, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_GETADDR, cb, private_data, (zdrproc_t)zdr_pmap3_string_result, sizeof(pmap3_string_result));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/GETADDR call");
		return -1;
	}

	if (zdr_pmap3_mapping(&pdu->zdr, map) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP3/GETADDR call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP3/GETADDR pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap3_dump_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_DUMP, cb, private_data, (zdrproc_t)zdr_pmap3_dump_result, sizeof(pmap3_dump_result));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/DUMP call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP3/DUMP pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap3_gettime_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_GETTIME, cb, private_data, (zdrproc_t)zdr_int, sizeof(uint32_t));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/GETTIME call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP3/GETTIME pdu");
		return -1;
	}

	return 0;
}

int rpc_pmap3_callit_async(struct rpc_context *rpc, int program, int version, int procedure, char *data, int datalen, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;
	struct pmap3_call_args ca;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_CALLIT, cb, private_data, (zdrproc_t)zdr_pmap3_call_result, sizeof(pmap3_call_result));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/CALLIT call");
		return -1;
	}

	ca.prog = program;
	ca.vers = version;
	ca.proc = procedure;
	ca.args.args_len = datalen;
	ca.args.args_val = data;

	if (zdr_pmap3_call_args(&pdu->zdr, &ca) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP3/CALLIT call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP3/CALLIT pdu: %s", rpc_get_error(rpc));
		return -1;
	}

	return 0;
}

int rpc_pmap3_uaddr2taddr_async(struct rpc_context *rpc, char *uaddr, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_UADDR2TADDR, cb, private_data, (zdrproc_t)zdr_pmap3_netbuf, sizeof(pmap3_netbuf));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/UADDR2TADDR call");
		return -1;
	}

	if (zdr_string(&pdu->zdr, &uaddr, 255) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP3/UADDR2TADDR call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP3/UADDR2TADDR pdu: %s", rpc_get_error(rpc));
		return -1;
	}

	return 0;
}

int rpc_pmap3_taddr2uaddr_async(struct rpc_context *rpc, struct pmap3_netbuf *nb, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, PMAP_PROGRAM, PMAP_V3, PMAP3_TADDR2UADDR, cb, private_data, (zdrproc_t)zdr_pmap3_string_result, sizeof(pmap3_string_result));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for PORTMAP3/TADDR2UADDR call");
		return -1;
	}

	if (zdr_pmap3_netbuf(&pdu->zdr, nb) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode data for PORTMAP3/TADDR2UADDR call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Failed to queue PORTMAP3/TADDR2UADDR pdu: %s", rpc_get_error(rpc));
		return -1;
	}

	return 0;
}
