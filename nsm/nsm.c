/*
   Copyright (C) 2013 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#include "win32_compat.h"
#endif/*WIN32*/

#include <stdio.h>
#include <errno.h>
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#include "libnfs-raw-nsm.h"

int rpc_nsm1_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NSM_PROGRAM, NSM_V1, NSM1_NULL, cb, private_data, (zdrproc_t)zdr_void, 0);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for nsm/null call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for nsm/null call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	return 0;
}

#if 0
int rpc_nlm4_test_async(struct rpc_context *rpc, rpc_cb cb, struct NLM4_TESTargs *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NLM_PROGRAM, NLM_V4, NLM4_TEST, cb, private_data, (zdrproc_t)zdr_NLM4_TESTres, sizeof(NLM4_TESTres));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for nlm/test call");
		return -1;
	}

	if (zdr_NLM4_TESTargs(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode NLM4_TESTargs");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for nlm/test call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	return 0;
}

int rpc_nlm4_lock_async(struct rpc_context *rpc, rpc_cb cb, struct NLM4_LOCKargs *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NLM_PROGRAM, NLM_V4, NLM4_LOCK, cb, private_data, (zdrproc_t)zdr_NLM4_LOCKres, sizeof(NLM4_LOCKres));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for nlm/lock call");
		return -1;
	}

	if (zdr_NLM4_LOCKargs(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode NLM4_LOCKargs");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for nlm/lock call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	return 0;
}

int rpc_nlm4_cancel_async(struct rpc_context *rpc, rpc_cb cb, struct NLM4_CANCargs *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NLM_PROGRAM, NLM_V4, NLM4_CANCEL, cb, private_data, (zdrproc_t)zdr_NLM4_CANCres, sizeof(NLM4_CANCres));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for nlm/cancel call");
		return -1;
	}

	if (zdr_NLM4_CANCargs(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode NLM4_CANCargs");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for nlm/cancel call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	return 0;
}

int rpc_nlm4_unlock_async(struct rpc_context *rpc, rpc_cb cb, struct NLM4_UNLOCKargs *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NLM_PROGRAM, NLM_V4, NLM4_UNLOCK, cb, private_data, (zdrproc_t)zdr_NLM4_UNLOCKres, sizeof(NLM4_UNLOCKres));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for nlm/unlock call");
		return -1;
	}

	if (zdr_NLM4_UNLOCKargs(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode NLM4_UNLOCKargs");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for nlm/unlock call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	return 0;
}
#endif

char *nsmstat1_to_str(int st)
{
	enum nsmstat1 stat = st;

	char *str = "unknown n1m stat";
	switch (stat) {
	case NSM_STAT_SUCC: str="NSM_STAT_SUCC";break;
	case NSM_STAT_FAIL: str="NSM_STAT_FAIL";break;
	}
	return str;
}
