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

#ifdef WIN32
#include "win32_compat.h"
#endif/*WIN32*/

#include <stdio.h>
#include <errno.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#include "libnfs-raw-nlm.h"

int rpc_nlm_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NLM_PROGRAM, NLM_V4, NLM4_NULL, cb, private_data, (xdrproc_t)xdr_void, 0);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for nlm/null call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for nlm/null call");
		rpc_free_pdu(rpc, pdu);
		return -1;
	}

	return 0;
}

char *nlmstat4_to_str(int st)
{
	enum nlmstat4 stat = st;

	char *str = "unknown nlm stat";
	switch (stat) {
	case NLM4_GRANTED: str="NLM4_GRANTED";break;
	case NLM4_DENIED: str="NLM4_DENIED";break;
	case NLM4_DENIED_NOLOCKS: str="NLM4_DENIED_NOLOCKS";break;
	case NLM4_BLOCKED: str="NLM4_BLOCKED";break;
	case NLM4_DENIED_GRACE_PERIOD: str="NLM4_DENIED_GRACE_PERIOD";break;
	case NLM4_DEADLCK: str="NLM4_DEADLCK";break;
	case NLM4_ROFS: str="NLM4_ROFS";break;
	case NLM4_STALE_FH: str="NLM4_STALE_FH";break;
	case NLM4_FBIG: str="NLM4_FBIG";break;
	case NLM4_FAILED: str="NLM4_FAILED";break;
	}
	return str;
}




