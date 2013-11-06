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
