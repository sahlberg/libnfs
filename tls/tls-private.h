/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2024 by Linuxsmiths <linuxsmiths@gmail.com>

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

#ifndef __TLS_PRIVATE_H__
#define __TLS_PRIVATE_H__

/*
 * Use this instead of RPC_LOG() inside this file as we don't want to pass around
 * rpc_context structure to various functions here as they don't really need the
 * rpc_context.
 * Note that just like RPC_LOG TLS_LOG() is also controlled by debug= libnfs option.
 */
#define TLS_LOG(level, format, ...) \
	do { \
		if (level <= tls_log_level) { \
			fprintf(stderr, "libnfs(tls):%d " format "\n", level, ## __VA_ARGS__); \
		} \
	} while (0)

#ifdef __cplusplus
extern "C" {
#endif

extern int tls_log_level;
extern int setup_ktls(gnutls_session_t session);

#ifdef __cplusplus
}
#endif

#endif /* __TLS_PRIVATE_H__ */
