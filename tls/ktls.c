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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <gnutls/gnutls.h>
#include <gnutls/socket.h>
#include <linux/tls.h>

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#include "tls-private.h"

#ifndef _U_
#define _U_ __attribute__((unused))
#endif

/*
 * Older gnutls versions don't have kTLS support and don't export
 * gnutls_transport_is_ktls_enabled().
 */
#ifdef HAVE_GNUTLS_TRANSPORT_IS_KTLS_ENABLED
/*
 * Check if gnutls_handshake() has enabled kTLS (and installed security keys)
 * for this sesssion for the given direction identified by 'read'.
 */
static bool tls_is_ktls_enabled(gnutls_session_t session, bool read)
{
	const int ret = gnutls_transport_is_ktls_enabled(session);

	if (ret == GNUTLS_E_UNIMPLEMENTED_FEATURE) {
		TLS_LOG(1, "gnutls version %s has kTLS support but kTLS is not "
			"enabled! Try building gnutls with kTLS support.",
			gnutls_check_version("0.0.0"));
		return false;
	}

	if (read) {
		if (!(ret & GNUTLS_KTLS_RECV)) {
			/*
			 * If gnutls has kTLS support there's no reason it'll
			 * not enable kTLS in both send and recv direction so
			 * log with higher priority.
			 * Note that Linux kernel versions >= 4.13 and < 4.17
			 * didn't have TLS_RX support so they don't support TLS
			 * recv offload. We need both TLS_TX and TLS_RX offload.
			 */
			TLS_LOG(1, "gnutls has *NOT* enabled receive kTLS for this session");
			return false;
		}
		TLS_LOG(2, "gnutls has enabled receive kTLS for this session");
	} else {
		if (!(ret & GNUTLS_KTLS_SEND)) {
			TLS_LOG(1, "gnutls has *NOT* enabled send kTLS for this session");
			return false;
		}
		TLS_LOG(2, "gnutls has enabled send kTLS for this session");
	}

	return true;
}
#else
static bool tls_is_ktls_enabled(gnutls_session_t session _U_, bool read _U_)
{
	return false;
}
#endif

static int ktls_setsockopt(int sock, bool read, const void *info, socklen_t infolen)
{
	const int ret = setsockopt(sock, SOL_TLS, read ? TLS_RX : TLS_TX, info, infolen);
	if (!ret) {
		TLS_LOG(2, "setsockopt(%s) success", read ? "TLS_RX" : "TLS_TX");
		return 0;
	}

	if (errno == EBUSY) {
		/*
		 * EBUSY indicates crypto info is already set for the socket in the
		 * given direction. Treat it as success.
		 *
		 * Note: Unless gnutls_transport_is_ktls_enabled() lies to us this
		 *       shouldn't happen but take care just in case.
		 */
		TLS_LOG(1, "setsockopt(%s) returned(%d): %s. Treating as success!",
			read ? "TLS_RX" : "TLS_TX", errno, strerror(errno));
		return 0;
	}

	TLS_LOG(1, "setsockopt(%s) failed(%d): %s",
		read ? "TLS_RX" : "TLS_TX", errno, strerror(errno));

	return -1;
}

#define tls12_crypto_info_AES_GCM_128 		tls12_crypto_info_aes_gcm_128
#define tls12_crypto_info_AES_GCM_256 		tls12_crypto_info_aes_gcm_256
#define tls12_crypto_info_AES_CCM_128 		tls12_crypto_info_aes_ccm_128
#define tls12_crypto_info_CHACHA20_POLY1305	tls12_crypto_info_chacha20_poly1305

#define GENERATE_SET_CRYPTO_INFO(CIPHER) 				\
static int ktls_set_##CIPHER##_info(gnutls_session_t session) 		\
{ 									\
	const bool is_tls12 = 						\
		(gnutls_protocol_get_version(session) == GNUTLS_TLS1_2);\
	struct tls12_crypto_info_##CIPHER info = { 			\
		.info.version           = (is_tls12 ? TLS_1_2_VERSION	\
						    : TLS_1_3_VERSION), \
		.info.cipher_type       = TLS_CIPHER_##CIPHER, 		\
	}; 								\
	unsigned char seq_number[12]; 					\
	gnutls_datum_t cipher_key; 					\
	gnutls_datum_t mac_key; 					\
	gnutls_datum_t iv;						\
	int ret, read;							\
	const int sockfd = gnutls_transport_get_int(session);		\
									\
	/* (read == 0) => send, (read == 1) => recv */			\
	for (read = 0; read <= 1; read++) {				\
		if (tls_is_ktls_enabled(session, read))			\
			continue;					\
									\
		ret = gnutls_record_get_state(session,			\
					      read, 			\
					      &mac_key, 		\
					      &iv, 			\
					      &cipher_key, 		\
					      seq_number);		\
		if (ret != GNUTLS_E_SUCCESS) { 				\
			TLS_LOG(1, "gnutls_record_get_state "		\
				"failed(%d): %s",			\
				ret, gnutls_strerror(ret));		\
			return -1;					\
		}							\
									\
		/* for TLS 1.2 IV is generated in kernel */		\
		if (is_tls12) {						\
			memcpy(info.iv, seq_number,			\
			       TLS_CIPHER_##CIPHER##_IV_SIZE);		\
		} else {						\
			memcpy(info.iv,					\
			       iv.data + TLS_CIPHER_##CIPHER##_SALT_SIZE,\
			       TLS_CIPHER_##CIPHER##_IV_SIZE);		\
		}							\
		memcpy(info.salt, iv.data,				\
		       TLS_CIPHER_##CIPHER##_SALT_SIZE);		\
		memcpy(info.key, cipher_key.data,			\
		       TLS_CIPHER_##CIPHER##_KEY_SIZE);			\
		memcpy(info.rec_seq, seq_number,			\
		       TLS_CIPHER_##CIPHER##_REC_SEQ_SIZE);		\
									\
		if (ktls_setsockopt(sockfd, read, &info,		\
				    sizeof(info)) != 0) {		\
			TLS_LOG(1, "Failed to set crypto info for %s",	\
				#CIPHER);				\
			return -1;					\
		}							\
	}								\
	return 0;							\
}

#define SET_CRYPTO_INFO(CIPHER, session) ktls_set_##CIPHER##_info(session)

#if defined(TLS_CIPHER_AES_GCM_128)
GENERATE_SET_CRYPTO_INFO(AES_GCM_128)
#endif

#if defined(TLS_CIPHER_AES_GCM_256)
GENERATE_SET_CRYPTO_INFO(AES_GCM_256)
#endif

#if defined(TLS_CIPHER_AES_CCM_128)
GENERATE_SET_CRYPTO_INFO(AES_CCM_128)
#endif

#if defined(TLS_CIPHER_CHACHA20_POLY1305)
GENERATE_SET_CRYPTO_INFO(CHACHA20_POLY1305)
#endif

int setup_ktls(gnutls_session_t session)
{
	const gnutls_cipher_algorithm_t cipher = gnutls_cipher_get(session);

	TLS_LOG(2, "setup_ktls(session=%p, fd=%d)",
		session, gnutls_transport_get_int(session));

	/*
	 * Before we can set crypto info, need to set ULP=TLS.
	 */
	if (setsockopt(gnutls_transport_get_int(session), SOL_TCP, TCP_ULP,
		       "tls", sizeof("tls")) == -1) {
		TLS_LOG(1, "setsockopt(TLS_ULP) failed(%d): %s", errno, strerror(errno));
		return -1;
	}

	switch (cipher) {
#if defined(TLS_CIPHER_AES_GCM_128)
		case GNUTLS_CIPHER_AES_128_GCM:
			TLS_LOG(2, "Got cipher AES_GCM_128");
			return SET_CRYPTO_INFO(AES_GCM_128, session);
#endif
#if defined(TLS_CIPHER_AES_GCM_256)
		case GNUTLS_CIPHER_AES_256_GCM:
			TLS_LOG(2, "Got cipher AES_GCM_256");
			return SET_CRYPTO_INFO(AES_GCM_256, session);
#endif
#if defined(TLS_CIPHER_AES_CCM_128)
		case GNUTLS_CIPHER_AES_128_CCM:
			TLS_LOG(2, "Got cipher AES_CCM_128");
			return SET_CRYPTO_INFO(AES_CCM_128, session);
#endif
#if defined(TLS_CIPHER_CHACHA20_POLY1305)
		case GNUTLS_CIPHER_CHACHA20_POLY1305:
			TLS_LOG(2, "Got cipher CHACHA20_POLY1305");
			return SET_CRYPTO_INFO(CHACHA20_POLY1305, session);
#endif
		default:
			TLS_LOG(1, "Unsupported cipher %d", cipher);
	}

	return -1;
}
