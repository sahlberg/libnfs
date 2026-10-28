/*
 * Copyright 2026 libnfs fuzzing effort
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * libnfs_url_fuzzer - exercise the nfs:// URL parser (lib/libnfs.c).
 *
 * Threat model:
 * - Untrusted input: nfs:// URLs are handed to libnfs by applications and
 *   are frequently assembled from user-typed or remote-provided strings
 *   (mount helpers, gvfs/kio slaves, management UIs).  The parser is a
 *   hand-rolled string scanner: a required "nfs://" prefix, %-hex unescaping
 *   with an in-place memmove, server/port splitting with strtol, path/file
 *   splitting on '/' and option splitting on '?' with flag scanning.
 * - Trust boundary crossed: nfs_parse_url_full()/nfs_parse_url_dir()/
 *   nfs_parse_url_incomplete() -- the three exported entry points all funnel
 *   into the same nfs_parse_url() core; each exercise different tail
 *   handling (file vs directory vs incomplete).
 * - Attacker controls: the whole URL string.
 * - Real bug here: OOB read/move in the %-unescape loop, off-by-one/port
 *   parsing issues (strtol + end_ptr), path/file/option splitting edge
 *   cases, leaks on the many early-error returns.
 *
 * Design notes:
 * - the same fuzzed URL is parsed through all three exported variants on a
 *   fresh nfs_context, and every returned nfs_url is released with
 *   nfs_destroy_url(), so LSan reports only genuine product leaks;
 * - input is a NUL-terminated C string by API contract: embedded NULs are
 *   rejected and the size is capped at 4 KiB (URL lengths beyond that are
 *   not a real input class, only fuzzing overhead);
 * - the parser requires the "nfs://" prefix and returns immediately
 *   otherwise; the seed corpus and dictionary focus on the prefix plus the
 *   split/escape/option syntax so mutations stay past the gate.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nfsc/libnfs.h"

#define MAX_URL_LEN 4096

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *url;
	struct nfs_context *nfs;
	struct nfs_url *u;

	if (size < 7 || size > MAX_URL_LEN)
		return 0;

	/* the API is NUL-terminated: embedded NULs only hide the tail */
	if (memchr(data, 0, size) != NULL)
		return 0;

	url = (char *)malloc(size + 1);
	if (url == NULL)
		return 0;
	memcpy(url, data, size);
	url[size] = '\0';

	nfs = nfs_init_context();
	if (nfs != NULL) {
		u = nfs_parse_url_full(nfs, url);
		if (u != NULL)
			nfs_destroy_url(u);

		u = nfs_parse_url_dir(nfs, url);
		if (u != NULL)
			nfs_destroy_url(u);

		u = nfs_parse_url_incomplete(nfs, url);
		if (u != NULL)
			nfs_destroy_url(u);

		nfs_destroy_context(nfs);
	}

	free(url);
	return 0;
}
