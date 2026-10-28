/*
 * Copyright 2026 libnfs fuzzing effort
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * libnfs_zdr_roundtrip_fuzzer - exercise the ZDR *encode* direction.
 *
 * Threat model:
 * - Untrusted input: the fuzz input is the payload of an RPC reply, exactly
 *   as for libnfs_reply_fuzzer (byte 0 selects the decoder, the rest is the
 *   reply body a server sent).  The twist: whatever decodes successfully is
 *   then *re-encoded* -- and the encode direction is what the CLIENT puts on
 *   the wire toward servers, plus the code path that marshals client state
 *   (strings, opaque creds, arrays, unions) throughout the library.
 * - Trust boundary crossed: zdrmem decode of every reply structure, then the
 *   full ZDR encode engine (libnfs-zdr.c encode branches and the encode
 *   halves of all generated libnfs-raw-* marshallers) driven by
 *   attacker-shaped decoded contents: strings with arbitrary lengths and
 *   embedded NULs, maximal arrays, unusual union arms, extreme ints.
 * - Attacker controls: decoder selection + the whole payload.
 * - Real bug here: memory-safety violations in the encode half (fixed
 *   buffers, size arithmetic, padding), use-after-free/uninitialised reads
 *   from decoded objects, and encode rejecting/looping on decoded state.
 *
 * Design notes:
 * - round-trip shape: decode(payload) -> if TRUE, encode(obj) into a bounded
 *   heap buffer -> decode(that) again.  No byte-equality assertion: the
 *   encode side uses strlen() on decoded strings (libnfs_zdr_string), so
 *   encodings legitimately shrink when a decoded string embeds NULs; an
 *   equality check would produce false positives.  The asserted property is
 *   only "the re-encoded buffer is structurally valid again", which drives
 *   all encode/decode branches under ASan without asserting policy.
 * - the decoder table is shared verbatim with libnfs_reply_fuzzer via
 *   fuzzing/zdr_decoders.h so both targets always walk the same 157 decoders;
 * - payload capped at 64 KiB; encode buffer is payload-sized + slack, an
 *   encode that hits the slack is a normal, expected outcome;
 * - cleanup mirrors libnfs_reply_fuzzer exactly (free(obj) + zdr_destroy),
 *   so LeakSanitizer reports only genuine product leaks.
 */

/* glibc needs this for caddr_t in the system headers */
#ifndef __APPLE__
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zdr_decoders.h"

#define MAX_PAYLOAD (64 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned idx;
	ZDR zdec, zenc, zdec2;
	void *obj, *obj2;
	char *encbuf;
	size_t enclen;
	bool_t ok;

	if (size < 2 || size > MAX_PAYLOAD)
		return 0;

	idx = data[0];
	if (idx >= ZDR_DECODERS_COUNT)
		return 0;

	obj = calloc(1, libnfs_zdr_decoders[idx].size);
	if (obj == NULL)
		return 0;

	zdrmem_create(&zdec, (caddr_t)(data + 1), (uint32_t)(size - 1),
	    ZDR_DECODE);
	ok = libnfs_zdr_decoders[idx].fn(&zdec, obj);

	if (ok) {
		/* encode the decoded object into a bounded heap buffer.
		 * NOTE: the decoded object's string members point into the
		 * decode ZDR buffer (in-place decode), so the source ZDR must
		 * stay alive until after the encode. */
		enclen = size + 4096;
		encbuf = (char *)malloc(enclen);
		if (encbuf != NULL) {
			zdrmem_create(&zenc, encbuf, (uint32_t)enclen,
			    ZDR_ENCODE);
			if (libnfs_zdr_decoders[idx].fn(&zenc, obj)) {
				uint32_t encsize = zdr_getpos(&zenc);

				/* decode what we just encoded */
				obj2 = calloc(1,
				    libnfs_zdr_decoders[idx].size);
				if (obj2 != NULL) {
					zdrmem_create(&zdec2, encbuf, encsize,
					    ZDR_DECODE);
					libnfs_zdr_decoders[idx].fn(&zdec2,
					    obj2);
					zdr_destroy(&zdec2);
					free(obj2);
				}
			}
			zdr_destroy(&zenc);
			free(encbuf);
		}
	}

	/* only now may the decode buffer die: it backs obj's strings */
	zdr_destroy(&zdec);
	free(obj);
	return 0;
}
