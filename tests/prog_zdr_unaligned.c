/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* A record whose length is not a multiple of four must fail to decode, not abort. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnfs-zdr.h"

#define CHECK(expr) do { if (!(expr)) { \
        fprintf(stderr, "FAIL %d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

/* A one byte opaque or string with its padding cut off. */
static unsigned char wire[5] = { 0, 0, 0, 1, 'a' };

int main(void)
{
        uint32_t size, u;
        uint64_t u64;
        char *bytes = NULL, *str = NULL;
        ZDR zdr;

        zdrmem_create(&zdr, (char *)wire, sizeof(wire), ZDR_DECODE);
        CHECK(zdr_bytes(&zdr, &bytes, &size, 16));
        CHECK(size == 1);
        CHECK(!zdr_u_int(&zdr, &u));
        CHECK(!zdr_uint64_t(&zdr, &u64));
        zdr_destroy(&zdr);

        zdrmem_create(&zdr, (char *)wire, sizeof(wire), ZDR_DECODE);
        CHECK(zdr_string(&zdr, &str, 16));
        CHECK(!strcmp(str, "a"));
        CHECK(!zdr_u_int(&zdr, &u));
        zdr_destroy(&zdr);

        puts("PASS: unaligned record end fails the decode");
        return 0;
}
