/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnfs-zdr.h"

#define CHECK(expr, message) do { if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", message); exit(1); \
} } while (0)

union aligned_value {
        uint64_t u64;
        long double ld;
        void *ptr;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
        max_align_t max_align;
#endif
};

struct alignment_probe {
        char byte;
        union aligned_value value;
};

static void check_alignment(const void *ptr)
{
        CHECK(ptr != NULL, "allocation failed");
        CHECK((uintptr_t)ptr % offsetof(struct alignment_probe, value) == 0,
              "zdr_malloc returned a misaligned address");
}

static bool_t decode_uint64(ZDR *zdr, void *value, ...)
{
        return zdr_uint64_t(zdr, value);
}

static void check_allocations(void)
{
        static const uint32_t sizes[] = { 0, 1, 2, 3, 7, 8, 15, 16, 31, 257, 4096 };
        unsigned char *blocks[sizeof(sizes) / sizeof(sizes[0])];
        ZDR zdr;
        size_t i, j;
        unsigned int cycle;

        for (cycle = 0; cycle < 100; cycle++) {
                zdrmem_create(&zdr, NULL, 0, ZDR_DECODE);
                for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
                        blocks[i] = zdr_malloc(&zdr, sizes[i]);
                        check_alignment(blocks[i]);
                        memset(blocks[i], (int)i, sizes[i]);
                }
                for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
                        for (j = 0; j < sizes[i]; j++) {
                                CHECK(blocks[i][j] == (unsigned char)i,
                                      "allocation contents were overwritten");
                        }
                }
                CHECK(zdr_malloc(&zdr, UINT32_C(1073741825)) == NULL,
                      "allocation above the 1 GiB limit succeeded");
                CHECK(zdr_malloc(&zdr, UINT32_MAX) == NULL,
                      "maximum uint32 allocation succeeded");
                zdr_destroy(&zdr);
                CHECK(zdr.mem == NULL, "allocation list was not cleared");
                zdr_destroy(&zdr);
        }
        puts("PASS: aligned allocations, boundaries, contents and destruction");
}

static void check_typed_access(void)
{
        ZDR zdr;
        uint64_t *integer;
        long double *floating;
        void **pointer;

        zdrmem_create(&zdr, NULL, 0, ZDR_DECODE);
        integer = zdr_malloc(&zdr, sizeof(*integer));
        floating = zdr_malloc(&zdr, sizeof(*floating));
        pointer = zdr_malloc(&zdr, sizeof(*pointer));
        check_alignment(integer);
        check_alignment(floating);
        check_alignment(pointer);
        *integer = UINT64_C(0x123456789abcdef0);
        *floating = 1.25L;
        *pointer = integer;
        CHECK(*integer == UINT64_C(0x123456789abcdef0), "uint64 access failed");
        CHECK(*floating == 1.25L, "long double access failed");
        CHECK(*pointer == integer, "pointer access failed");
        zdr_destroy(&zdr);
        puts("PASS: typed uint64, long double and pointer access");
}

static void check_decoding(void)
{
        uint32_t wire[32];
        uint64_t values[] = { UINT64_C(0x0123456789abcdef), UINT64_MAX, 0 };
        uint64_t *array = values, *single = values, *decoded_array = NULL;
        uint64_t *decoded_single = NULL;
        uint32_t count = 3, decoded_count = 0, length;
        ZDR encoder, decoder;

        zdrmem_create(&encoder, (char *)wire, sizeof(wire), ZDR_ENCODE);
        CHECK(zdr_array(&encoder, (char **)&array, &count, 3, sizeof(*array),
                        decode_uint64), "array encoding failed");
        CHECK(zdr_pointer(&encoder, (char **)&single, sizeof(*single),
                          decode_uint64), "pointer encoding failed");
        length = zdr_getpos(&encoder);
        zdr_destroy(&encoder);

        zdrmem_create(&decoder, (char *)wire, length, ZDR_DECODE);
        CHECK(zdr_array(&decoder, (char **)&decoded_array, &decoded_count, 3,
                        sizeof(*decoded_array), decode_uint64),
              "array decoding failed");
        CHECK(zdr_pointer(&decoder, (char **)&decoded_single,
                          sizeof(*decoded_single), decode_uint64),
              "pointer decoding failed");
        check_alignment(decoded_array);
        check_alignment(decoded_single);
        CHECK(decoded_count == count, "decoded array length changed");
        CHECK(memcmp(decoded_array, values, sizeof(values)) == 0,
              "decoded array contents changed");
        CHECK(*decoded_single == values[0], "decoded pointer contents changed");
        CHECK(zdr_getpos(&decoder) == length, "decode position changed");
        zdr_destroy(&decoder);
        CHECK(decoder.mem == NULL, "decoded allocations were not released");
        puts("PASS: uint64 array and pointer decoding");
}

int main(void)
{
        check_allocations();
        check_typed_access();
        check_decoding();
        puts("PASS: all ZDR alignment regression cases");
        return 0;
}
