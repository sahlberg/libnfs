/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnfs-zdr.h"

#define CHECK(expr, message) do { if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", message); exit(1); \
} } while (0)

static void check_untouched(const unsigned char *bytes, size_t first, size_t end)
{
        size_t i;

        for (i = first; i < end; i++) {
                CHECK(bytes[i] == 0xa5, "bytes outside the field changed");
        }
}

static void check_round_trip(uint32_t length, int null_payload)
{
        uint32_t wire[8];
        unsigned char payload[] = { 0, 0x80, 2, 3, 4, 5, 6, 7, 0xff };
        unsigned char destination[16];
        unsigned char *bytes = (unsigned char *)wire;
        char *input = null_payload ? NULL : (char *)payload;
        char *borrowed = NULL, *copied = (char *)destination;
        uint32_t size = length, borrowed_size = 99, copied_size = 99;
        uint32_t field_size = 4 + ((length + 3) & ~UINT32_C(3));
        uint32_t next = UINT32_C(0x12345678), decoded_next = 0, i;
        ZDR encoder, decoder;

        memset(wire, 0xa5, sizeof(wire));
        zdrmem_create(&encoder, (char *)wire, sizeof(wire), ZDR_ENCODE);
        CHECK(zdr_bytes(&encoder, &input, &size, sizeof(payload)),
              "byte field encoding failed");
        CHECK(size == length, "encoder changed the payload length");
        CHECK(input == (null_payload ? NULL : (char *)payload),
              "encoder changed the payload pointer");
        CHECK(zdr_getpos(&encoder) == field_size, "incorrect encoded field size");
        CHECK(bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == length,
              "incorrect wire length");
        CHECK(memcmp(bytes + 4, payload, length) == 0, "payload changed");
        for (i = 4 + length; i < field_size; i++) {
                CHECK(bytes[i] == 0, "padding is not zero");
        }
        check_untouched(bytes, field_size, sizeof(wire));
        CHECK(zdr_u_int(&encoder, &next), "following field encoding failed");
        CHECK(zdr_getpos(&encoder) == field_size + 4,
              "following field position changed");
        check_untouched(bytes, field_size + 4, sizeof(wire));
        zdr_destroy(&encoder);

        zdrmem_create(&decoder, (char *)wire, field_size + 4, ZDR_DECODE);
        CHECK(zdr_bytes(&decoder, &borrowed, &borrowed_size, sizeof(payload)),
              "borrowed byte field decoding failed");
        CHECK(borrowed_size == length && borrowed == (char *)wire + 4,
              "borrowed buffer semantics changed");
        CHECK(memcmp(borrowed, payload, length) == 0, "borrowed payload changed");
        CHECK(zdr_getpos(&decoder) == field_size, "borrowed decode position changed");
        CHECK(zdr_u_int(&decoder, &decoded_next) && decoded_next == next,
              "following field decoding failed");
        zdr_destroy(&decoder);

        memset(destination, 0xa5, sizeof(destination));
        zdrmem_create(&decoder, (char *)wire, field_size, ZDR_DECODE);
        CHECK(zdr_bytes(&decoder, &copied, &copied_size, sizeof(destination)),
              "preallocated byte field decoding failed");
        CHECK(copied_size == length && copied == (char *)destination,
              "preallocated buffer semantics changed");
        CHECK(memcmp(destination, payload, length) == 0, "copied payload changed");
        check_untouched(destination, length, sizeof(destination));
        CHECK(zdr_getpos(&decoder) == field_size, "copied decode position changed");
        zdr_destroy(&decoder);
}

static void check_empty_exact_fit(void)
{
        uint32_t wire[4];
        char *payload = NULL, *decoded = NULL;
        uint32_t size = 0, decoded_size = 99;
        unsigned char *bytes = (unsigned char *)wire;
        ZDR encoder, decoder;

        memset(wire, 0xa5, sizeof(wire));
        zdrmem_create(&encoder, (char *)wire, 4, ZDR_ENCODE);
        CHECK(zdr_bytes(&encoder, &payload, &size, 0), "empty exact-fit encoding failed");
        CHECK(zdr_getpos(&encoder) == 4 && wire[0] == 0,
              "empty field must still encode its four-byte length");
        check_untouched(bytes, 4, sizeof(wire));
        zdr_destroy(&encoder);

        zdrmem_create(&decoder, (char *)wire, 4, ZDR_DECODE);
        CHECK(zdr_bytes(&decoder, &decoded, &decoded_size, 0),
              "empty exact-fit decoding failed");
        CHECK(decoded_size == 0 && decoded == (char *)wire + 4,
              "empty borrowed buffer semantics changed");
        CHECK(zdr_getpos(&decoder) == 4, "empty decode position changed");
        zdr_destroy(&decoder);
}

static void check_short_buffers(void)
{
        uint32_t wire[4], capacity, size;
        unsigned char *bytes = (unsigned char *)wire;
        char data[] = { 1, 2, 3 };
        char *payload;
        ZDR encoder;

        for (capacity = 0; capacity < 4; capacity++) {
                memset(wire, 0xa5, sizeof(wire));
                payload = NULL;
                size = 0;
                zdrmem_create(&encoder, (char *)wire, capacity, ZDR_ENCODE);
                CHECK(!zdr_bytes(&encoder, &payload, &size, 0),
                      "missing length word was accepted");
                CHECK(zdr_getpos(&encoder) == 0, "failed length write advanced position");
                check_untouched(bytes, 0, sizeof(wire));
                zdr_destroy(&encoder);
        }
        for (capacity = 4; capacity < 8; capacity++) {
                memset(wire, 0xa5, sizeof(wire));
                payload = data;
                size = sizeof(data);
                zdrmem_create(&encoder, (char *)wire, capacity, ZDR_ENCODE);
                CHECK(!zdr_bytes(&encoder, &payload, &size, sizeof(data)),
                      "truncated payload or padding was accepted");
                CHECK(zdr_getpos(&encoder) == 4, "failed payload write advanced position");
                CHECK(bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 3,
                      "payload failure changed the encoded length");
                check_untouched(bytes, 4, sizeof(wire));
                zdr_destroy(&encoder);
        }
}

int main(void)
{
        uint32_t length;

        /* UBSan must also instrument libnfs-zdr.c to detect the original bug. */
        check_round_trip(0, 1);
        check_round_trip(0, 0);
        check_empty_exact_fit();
        puts("PASS: empty NULL/non-NULL payloads, wire length and exact fit");
        for (length = 1; length <= 9; length++) {
                check_round_trip(length, 0);
        }
        puts("PASS: nonempty payloads, padding, following field and both decode modes");
        check_short_buffers();
        puts("PASS: truncated headers, payloads and padding are rejected");
        puts("PASS: all ZDR zero-length byte regression cases");
        return 0;
}
