/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* A long MOUNT EXPORT reply must decode without one stack frame per entry. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnfs-zdr.h"
#include "libnfs-raw-mount.h"

#define CHECK(expr) do { if (!(expr)) { \
        fprintf(stderr, "FAIL %d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

#define NODES (1024 * 1024)

int main(void)
{
        /* more, empty ex_dir, no groups; the last node ends the list */
        size_t len = (size_t)NODES * 12 + 4;
        unsigned char *wire = calloc(1, len);
        exports ex = NULL;
        exportnode *e;
        size_t i, n = 0;
        ZDR zdr;

        CHECK(wire != NULL);
        for (i = 0; i < NODES; i++) {
                wire[i * 12 + 3] = 1;
        }
        zdrmem_create(&zdr, (char *)wire, (uint32_t)len, ZDR_DECODE);
        CHECK(zdr_exports(&zdr, &ex));
        for (e = ex; e; e = e->ex_next) {
                CHECK(e->ex_dir[0] == 0 && e->ex_groups == NULL);
                n++;
        }
        CHECK(n == NODES);
        zdr_destroy(&zdr);
        free(wire);

        puts("PASS: long export list decodes iteratively");
        return 0;
}
