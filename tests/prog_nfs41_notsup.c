/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Check that a NFSv4.1 mount reports NFS_V4_1 and refuses the calls that only
 * NFSv4.2 defines (fallocate, SEEK_HOLE and SEEK_DATA) with -ENOTSUP, while
 * ordinary calls keep working.
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libnfs.h"

static void unexpected_cb(int status, struct nfs_context *nfs _U_,
                          void *data _U_, void *private_data _U_)
{
        fprintf(stderr, "A call that must be refused was queued "
                "(status %d)\n", status);
        exit(1);
}

static void expect_notsup(const char *what, int ret)
{
        if (ret != -ENOTSUP) {
                fprintf(stderr, "%s returned %d, expected %d (-ENOTSUP)\n",
                        what, ret, -ENOTSUP);
                exit(1);
        }
        printf("%s refused with -ENOTSUP\n", what);
}

int main(int argc, char *argv[])
{
        struct nfs_context *nfs;
        struct nfsfh *nfsfh;
        struct nfs_url *url;
        uint64_t current;

        if (argc != 4) {
                fprintf(stderr, "Usage: prog_nfs41_notsup <url> <cwd> <path>\n");
                exit(1);
        }

        nfs = nfs_init_context();
        if (nfs == NULL) {
                fprintf(stderr, "failed to init context\n");
                exit(1);
        }

        url = nfs_parse_url_full(nfs, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "%s\n", nfs_get_error(nfs));
                exit(1);
        }

        if (nfs_mount(nfs, url->server, url->path) != 0) {
                fprintf(stderr, "Failed to mount nfs share : %s\n",
                        nfs_get_error(nfs));
                exit(1);
        }

        if (nfs_get_version(nfs) != NFS_V4_1) {
                fprintf(stderr, "nfs_get_version() returned %d, expected "
                        "%d (NFS_V4_1)\n", nfs_get_version(nfs), NFS_V4_1);
                exit(1);
        }
        printf("nfs_get_version() is NFS_V4_1\n");

        if (nfs_chdir(nfs, argv[2]) != 0) {
                fprintf(stderr, "Failed to chdir to \"%s\" : %s\n",
                        argv[2], nfs_get_error(nfs));
                exit(1);
        }

        if (nfs_open(nfs, argv[3], O_RDWR, &nfsfh)) {
                fprintf(stderr, "Failed to open file : %s\n",
                        nfs_get_error(nfs));
                exit(1);
        }

        /*
         * The async calls refuse the request before queueing it, so the
         * callback must never run.
         */
        expect_notsup("fallocate(mode 0)",
                      nfs_fallocate_async(nfs, nfsfh, 0, 0, 4096,
                                          unexpected_cb, NULL));
        expect_notsup("fallocate(PUNCH_HOLE|KEEP_SIZE)",
                      nfs_fallocate_async(nfs, nfsfh,
                                          FALLOC_FL_PUNCH_HOLE |
                                          FALLOC_FL_KEEP_SIZE, 0, 4096,
                                          unexpected_cb, NULL));
        expect_notsup("fallocate(ZERO_RANGE)",
                      nfs_fallocate_async(nfs, nfsfh, FALLOC_FL_ZERO_RANGE,
                                          0, 4096, unexpected_cb, NULL));
        expect_notsup("lseek(SEEK_HOLE)",
                      nfs_lseek_async(nfs, nfsfh, 0, SEEK_HOLE,
                                      unexpected_cb, NULL));
        expect_notsup("lseek(SEEK_DATA)",
                      nfs_lseek_async(nfs, nfsfh, 0, SEEK_DATA,
                                      unexpected_cb, NULL));

        /* The refused calls must not have broken the mount. */
        if (nfs_lseek(nfs, nfsfh, 0, SEEK_END, &current)) {
                fprintf(stderr, "lseek(SEEK_END) failed after the refused "
                        "calls: %s\n", nfs_get_error(nfs));
                exit(1);
        }
        printf("lseek(SEEK_END) still works\n");

        nfs_close(nfs, nfsfh);
        nfs_destroy_url(url);
        nfs_destroy_context(nfs);

        return 0;
}
