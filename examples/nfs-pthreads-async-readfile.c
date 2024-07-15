/*
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2024
   Copyright (C) by Linuxsmiths <linuxsmiths@gmail.com> 2024

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

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif


#ifdef WIN32
#include <win32/win32_compat.h>
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#else
#include <sys/stat.h>
#include <string.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"

/*
 * Number of RPC transports to the server.
 * We will have these many connections to the NFS server carrying RPC
 * requests.
 */
#define NUM_CONTEXTS 4

/*
 * Number of threads parallely writing file data.
 * Usually one thread per context should be sufficient, but here we use more
 * threads to demonstrate that multiple threads can very well read to the same
 * context.
 *
 * Note: Don't set very high number of threads else it'll negatively impact
 *       performance.
 */
#define NUM_THREADS  8

/*
 * Max how many reads can be outstanding at any tine.
 * This will be divided by NUM_THREADS to decide per-thread outstanding.
 */
#define MAX_CONCURRENCY 1024

void usage(void)
{
        fprintf(stderr, "Usage: nfs-pthreads-async-readile <src> <dst>\n");
        fprintf(stderr, "<src> is an nfs URL, <dst> is a local file.\n");
        exit(0);
}

struct read_data {
        struct nfs_context *nfs;
        char *ptr;
        struct nfsfh *nfsfh;
        uint64_t offset;
        ssize_t len;
        int max_outstanding;
};

struct read_cb_data {
        atomic_int calls_in_flight;
        int status;
};

void read_async_cb(int status, struct nfs_context *nfs,
                   void *data, void *private_data)
{
        struct read_cb_data *read_cb_data = private_data;

        if (status < 0) {
                fprintf(stderr, "pread failed with \"%s\"\n", (char *)data);
                status = -EIO;
        }
        atomic_fetch_sub_explicit(&read_cb_data->calls_in_flight, 1, memory_order_relaxed);
}

/*
 * Thread that is created to read up to chunk_size part of the file.
 */
static void *nfs_read_thread(void *arg)
{
        struct read_data *rd = arg;
        ssize_t count;
        struct read_cb_data read_cb_data;
        struct timespec ts;

        read_cb_data.status = 0;
        read_cb_data.calls_in_flight = 0;

        while (rd->len) {
                /* 1MB read RPC is fair size */
                count = 1048576;
                if (count > rd->len) {
                        count = rd->len;
                }
                atomic_fetch_add_explicit(&read_cb_data.calls_in_flight, 1, memory_order_relaxed);
                if (nfs_pread_async(rd->nfs, rd->nfsfh,
                                    rd->ptr + rd->offset,
                                    count, rd->offset,
                                    read_async_cb, &read_cb_data) < 0) {
                        fprintf(stderr, "Failed to read from nfs file. %s\n", nfs_get_error(rd->nfs));
                        exit(1);
                }
                rd->offset += count;
                rd->len -= count;

                /* Wait a bit if we have max_outstanding IOs in flight */
                while(read_cb_data.calls_in_flight >= rd->max_outstanding) {
                      ts.tv_sec = 0;
                      ts.tv_nsec = 1000000;
                      nanosleep(&ts, NULL);
                }
        }

        /*
         * Wait for the final lot of outstanding reads to complete.
         */
        while(read_cb_data.calls_in_flight) {
                ts.tv_sec = 0;
                ts.tv_nsec = 1000000;
                nanosleep(&ts, NULL);
        }
        if (read_cb_data.status) {
                fprintf(stderr, "Oh, no, something went wrong\n");
                exit(1);
        }
        return NULL;
}

int main(int argc, char *argv[])
{
        int i;
        int fd = -1;
        uint64_t chunk_size;
        struct nfs_context *nfs[NUM_CONTEXTS] = {NULL,};
        struct nfs_url *url = NULL;
        pthread_t *read_threads;
        struct read_data *rd;
        struct nfsfh *nfsfh = NULL;
        struct nfs_stat_64 st;
        char *ptr;
        char *nfs_file = NULL;

#ifdef WIN32
        if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
                printf("Failed to start Winsock2\n");
                return 10;
        }
#endif

#ifdef AROS
        aros_init_socket();
#endif

        if (argc != 3) {
                usage();
        }


        /*
         * Create NUM_CONTEXT number of connections to the server, each
         * having its own service thread to perform all I/O to/from the
         * socket.
         */
        for (i = 0; i < NUM_CONTEXTS; i++) {
                nfs[i] = nfs_init_context();
                if (nfs[i] == NULL) {
                        fprintf(stderr, "failed to init context\n");
                        exit(1);
                }
                /*
                 * Bump the number of xid hashes so we don't have to spend
                 * too much time scanning the linked list for each hash bucket
                 * if we have very many threads doing i/o concurrently.
                 */
                nfs_set_hash_size(nfs[i], 50);
                if (url) {
                        nfs_destroy_url(url);
                }
                url = nfs_parse_url_full(nfs[i], argv[1]);
                if (url == NULL) {
                        fprintf(stderr, "%s\n", nfs_get_error(nfs[0]));
                        exit(1);
                }

                if (nfs_mount(nfs[i], url->server, url->path) != 0) {
                        fprintf(stderr, "Failed to mount nfs share : %s\n",
                                nfs_get_error(nfs[i]));
                        exit(1);
                }

                /*
                 * We just need to open the file once and can then just
                 * use the handle from all the other contexts too.
                 */
                if (i == 0) {
                        nfs_file = strdup(url->file);

                        if (nfs_open(nfs[0], url->file, O_RDONLY, &nfsfh) < 0) {
                                fprintf(stderr, "Failed to open nfs file %s. %s\n",
                                        url->file,
                                        nfs_get_error(nfs[0]));
                                exit(1);
                        }

                        /*
                         * Also query the file size so that we can create the
                         * dest file of the same size.
                         */
                        if (nfs_lstat64(nfs[0], url->file, &st) < 0) {
                                fprintf(stderr, "Failed to stat nfs file %s. %s\n",
                                        url->file,
                                        nfs_get_error(nfs[0]));
                                exit(1);
                        }
                }

                /*
                 * Before we can use multithreading we must initialize and
                 * start the service thread.
                 */
                if (nfs_mt_service_thread_start(nfs[i])) {
                        fprintf(stderr, "failed to start service thread\n");
                        exit(10);
                }
                printf("Service thread #%d is active. Ready to do I/O\n", i);
        }

        /*
         * Now create the local file and truncate it to the same size as the
         * nfs file.
         */
        fd = open(argv[2], O_RDWR|O_CREAT|O_TRUNC);
        if (fd < 0) {
                fprintf(stderr, "Failed to open dest file %s\n", argv[2]);
                exit(1);
        }
        if (ftruncate(fd, st.nfs_size) < 0) {
                fprintf(stderr, "failed to truncate(%s) to %lu bytes\n",
                        argv[2], st.nfs_size);
                exit(1);
        }
        ptr = mmap(NULL, st.nfs_size, PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
                fprintf(stderr, "failed to mmap file %s: %s\n",
                        argv[2], strerror(errno));
                exit(1);
        }

        /*
         * Create threads to read the file. Each thread will read a
         * chunk_size portion of the file.
         */
        printf("Size of file:%s is %lu bytes\n", nfs_file, st.nfs_size);
        chunk_size = (st.nfs_size + NUM_THREADS - 1) / NUM_THREADS;

        printf("Using %d threads writing %lu bytes each\n", NUM_THREADS, chunk_size);

        if ((read_threads = malloc(sizeof(pthread_t) * NUM_THREADS)) == NULL) {
                fprintf(stderr, "Failed to allocated stat_thread\n");
                exit(10);
        }
        if ((rd = malloc(sizeof(struct read_data) * NUM_THREADS)) == NULL) {
                fprintf(stderr, "Failed to allocated read_data\n");
                exit(10);
        }
        for (i = 0; i < NUM_THREADS; i++) {
                rd[i].nfs = nfs[i % NUM_CONTEXTS];
                rd[i].ptr = ptr;
                rd[i].nfsfh = nfsfh;
                rd[i].offset = i * chunk_size;
                rd[i].len = st.nfs_size - rd[i].offset;
                if (rd[i].len > chunk_size) {
                        rd[i].len = chunk_size;
                }
                rd[i].max_outstanding = MAX_CONCURRENCY / NUM_THREADS;

                if (pthread_create(&read_threads[i], NULL,
                                   &nfs_read_thread, &rd[i])) {
                        printf("Failed to create stat thread %d\n", i);
                        exit(10);
                }
        }

        /*
         * Wait for all threads to complete
         */
        for (i = 0; i < NUM_THREADS; i++) {
                pthread_join(read_threads[i], NULL);
        }

        /*
         * Closing the files
         */
        nfs_close(nfs[0], nfsfh);
        close(fd);

        printf("closing service threads\n");
        for (i = 0; i < NUM_CONTEXTS; i++) {
                nfs_mt_service_thread_stop(nfs[i]);
                nfs_destroy_context(nfs[i]);
        }
        if (url) {
                nfs_destroy_url(url);
        }
        free(rd);
        free(read_threads);
        munmap(ptr, st.nfs_size);
        return 0;
}
