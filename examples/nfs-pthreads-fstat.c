/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2021
   
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-nfs.h"

void usage(void)
{
	fprintf(stderr, "Usage: nfs-pthread-example <url> <num-threads>\n");
	fprintf(stderr, "\tExample program using pthreads.\n");
	exit(0);
}

struct stat_data {
        struct nfs_context *nfs;
        int idx;
        char *path;
        int is_finished;
};

static void *nfs_stat_thread(void *arg)
{
        struct stat_data *sd = arg;
        struct nfs_stat_64 st;
        int i, ret;
	struct nfsfh *nfsfh = NULL;

        printf("Stat thread %03d\n", sd->idx);
        i = 0;
        while(!sd->is_finished) {
		ret = nfs_open(sd->nfs, sd->path, 0600, &nfsfh);
		if (ret != 0) {
			printf("failed to open %s. %s\n", sd->path, nfs_get_error(sd->nfs));
                        exit(10);
                }
                if (nfsfh == NULL) {
			printf("nfsfh is NULL after nfs_open()\n");
                        exit(10);
                }
                ret = nfs_fstat64(sd->nfs, nfsfh, &st);
                if (ret < 0) {
                        printf("Stat failed: %s\n", nfs_get_error(sd->nfs));
                        exit(10);
                }
                nfs_close(sd->nfs, nfsfh);
                nfsfh = NULL;
                i++;
        }
        printf("%03d:%d ret:%d  st->ino:%d\n", sd->idx, i, ret, (int)st.nfs_ino);
        return NULL;
}

int main(int argc, char *argv[])
{
	int i, num_threads;
	int ret = 0;
	struct nfs_context *nfs = NULL;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_url *url = NULL;
        pthread_t *stat_thread;
        struct stat_data *sd;

#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		return 1;
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

	if (argc < 3) {
		usage();
	}

        num_threads = atoi(argv[2]);
        printf("Number of threads : %d\n", num_threads);
        
	nfs = nfs_init_context();
	if (nfs == NULL) {
		fprintf(stderr, "failed to init context\n");
		goto finished;
	}

	url = nfs_parse_url_full(nfs, argv[1]);
	if (url == NULL) {
		fprintf(stderr, "%s\n", nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}

	if (nfs_mount(nfs, url->server, url->path) != 0) {
		fprintf(stderr, "Failed to mount nfs share : %s\n",
			       nfs_get_error(nfs));
		ret = 1;
		goto finished;
	}

        /*
         * Before we can use multithreading we must initialize and
         * start the service thread.
         */
        printf("Start the service thread\n");
        if (nfs_mt_service_thread_start(nfs)) {
                printf("failed to start service thread\n");
                exit(10);
        }
        printf("Service thread is active. Ready to do I/O\n");


        printf("Start %d thread(s) calling stat on %s\n", num_threads, url->file);
        if ((sd = malloc(sizeof(struct stat_data) * num_threads)) == NULL) {
                printf("Failed to allocated stat_data\n");
                exit(10);
        }
        if ((stat_thread = malloc(sizeof(pthread_t) * num_threads)) == NULL) {
                printf("Failed to allocated stat_thread\n");
                exit(10);
        }
        for (i = 0; i < num_threads; i++) {
                sd[i].nfs = nfs;
                sd[i].path = url->file;
                sd[i].is_finished = 0;
                sd[i].idx = i;
                if (pthread_create(&stat_thread[i], NULL,
                                   &nfs_stat_thread, &sd[i])) {
                        printf("Failed to create stat thread %d\n", i);
                        exit(10);
                }
        }
        
        
        sleep(1);
        /*
         * Terminate all the worker threads
         */
        printf("Closing all worker threads\n");
        for (i = 0; i < num_threads; i++) {
                sd[i].is_finished = 1;
        }
        for (i = 0; i < num_threads; i++) {
                pthread_join(stat_thread[i], NULL);
        }
        
        printf("closing service thread\n");
        nfs_mt_service_thread_stop(nfs);
        
 finished:
	if (nfsfh) {
		nfs_close(nfs, nfsfh);
	}
        nfs_umount(nfs);
	if (url) {
		nfs_destroy_url(url);
	}
	if (nfs) {
		nfs_destroy_context(nfs);
	}
        free(sd);
        free(stat_thread);
	return ret;
        }
