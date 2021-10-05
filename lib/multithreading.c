/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2010 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif

#ifdef PS2_EE
#include "ps2_compat.h"
#endif

#ifdef PS3_PPU
#include "ps3_compat.h"
#endif

#ifdef WIN32
#include <win32/win32_compat.h>
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#ifdef HAVE_MULTITHREADING

#ifdef HAVE_PTHREAD
static void *nfs_mt_service_thread(void *arg)
{
        struct nfs_context *nfs = (struct nfs_context *)arg;
	struct pollfd pfd;
	int revents;
	int ret;

        nfs->multithreading_enabled = 1;

	while (nfs->multithreading_enabled) {
		pfd.fd = nfs_get_fd(nfs);
		pfd.events = nfs_which_events(nfs);
		pfd.revents = 0;

                //qqq   ~12737 iterations with busy loop
		ret = poll(&pfd, 1, 0);
		if (ret < 0) {
			nfs_set_error(nfs, "Poll failed");
			revents = -1;
		} else {
			revents = pfd.revents;
		}
		if (nfs_service(nfs, revents) < 0) {
			if (revents != -1)
				nfs_set_error(nfs, "nfs_service failed");
		}
	}
        return NULL;
}

int nfs_mt_service_thread_start(struct nfs_context *nfs)
{
        if (pthread_create(&nfs->service_thread, NULL,
                           &nfs_mt_service_thread, nfs)) {
                nfs_set_error(nfs, "Failed to start service thread");
                return -1;
        }
        while (nfs->multithreading_enabled == 0) {
                struct timespec ts = {0, 1000000};
                nanosleep(&ts, NULL);
        }
        return 0;
}

void nfs_mt_service_thread_stop(struct nfs_context *nfs)
{
        nfs->multithreading_enabled = 0;
        pthread_join(nfs->service_thread, NULL);
}
        
int nfs_mt_mutex_init(libnfs_mutex_t *mutex)
{
        pthread_mutex_init(mutex, NULL);
        return 0;
}

int nfs_mt_mutex_destroy(libnfs_mutex_t *mutex)
{
        pthread_mutex_destroy(mutex);
        return 0;
}

int nfs_mt_mutex_lock(libnfs_mutex_t *mutex)
{
        return pthread_mutex_lock(mutex);
}

int nfs_mt_mutex_unlock(libnfs_mutex_t *mutex)
{
        return pthread_mutex_unlock(mutex);
}

int nfs_mt_sem_init(libnfs_sem_t *sem, int value)
{
        return sem_init(sem, 0, value);
}

int nfs_mt_sem_destroy(libnfs_sem_t *sem)
{
        return sem_destroy(sem);
}

int nfs_mt_sem_post(libnfs_sem_t *sem)
{
        return sem_post(sem);
}

int nfs_mt_sem_wait(libnfs_sem_t *sem)
{
        return sem_wait(sem);
}

#endif /* HAVE_PTHREAD */

#endif /* HAVE_MULTITHREADING */

