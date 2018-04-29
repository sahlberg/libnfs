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
/*
 * High level api to nfs filesystems
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif

#ifdef WIN32
#include <win32/win32_compat.h>
#endif

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif

#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

#if defined(__ANDROID__) && !defined(HAVE_SYS_STATVFS_H)
#define statvfs statfs
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "slist.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-portmap.h"
#include "libnfs-private.h"

void
nfs_free_nfsdir(struct nfsdir *nfsdir)
{
	while (nfsdir->entries) {
		struct nfsdirent *dirent = nfsdir->entries->next;
		if (nfsdir->entries->name != NULL) {
			free(nfsdir->entries->name);
		}
		free(nfsdir->entries);
		nfsdir->entries = dirent;
	}
	free(nfsdir->fh.val);
	free(nfsdir);
}

void
nfs_dircache_add(struct nfs_context *nfs, struct nfsdir *nfsdir)
{
	int i = 0;
	LIBNFS_LIST_ADD(&nfs->dircache, nfsdir);

	for (nfsdir = nfs->dircache; nfsdir; nfsdir = nfsdir->next, i++) {
		if (i > MAX_DIR_CACHE) {
			LIBNFS_LIST_REMOVE(&nfs->dircache, nfsdir);
			nfs_free_nfsdir(nfsdir);
			break;
		}
	}
}

struct nfsdir *
nfs_dircache_find(struct nfs_context *nfs, struct nfs_fh *fh)
{
	struct nfsdir *nfsdir;

	for (nfsdir = nfs->dircache; nfsdir; nfsdir = nfsdir->next) {
		if (nfsdir->fh.len == fh->len &&
		    !memcmp(nfsdir->fh.val, fh->val, fh->len)) {
			LIBNFS_LIST_REMOVE(&nfs->dircache, nfsdir);
			return nfsdir;
		}
	}

	return NULL;
}

void
nfs_dircache_drop(struct nfs_context *nfs, struct nfs_fh *fh)
{
	struct nfsdir *cached;

	cached = nfs_dircache_find(nfs, fh);
	if (cached) {
		nfs_free_nfsdir(cached);
	}
}

static uint32_t
nfs_pagecache_hash(struct nfs_pagecache *pagecache, uint64_t offset) {
	return (2654435761UL * (1 + ((uint32_t)(offset) / NFS_BLKSIZE))) &
                (pagecache->num_entries - 1);
}

void
nfs_pagecache_invalidate(struct nfs_context *nfs, struct nfsfh *nfsfh) {
	if (nfsfh->pagecache.entries) {
		RPC_LOG(nfs->rpc, 2, "invalidating pagecache");
		memset(nfsfh->pagecache.entries, 0x00,
                       sizeof(struct nfs_pagecache_entry) *
                       nfsfh->pagecache.num_entries);
	}
}

void
nfs_pagecache_put(struct nfs_pagecache *pagecache, uint64_t offset,
                  const char *buf, size_t len)
{
	time_t ts = pagecache->ttl ? (time_t)(rpc_current_time() / 1000) : 1;
	if (!pagecache->num_entries) return;
	while (len > 0) {
		uint64_t page_offset = offset & ~(NFS_BLKSIZE - 1);
		uint32_t entry = nfs_pagecache_hash(pagecache, page_offset);
		struct nfs_pagecache_entry *e = &pagecache->entries[entry];
		size_t n = MIN(NFS_BLKSIZE - offset % NFS_BLKSIZE, len);

		/* we can only write to the cache if we add a full page or
		 * partially update a page that is still valid */
		if (n == NFS_BLKSIZE ||
		    (e->ts && e->offset == page_offset &&
		     (!pagecache->ttl || ts - e->ts <= pagecache->ttl))) {
			e->ts = ts;
			e->offset = page_offset;
			memcpy(e->buf + offset % NFS_BLKSIZE, buf, n);
		}
		buf += n;
		offset += n;
		len -= n;
	}
}

char *
nfs_pagecache_get(struct nfs_pagecache *pagecache, uint64_t offset)
{
	uint32_t entry;
	struct nfs_pagecache_entry *e;

	entry = nfs_pagecache_hash(pagecache, offset);
	e = &pagecache->entries[entry];

	if (offset != e->offset) {
		return NULL;
	}
	if (!e->ts) {
		return NULL;
	}
	if (pagecache->ttl && (time_t)(rpc_current_time() / 1000) - e->ts > pagecache->ttl) {
		return NULL;
	}

	return e->buf;
}

void nfs_pagecache_init(struct nfs_context *nfs, struct nfsfh *nfsfh) {
	/* init page cache */
	if (nfs->rpc->pagecache) {
		nfsfh->pagecache.num_entries = nfs->rpc->pagecache;
		nfsfh->pagecache.ttl = nfs->rpc->pagecache_ttl;
		nfsfh->pagecache.entries = malloc(sizeof(struct nfs_pagecache_entry) * nfsfh->pagecache.num_entries);
		nfs_pagecache_invalidate(nfs, nfsfh);
		RPC_LOG(nfs->rpc, 2, "init pagecache entries %d pagesize %d\n",
                        nfsfh->pagecache.num_entries, NFS_BLKSIZE);
	}
}

void
nfs_set_auth(struct nfs_context *nfs, struct AUTH *auth)
{
	rpc_set_auth(nfs->rpc, auth);
}

int
nfs_get_fd(struct nfs_context *nfs)
{
	return rpc_get_fd(nfs->rpc);
}

int
nfs_queue_length(struct nfs_context *nfs)
{
	return rpc_queue_length(nfs->rpc);
}

int
nfs_which_events(struct nfs_context *nfs)
{
	return rpc_which_events(nfs->rpc);
}

int
nfs_service(struct nfs_context *nfs, int revents)
{
	return rpc_service(nfs->rpc, revents);
}

char *
nfs_get_error(struct nfs_context *nfs)
{
	return rpc_get_error(nfs->rpc);
};

#ifdef HAVE_SO_BINDTODEVICE
void
nfs_set_interface(struct nfs_context *nfs, const char *ifname)
{
	rpc_set_interface(nfs_get_rpc_context(nfs), ifname);
}
#endif

static int
nfs_set_context_args(struct nfs_context *nfs, const char *arg, const char *val)
{
	if (!strcmp(arg, "tcp-syncnt")) {
		rpc_set_tcp_syncnt(nfs_get_rpc_context(nfs), atoi(val));
	} else if (!strcmp(arg, "uid")) {
		rpc_set_uid(nfs_get_rpc_context(nfs), atoi(val));
	} else if (!strcmp(arg, "gid")) {
		rpc_set_gid(nfs_get_rpc_context(nfs), atoi(val));
	} else if (!strcmp(arg, "readahead")) {
		rpc_set_readahead(nfs_get_rpc_context(nfs), atoi(val));
	} else if (!strcmp(arg, "pagecache")) {
		rpc_set_pagecache(nfs_get_rpc_context(nfs), atoi(val));
	} else if (!strcmp(arg, "debug")) {
		rpc_set_debug(nfs_get_rpc_context(nfs), atoi(val));
	} else if (!strcmp(arg, "auto-traverse-mounts")) {
		nfs->auto_traverse_mounts = atoi(val);
	} else if (!strcmp(arg, "dircache")) {
		nfs_set_dircache(nfs, atoi(val));
	} else if (!strcmp(arg, "autoreconnect")) {
		nfs_set_autoreconnect(nfs, atoi(val));
#ifdef HAVE_SO_BINDTODEVICE
	} else if (!strcmp(arg, "if")) {
		nfs_set_interface(nfs, val);
#endif
	} else if (!strcmp(arg, "version")) {
		if (nfs_set_version(nfs, atoi(val)) < 0) {
			nfs_set_error(nfs, "NFS version %d is not supported",
				      atoi(val));
			return -1;
		}
	} else if (!strcmp(arg, "nfsport")) {
		nfs->nfsport =  atoi(val);
	} else if (!strcmp(arg, "mountport")) {
		nfs->mountport =  atoi(val);
	}
	return 0;
}

static struct nfs_url *
nfs_parse_url(struct nfs_context *nfs, const char *url, int dir, int incomplete)
{
	struct nfs_url *urls;
	char *strp, *flagsp, *strp2;

	if (strncmp(url, "nfs://", 6)) {
		nfs_set_error(nfs, "Invalid URL specified");
		return NULL;
	}

	urls = malloc(sizeof(struct nfs_url));
	if (urls == NULL) {
		nfs_set_error(nfs, "Out of memory");
		return NULL;
	}

	memset(urls, 0x00, sizeof(struct nfs_url));
	urls->server = strdup(url + 6);
	if (urls->server == NULL) {
		nfs_destroy_url(urls);
		nfs_set_error(nfs, "Out of memory");
		return NULL;
	}

	if (urls->server[0] == '/' || urls->server[0] == '\0' ||
		urls->server[0] == '?') {
		if (incomplete) {
			flagsp = strchr(urls->server, '?');
			goto flags;
		}
		nfs_destroy_url(urls);
		nfs_set_error(nfs, "Invalid server string");
		return NULL;
	}

	strp = strchr(urls->server, '/');
	if (strp == NULL) {
		if (incomplete) {
			flagsp = strchr(urls->server, '?');
			goto flags;
		}
		nfs_destroy_url(urls);
		nfs_set_error(nfs, "Incomplete or invalid URL specified.");
		return NULL;
	}

	urls->path = strdup(strp);
	if (urls->path == NULL) {
		nfs_destroy_url(urls);
		nfs_set_error(nfs, "Out of memory");
		return NULL;
	}
	*strp = 0;

	if (dir) {
		flagsp = strchr(urls->path, '?');
		goto flags;
	}

	strp = strrchr(urls->path, '/');
	if (strp == NULL) {
		if (incomplete) {
			flagsp = strchr(urls->path, '?');
			goto flags;
		}
		nfs_destroy_url(urls);
		nfs_set_error(nfs, "Incomplete or invalid URL specified.");
		return NULL;
	}
	urls->file = strdup(strp);
	if (urls->path == NULL) {
		nfs_destroy_url(urls);
		nfs_set_error(nfs, "Out of memory");
		return NULL;
	}
	*strp = 0;
	flagsp = strchr(urls->file, '?');

flags:
	if (flagsp) {
		*flagsp = 0;
	}

	if (urls->file && !strlen(urls->file)) {
		free(urls->file);
		urls->file = NULL;
		if (!incomplete) {
			nfs_destroy_url(urls);
			nfs_set_error(nfs, "Incomplete or invalid URL "
                                      "specified.");
			return NULL;
		}
	}

	while (flagsp != NULL && *(flagsp+1) != 0) {
		strp = flagsp + 1;
		flagsp = strchr(strp, '&');
		if (flagsp) {
			*flagsp = 0;
		}
		strp2 = strchr(strp, '=');
		if (strp2) {
			*strp2 = 0;
			strp2++;
			nfs_set_context_args(nfs, strp, strp2);
		}
	}

	if (urls->server && strlen(urls->server) <= 1) {
		free(urls->server);
		urls->server = NULL;
	}

	return urls;
}

struct nfs_url *
nfs_parse_url_full(struct nfs_context *nfs, const char *url)
{
	return nfs_parse_url(nfs, url, 0, 0);
}

struct nfs_url *
nfs_parse_url_dir(struct nfs_context *nfs, const char *url)
{
	return nfs_parse_url(nfs, url, 1, 0);
}

struct nfs_url *
nfs_parse_url_incomplete(struct nfs_context *nfs, const char *url)
{
	return nfs_parse_url(nfs, url, 0, 1);
}


void
nfs_destroy_url(struct nfs_url *url)
{
	if (url) {
		free(url->server);
		free(url->path);
		free(url->file);
	}
	free(url);
}

#define MAX_CLIENT_NAME 64

struct nfs_context *
nfs_init_context(void)
{
	struct nfs_context *nfs;
        int i;
        uint64_t v;
        verifier4 verifier;
        char client_name[MAX_CLIENT_NAME];

	nfs = malloc(sizeof(struct nfs_context));
	if (nfs == NULL) {
		return NULL;
	}
	memset(nfs, 0, sizeof(struct nfs_context));

	nfs->rpc = rpc_init_context();
	if (nfs->rpc == NULL) {
		free(nfs);
		return NULL;
	}

	nfs->cwd = strdup("/");
	nfs->mask = 022;
	nfs->auto_traverse_mounts = 1;
	nfs->dircache_enabled = 1;
	/* Default is never give up, never surrender */
	nfs->auto_reconnect = -1;
	nfs->version = NFS_V3;

        /* NFSv4 parameters */
        /* We need a "random" initial verifier */
        v = rpc_current_time() << 32 | getpid();
        for (i = 0; i < NFS4_VERIFIER_SIZE; i++) {
                verifier[i] = v & 0xff;
                v >>= 8;
        }
        nfs4_set_verifier(nfs, verifier);
        
        snprintf(client_name, MAX_CLIENT_NAME, "Libnfs pid:%d %d", getpid(),
                 (int)time(NULL));
        nfs4_set_client_name(nfs, client_name);

	return nfs;
}

void
nfs4_set_client_name(struct nfs_context *nfs, const char *client_name)
{
        nfs->client_name = strdup(client_name);
}

void
nfs4_set_verifier(struct nfs_context *nfs, const char *verifier)
{
        memcpy(nfs->verifier, verifier, NFS4_VERIFIER_SIZE);
}

void
nfs_destroy_context(struct nfs_context *nfs)
{
	while (nfs->nested_mounts) {
		struct nested_mounts *mnt = nfs->nested_mounts;

		LIBNFS_LIST_REMOVE(&nfs->nested_mounts, mnt);
		free(mnt->path);
		free(mnt->fh.val);
                free(mnt);
	}

	rpc_destroy_context(nfs->rpc);
	nfs->rpc = NULL;

        free(nfs->server);
        nfs->server = NULL;

        free(nfs->export);
        nfs->export = NULL;

        free(nfs->cwd);
        nfs->cwd = NULL;

        free(nfs->rootfh.val);
        nfs->rootfh.len = 0;
        nfs->rootfh.val = NULL;

        free(nfs->client_name);
        nfs->client_name = NULL;

	while (nfs->dircache) {
		struct nfsdir *nfsdir = nfs->dircache;
		LIBNFS_LIST_REMOVE(&nfs->dircache, nfsdir);
		nfs_free_nfsdir(nfsdir);
	}

	free(nfs);
}

struct rpc_cb_data {
       char *server;
       uint32_t program;
       uint32_t version;

       rpc_cb cb;
       void *private_data;
};

void free_rpc_cb_data(struct rpc_cb_data *data)
{
	free(data->server);
	data->server = NULL;
	free(data);
}

static int
rpc_connect_port_internal(struct rpc_context *rpc, int port, struct rpc_cb_data *data);

static void
rpc_connect_program_5_cb(struct rpc_context *rpc, int status,
                         void *command_data, void *private_data)
{
	struct rpc_cb_data *data = private_data;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Dont want any more callbacks even if the socket is closed */
	rpc->connect_cb = NULL;

	if (status != RPC_STATUS_SUCCESS) {
		data->cb(rpc, status, command_data, data->private_data);
		free_rpc_cb_data(data);
		return;
	}

	data->cb(rpc, status, NULL, data->private_data);
	free_rpc_cb_data(data);
}

static void
rpc_connect_program_4_cb(struct rpc_context *rpc, int status,
                         void *command_data, void *private_data)
{
	struct rpc_cb_data *data = private_data;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Dont want any more callbacks even if the socket is closed */
	rpc->connect_cb = NULL;

	if (status != RPC_STATUS_SUCCESS) {
		data->cb(rpc, status, command_data, data->private_data);
		free_rpc_cb_data(data);
		return;
	}

        if (rpc_null_async(rpc, data->program, data->version,
                           rpc_connect_program_5_cb, data) != 0) {
                data->cb(rpc, RPC_STATUS_ERROR, command_data, data->private_data);
                free_rpc_cb_data(data);
                return;
        }
}

static void
rpc_connect_program_3_cb(struct rpc_context *rpc, int status,
                         void *command_data, void *private_data)
{
	struct rpc_cb_data *data = private_data;
	struct pmap3_string_result *gar;
	uint32_t rpc_port = 0;
	char *ptr;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (status != RPC_STATUS_SUCCESS) {
		data->cb(rpc, status, command_data, data->private_data);
		free_rpc_cb_data(data);
		return;
	}

	switch (rpc->s.ss_family) {
	case AF_INET:
		rpc_port = *(uint32_t *)(void *)command_data;
		break;
	case AF_INET6:
		/* ouch. portmapper and ipv6 are not great */
		gar = command_data;
		if (gar->addr == NULL) {
			break;
		}
		ptr = strrchr(gar->addr, '.');
		if (ptr == NULL) {
			break;
		}
		rpc_port = atoi(ptr + 1);
		*ptr = 0;
		ptr = strrchr(gar->addr, '.');
		if (ptr == NULL) {
			break;
		}
		rpc_port += 256 * atoi(ptr + 1);
		break;
	}
	if (rpc_port == 0) {
		rpc_set_error(rpc, "RPC error. Program is not available on %s",
			      data->server);
		data->cb(rpc, RPC_STATUS_ERROR, rpc_get_error(rpc),
			 data->private_data);
		free_rpc_cb_data(data);
		return;
	}

	rpc_disconnect(rpc, "normal disconnect");
        if (rpc_connect_port_internal(rpc, rpc_port, data)) {
		data->cb(rpc, RPC_STATUS_ERROR, command_data,
                         data->private_data);
		free_rpc_cb_data(data);
                return;
        }
}

static void
rpc_connect_program_2_cb(struct rpc_context *rpc, int status,
                         void *command_data, void *private_data)
{
	struct rpc_cb_data *data = private_data;
	struct pmap3_mapping map;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (status != RPC_STATUS_SUCCESS) {
		data->cb(rpc, status, command_data, data->private_data);
		free_rpc_cb_data(data);
		return;
	}

	switch (rpc->s.ss_family) {
	case AF_INET:
		if (rpc_pmap2_getport_async(rpc, data->program, data->version,
                                            IPPROTO_TCP,
                                            rpc_connect_program_3_cb,
                                            private_data) != 0) {
			data->cb(rpc, RPC_STATUS_ERROR, command_data, data->private_data);
			free_rpc_cb_data(data);
			return;
		}
		break;
	case AF_INET6:
		map.prog=data->program;
		map.vers=data->version;
		map.netid="";
		map.addr="";
		map.owner="";
		if (rpc_pmap3_getaddr_async(rpc, &map,
                                            rpc_connect_program_3_cb,
                                            private_data) != 0) {
			data->cb(rpc, RPC_STATUS_ERROR, command_data, data->private_data);
			free_rpc_cb_data(data);
			return;
		}
		break;
	}
}

static void
rpc_connect_program_1_cb(struct rpc_context *rpc, int status,
                         void *command_data, void *private_data)
{
	struct rpc_cb_data *data = private_data;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Dont want any more callbacks even if the socket is closed */
	rpc->connect_cb = NULL;

	if (status != RPC_STATUS_SUCCESS) {
		data->cb(rpc, status, command_data, data->private_data);
		free_rpc_cb_data(data);
		return;
	}

	switch (rpc->s.ss_family) {
	case AF_INET:
		if (rpc_pmap2_null_async(rpc, rpc_connect_program_2_cb,
                                         data) != 0) {
			data->cb(rpc, RPC_STATUS_ERROR, command_data, data->private_data);
			free_rpc_cb_data(data);
			return;
		}
		break;
	case AF_INET6:
		if (rpc_pmap3_null_async(rpc, rpc_connect_program_2_cb,
                                         data) != 0) {
			data->cb(rpc, RPC_STATUS_ERROR, command_data, data->private_data);
			free_rpc_cb_data(data);
			return;
		}
		break;
	}
}

static int
rpc_connect_port_internal(struct rpc_context *rpc, int port, struct rpc_cb_data *data)
{
        if (rpc_connect_async(rpc, data->server, port,
                              rpc_connect_program_4_cb, data) != 0) {
		return -1;
	}

        return 0;
}

int
rpc_connect_port_async(struct rpc_context *rpc, const char *server,
                       int port,
                       int program, int version,
                       rpc_cb cb, void *private_data)
{
	struct rpc_cb_data *data;

	data = malloc(sizeof(struct rpc_cb_data));
	if (data == NULL) {
		return -1;
	}
	memset(data, 0, sizeof(struct rpc_cb_data));
	data->server       = strdup(server);
	data->program      = program;
	data->version      = version;

	data->cb           = cb;
	data->private_data = private_data;

        if (rpc_connect_port_internal(rpc, port, data)) {
		rpc_set_error(rpc, "Failed to start connection. %s",
                              rpc_get_error(rpc));
		free_rpc_cb_data(data);
                return -1;
        }
        return 0;
}

int
rpc_connect_program_async(struct rpc_context *rpc, const char *server,
                          int program, int version,
                          rpc_cb cb, void *private_data)
{
	struct rpc_cb_data *data;

	data = malloc(sizeof(struct rpc_cb_data));
	if (data == NULL) {
		return -1;
	}
	memset(data, 0, sizeof(struct rpc_cb_data));
	data->server       = strdup(server);
	data->program      = program;
	data->version      = version;

	data->cb           = cb;
	data->private_data = private_data;

	if (rpc_connect_async(rpc, server, 111, rpc_connect_program_1_cb,
                              data) != 0) {
		rpc_set_error(rpc, "Failed to start connection. %s",
                              rpc_get_error(rpc));
		free_rpc_cb_data(data);
		return -1;
	}
	return 0;
}

void
free_nfs_cb_data(struct nfs_cb_data *data)
{
	if (data->continue_data != NULL) {
		assert(data->free_continue_data);
		data->free_continue_data(data->continue_data);
	}

	free(data->saved_path);
	free(data->fh.val);
	if (!data->not_my_buffer) {
		free(data->buffer);
	}

	free(data);
}

void
nfs_free_nfsfh(struct nfsfh *nfsfh)
{
	if (nfsfh->fh.val != NULL) {
		free(nfsfh->fh.val);
		nfsfh->fh.len = 0;
		nfsfh->fh.val = NULL;
	}
	free(nfsfh->pagecache.entries);
	free(nfsfh);
}

/*
 * Async call for mounting an nfs share and geting the root filehandle
 */
int
nfs_mount_async(struct nfs_context *nfs, const char *server,
                const char *export, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_mount_async(nfs, server, export, cb, private_data);
        case NFS_V4:
                return nfs4_mount_async(nfs, server, export, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_normalize_path(struct nfs_context *nfs, char *path)
{
	char *str;
	int len;

	/* // -> / */
	while ((str = strstr(path, "//"))) {
		while(*str) {
			*str = *(str + 1);
			str++;
		}
	}

	/* /./ -> / */
	while ((str = strstr(path, "/./"))) {
		while(*(str + 1)) {
			*str = *(str + 2);
			str++;
		}
	}

	/* ^/../ -> error */
	if (!strncmp(path, "/../", 4)) {
		nfs_set_error(nfs,
			"Absolute path starts with '/../' "
			"during normalization");
		return -1;
	}

	/* ^[^/] -> error */
	if (path[0] != '/') {
		nfs_set_error(nfs,
			"Absolute path does not start with '/'");
		return -1;
	}

	/* /string/../ -> / */
	while ((str = strstr(path, "/../"))) {
		char *tmp;

		if (!strncmp(path, "/../", 4)) {
			nfs_set_error(nfs,
				"Absolute path starts with '/../' "
				"during normalization");
			return -1;
		}

		tmp = str - 1;
		while (*tmp != '/') {
			tmp--;
		}
		str += 3;
		while((*(tmp++) = *(str++)) != '\0')
			;
	}

	/* /$ -> \0 */
	len = strlen(path);
	if (len > 1) {
		if (path[len - 1] == '/') {
			path[len - 1] = '\0';
			len--;
		}
	}
	if (path[0] == '\0') {
		nfs_set_error(nfs,
			"Absolute path became '' "
			"during normalization");
		return -1;
	}

	/* /.$ -> \0 */
	if (len >= 2) {
		if (!strcmp(&path[len - 2], "/.")) {
			path[len - 2] = '\0';
			len -= 2;
		}
	}

	/* ^/..$ -> error */
	if (!strcmp(path, "/..")) {
		nfs_set_error(nfs,
			"Absolute path is '/..' "
			"during normalization");
		return -1;
	}

	/* /string/..$ -> / */
	if (len >= 3) {
		if (!strcmp(&path[len - 3], "/..")) {
			char *tmp = &path[len - 3];
			while (*--tmp != '/')
				;
			*tmp = '\0';
		}
	}

	return 0;
}

int
nfs_stat_async(struct nfs_context *nfs, const char *path,
               nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_stat_async(nfs, path, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv4",
                              __FUNCTION__);
                return -1;
        }
}

int
nfs_stat64_async(struct nfs_context *nfs, const char *path,
                 nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_stat64_async(nfs, path, 0,
                                         cb, private_data);
        case NFS_V4:
                return nfs4_stat64_async(nfs, path, 0,
                                         cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_lstat64_async(struct nfs_context *nfs, const char *path,
                  nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_stat64_async(nfs, path, 1,
                                         cb, private_data);
        case NFS_V4:
                return nfs4_stat64_async(nfs, path, 1,
                                         cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_open2_async(struct nfs_context *nfs, const char *path, int flags,
                int mode, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_open_async(nfs, path, flags, mode,
                                       cb, private_data);
        case NFS_V4:
                return nfs4_open_async(nfs, path, flags, mode,
                                       cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_open_async(struct nfs_context *nfs, const char *path, int flags,
               nfs_cb cb, void *private_data)
{
        return nfs_open2_async(nfs, path, flags, 0666 & ~nfs->mask,
                               cb, private_data);
}

int
nfs_chdir_async(struct nfs_context *nfs, const char *path,
                nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_chdir_async(nfs, path, cb, private_data);
        case NFS_V4:
                return nfs4_chdir_async(nfs, path, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_pread_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t offset,
                uint64_t count, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_pread_async_internal(nfs, nfsfh, offset,
                                                 (size_t)count,
                                                 cb, private_data, 0);
        case NFS_V4:
                return nfs4_pread_async_internal(nfs, nfsfh, offset,
                                                 (size_t)count,
                                                 cb, private_data, 0);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_read_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t count,
               nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_pread_async_internal(nfs, nfsfh, nfsfh->offset,
                                                 (size_t)count,
                                                 cb, private_data, 1);
        case NFS_V4:
                return nfs4_pread_async_internal(nfs, nfsfh, nfsfh->offset,
                                                 (size_t)count,
                                                 cb, private_data, 1);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_pwrite_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t offset,
                 uint64_t count, const void *buf, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_pwrite_async_internal(nfs, nfsfh, offset,
                                                  (size_t)count, buf,
                                                  cb, private_data, 0);
        case NFS_V4:
                return nfs4_pwrite_async_internal(nfs, nfsfh, offset,
                                                  (size_t)count, buf,
                                                  cb, private_data, 0);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d.",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_write_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t count,
                const void *buf, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_write_async(nfs, nfsfh, count, buf,
                                        cb, private_data);
        case NFS_V4:
                return nfs4_write_async(nfs, nfsfh, count, buf,
                                        cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_close_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb,
                void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_close_async(nfs, nfsfh, cb, private_data);
        case NFS_V4:
                return nfs4_close_async(nfs, nfsfh, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_fstat_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb,
                 void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_fstat_async(nfs, nfsfh, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv4",
                              __FUNCTION__);
                return -1;
        }
}

int
nfs_fstat64_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb,
                   void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_fstat64_async(nfs, nfsfh, cb, private_data);
        case NFS_V4:
                return nfs4_fstat64_async(nfs, nfsfh, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_fsync_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb,
                 void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_fsync_async(nfs, nfsfh, cb, private_data);
        case NFS_V4:
                return nfs4_fsync_async(nfs, nfsfh, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_ftruncate_async(struct nfs_context *nfs, struct nfsfh *nfsfh,
                    uint64_t length, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_ftruncate_async(nfs, nfsfh, length,
                                            cb, private_data);
        case NFS_V4:
                return nfs4_ftruncate_async(nfs, nfsfh, length,
                                            cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_truncate_async(struct nfs_context *nfs, const char *path, uint64_t length,
                   nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_truncate_async(nfs, path, length, cb, private_data);
        case NFS_V4:
                return nfs4_truncate_async(nfs, path, length, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_mkdir2_async(struct nfs_context *nfs, const char *path, int mode,
                 nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_mkdir2_async(nfs, path, mode, cb, private_data);
        case NFS_V4:
                return nfs4_mkdir2_async(nfs, path, mode, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_mkdir_async(struct nfs_context *nfs, const char *path, nfs_cb cb,
                void *private_data)
{
	return nfs_mkdir2_async(nfs, path, 0755, cb, private_data);
}

int
nfs_rmdir_async(struct nfs_context *nfs, const char *path, nfs_cb cb,
                 void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_rmdir_async(nfs, path, cb, private_data);
        case NFS_V4:
                return nfs4_rmdir_async(nfs, path, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_create_async(struct nfs_context *nfs, const char *path, int flags,
                  int mode, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_create_async(nfs, path, flags, mode,
                                         cb, private_data);
        case NFS_V4:
                return nfs4_create_async(nfs, path, flags, mode,
                                         cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_creat_async(struct nfs_context *nfs, const char *path, int mode, nfs_cb cb,
                void *private_data)
{
	return nfs_create_async(nfs, path, 0, mode, cb, private_data);
}

int
nfs_unlink_async(struct nfs_context *nfs, const char *path, nfs_cb cb,
                  void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_unlink_async(nfs, path, cb, private_data);
        case NFS_V4:
                return nfs4_unlink_async(nfs, path, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_mknod_async(struct nfs_context *nfs, const char *path, int mode, int dev,
                 nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_mknod_async(nfs, path, mode, dev, cb, private_data);
        case NFS_V4:
                return nfs4_mknod_async(nfs, path, mode, dev, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_opendir_async(struct nfs_context *nfs, const char *path, nfs_cb cb,
                   void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_opendir_async(nfs, path, cb, private_data);
        case NFS_V4:
                return nfs4_opendir_async(nfs, path, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv4",
                              __FUNCTION__);
                return -1;
        }
}

struct nfsdirent *
nfs_readdir(struct nfs_context *nfs _U_, struct nfsdir *nfsdir)
{
	struct nfsdirent *nfsdirent = nfsdir->current;

	if (nfsdir->current != NULL) {
		nfsdir->current = nfsdir->current->next;
	}
	return nfsdirent;
}

long
nfs_telldir(struct nfs_context *nfs _U_, struct nfsdir *nfsdir)
{
        long i;
        struct nfsdirent *tmp;

        for (i = 0, tmp = nfsdir->entries; tmp; i++, tmp = tmp->next) {
                if (tmp == nfsdir->current) {
                        return i;
                }
        }
        return -1;
}

void
nfs_seekdir(struct nfs_context *nfs _U_, struct nfsdir *nfsdir, long loc)
{
        if (loc < 0) {
                return;
        }
        for (nfsdir->current = nfsdir->entries;
             nfsdir && loc--;
             nfsdir = nfsdir->next) {
        }
}

void
nfs_rewinddir(struct nfs_context *nfs _U_, struct nfsdir *nfsdir)
{
	nfsdir->current = nfsdir->entries;
}

void
nfs_closedir(struct nfs_context *nfs, struct nfsdir *nfsdir)
{
	if (nfs && nfs->dircache_enabled) {
		nfs_dircache_add(nfs, nfsdir);
	} else {
		nfs_free_nfsdir(nfsdir);
	}
}

void
nfs_getcwd(struct nfs_context *nfs, const char **cwd)
{
	if (cwd) {
		*cwd = nfs->cwd;
	}
}

int
nfs_lseek_async(struct nfs_context *nfs, struct nfsfh *nfsfh, int64_t offset,
                 int whence, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_lseek_async(nfs, nfsfh, offset, whence,
                                        cb, private_data);
        case NFS_V4:
                return nfs4_lseek_async(nfs, nfsfh, offset, whence,
                                        cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_lockf_async(struct nfs_context *nfs, struct nfsfh *nfsfh,
                enum nfs4_lock_op op, uint64_t count,
                nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V4:
                return nfs4_lockf_async(nfs, nfsfh, op, count,
                                        cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_fcntl_async(struct nfs_context *nfs, struct nfsfh *nfsfh,
                enum nfs4_fcntl_op cmd, void *arg,
                nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V4:
                return nfs4_fcntl_async(nfs, nfsfh, cmd, arg,
                                        cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_statvfs_async(struct nfs_context *nfs, const char *path, nfs_cb cb,
                   void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_statvfs_async(nfs, path, cb, private_data);
        case NFS_V4:
                return nfs4_statvfs_async(nfs, path, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_readlink_async(struct nfs_context *nfs, const char *path, nfs_cb cb,
                    void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_readlink_async(nfs, path, cb, private_data);
        case NFS_V4:
                return nfs4_readlink_async(nfs, path, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_chmod_async(struct nfs_context *nfs, const char *path, int mode,
                nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_chmod_async_internal(nfs, path, 0, mode,
                                                 cb, private_data);
        case NFS_V4:
                return nfs4_chmod_async_internal(nfs, path, 0, mode,
                                                 cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_lchmod_async(struct nfs_context *nfs, const char *path, int mode,
                 nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_chmod_async_internal(nfs, path, 1, mode,
                                                 cb, private_data);
        case NFS_V4:
                return nfs4_chmod_async_internal(nfs, path, 1, mode,
                                                 cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_fchmod_async(struct nfs_context *nfs, struct nfsfh *nfsfh, int mode,
                  nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_fchmod_async(nfs, nfsfh, mode, cb, private_data);
        case NFS_V4:
                return nfs4_fchmod_async(nfs, nfsfh, mode, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_chown_async(struct nfs_context *nfs, const char *path, int uid, int gid,
                nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_chown_async_internal(nfs, path, 0, uid, gid,
                                                 cb, private_data);
        case NFS_V4:
                return nfs4_chown_async_internal(nfs, path, 0, uid, gid,
                                                 cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_lchown_async(struct nfs_context *nfs, const char *path, int uid, int gid,
                 nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_chown_async_internal(nfs, path, 1, uid, gid,
                                                 cb, private_data);
        case NFS_V4:
                return nfs4_chown_async_internal(nfs, path, 1, uid, gid,
                                                 cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_fchown_async(struct nfs_context *nfs, struct nfsfh *nfsfh, int uid,
                 int gid, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_fchown_async(nfs, nfsfh, uid, gid,
                                         cb, private_data);
        case NFS_V4:
                return nfs4_fchown_async(nfs, nfsfh, uid, gid,
                                         cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_utimes_async(struct nfs_context *nfs, const char *path,
                 struct timeval *times, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_utimes_async_internal(nfs, path, 0, times,
                                                  cb, private_data);
        case NFS_V4:
                return nfs4_utimes_async_internal(nfs, path, 0, times,
                                                  cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_lutimes_async(struct nfs_context *nfs, const char *path,
                  struct timeval *times, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_utimes_async_internal(nfs, path, 1, times,
                                                  cb, private_data);
        case NFS_V4:
                return nfs4_utimes_async_internal(nfs, path, 1, times,
                                                  cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_utime_async(struct nfs_context *nfs, const char *path,
                struct utimbuf *times, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_utime_async(nfs, path, times, cb, private_data);
        case NFS_V4:
                return nfs4_utime_async(nfs, path, times, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv4",
                              __FUNCTION__);
                return -1;
        }
}

int
nfs_access_async(struct nfs_context *nfs, const char *path, int mode,
                 nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_access_async(nfs, path, mode, cb, private_data);
        case NFS_V4:
                return nfs4_access_async(nfs, path, mode, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_access2_async(struct nfs_context *nfs, const char *path, nfs_cb cb,
                   void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_access2_async(nfs, path, cb, private_data);
        case NFS_V4:
                return nfs4_access2_async(nfs, path, cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv4",
                              __FUNCTION__);
                return -1;
        }
}

int
nfs_symlink_async(struct nfs_context *nfs, const char *target,
                   const char *newpath, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_symlink_async(nfs, target, newpath,
                                          cb, private_data);
        case NFS_V4:
                return nfs4_symlink_async(nfs, target, newpath,
                                          cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_rename_async(struct nfs_context *nfs, const char *oldpath,
                  const char *newpath, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_rename_async(nfs, oldpath, newpath,
                                         cb, private_data);
        case NFS_V4:
                return nfs4_rename_async(nfs, oldpath, newpath,
                                         cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

int
nfs_link_async(struct nfs_context *nfs, const char *oldpath,
               const char *newpath, nfs_cb cb, void *private_data)
{
	switch (nfs->version) {
        case NFS_V3:
                return nfs3_link_async(nfs, oldpath, newpath,
                                       cb, private_data);
        case NFS_V4:
                return nfs4_link_async(nfs, oldpath, newpath,
                                       cb, private_data);
        default:
                nfs_set_error(nfs, "%s does not support NFSv%d",
                              __FUNCTION__, nfs->version);
                return -1;
        }
}

/*
 * Get the maximum supported READ3 size by the server
 */
uint64_t
nfs_get_readmax(struct nfs_context *nfs)
{
	return nfs->readmax;
}

/*
 * Get the maximum supported WRITE3 size by the server
 */
uint64_t
nfs_get_writemax(struct nfs_context *nfs)
{
	return nfs->writemax;
}

void
nfs_set_tcp_syncnt(struct nfs_context *nfs, int v) {
	rpc_set_tcp_syncnt(nfs->rpc, v);
}

void
nfs_set_uid(struct nfs_context *nfs, int uid) {
	rpc_set_uid(nfs->rpc, uid);
}

void
nfs_set_gid(struct nfs_context *nfs, int gid) {
	rpc_set_gid(nfs->rpc, gid);
}

void
nfs_set_pagecache(struct nfs_context *nfs, uint32_t v) {
	rpc_set_pagecache(nfs->rpc, v);
}

void
nfs_set_pagecache_ttl(struct nfs_context *nfs, uint32_t v) {
	rpc_set_pagecache_ttl(nfs->rpc, v);
}

void
nfs_set_readahead(struct nfs_context *nfs, uint32_t v) {
	rpc_set_readahead(nfs->rpc, v);
}

void
nfs_set_debug(struct nfs_context *nfs, int level) {
	rpc_set_debug(nfs->rpc, level);
}

void
nfs_set_dircache(struct nfs_context *nfs, int enabled) {
	nfs->dircache_enabled = enabled;
}

void
nfs_set_autoreconnect(struct nfs_context *nfs, int num_retries) {
	nfs->auto_reconnect = num_retries;
}

int
nfs_set_version(struct nfs_context *nfs, int version) {
	switch (version) {
	case NFS_V3:
	case NFS_V4:
		nfs->version = version;
		break;
	default:
		nfs_set_error(nfs, "NFS version %d is not supported", version);
		return -1;
	}
	return 0;
}

void
nfs_set_error(struct nfs_context *nfs, char *error_string, ...)
{
        va_list ap;
	char *str = NULL;

        va_start(ap, error_string);
	str = malloc(1024);
	vsnprintf(str, 1024, error_string, ap);
	if (nfs->rpc->error_string != NULL) {
		free(nfs->rpc->error_string);
	}
	nfs->rpc->error_string = str;
	va_end(ap);
}

struct mount_cb_data {
       rpc_cb cb;
       void *private_data;
       char *server;
};

static void
free_mount_cb_data(struct mount_cb_data *data)
{
	if (data->server != NULL) {
		free(data->server);
		data->server = NULL;
	}

	free(data);
}

static void
mount_export_5_cb(struct rpc_context *rpc, int status, void *command_data,
                  void *private_data)
{
	struct mount_cb_data *data = private_data;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (status != RPC_STATUS_SUCCESS) {
		data->cb(rpc, -EFAULT, command_data, data->private_data);
		free_mount_cb_data(data);
		return;
	}

	data->cb(rpc, 0, command_data, data->private_data);
	if (rpc_disconnect(rpc, "normal disconnect") != 0) {
		rpc_set_error(rpc, "Failed to disconnect\n");
	}
	free_mount_cb_data(data);
}

static void
mount_export_4_cb(struct rpc_context *rpc, int status, void *command_data,
                  void *private_data)
{
	struct mount_cb_data *data = private_data;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Dont want any more callbacks even if the socket is closed */
	rpc->connect_cb = NULL;

	if (status != RPC_STATUS_SUCCESS) {
		data->cb(rpc, -EFAULT, command_data, data->private_data);
		free_mount_cb_data(data);
		return;
	}

	if (rpc_mount3_export_async(rpc, mount_export_5_cb, data) != 0) {
		data->cb(rpc, -ENOMEM, command_data, data->private_data);
		free_mount_cb_data(data);
		return;
	}
}

int
mount_getexports_async(struct rpc_context *rpc, const char *server, rpc_cb cb,
                       void *private_data)
{
	struct mount_cb_data *data;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	data = malloc(sizeof(struct mount_cb_data));
	if (data == NULL) {
		return -1;
	}
	memset(data, 0, sizeof(struct mount_cb_data));
	data->cb           = cb;
	data->private_data = private_data;
	data->server       = strdup(server);
	if (data->server == NULL) {
		free_mount_cb_data(data);
		return -1;
	}
	if (rpc_connect_program_async(rpc, data->server, MOUNT_PROGRAM,
                                      MOUNT_V3, mount_export_4_cb, data) != 0) {
		rpc_set_error(rpc, "Failed to start connection. %s",
                              rpc_get_error(rpc));
		free_mount_cb_data(data);
		return -1;
	}

	return 0;
}

struct rpc_context *
nfs_get_rpc_context(struct nfs_context *nfs)
{
	assert(nfs->rpc->magic == RPC_CONTEXT_MAGIC);
	return nfs->rpc;
}

const char *
nfs_get_server(struct nfs_context *nfs) {
	return nfs->server;
}

const char *
nfs_get_export(struct nfs_context *nfs) {
	return nfs->export;
}

const struct nfs_fh *
nfs_get_rootfh(struct nfs_context *nfs) {
      return &nfs->rootfh;
}

struct nfs_fh *
nfs_get_fh(struct nfsfh *nfsfh) {
       return &nfsfh->fh;
}

uint16_t
nfs_umask(struct nfs_context *nfs, uint16_t mask) {
	 uint16_t tmp = nfs->mask;
	 nfs->mask = mask;
	 return tmp;
}

/*
* Sets timeout for nfs apis
*/
void
nfs_set_timeout(struct nfs_context *nfs,int timeout)
{
	 rpc_set_timeout(nfs->rpc,timeout);
}

/*
* Gets timeout for nfs apis
*/
int
nfs_get_timeout(struct nfs_context *nfs)
{
	return rpc_get_timeout(nfs->rpc);
}

int
rpc_null_async(struct rpc_context *rpc, int program, int version, rpc_cb cb,
               void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, program, version, 0, cb, private_data,
                               (zdrproc_t)zdr_void, 0);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu "
                              "for NULL call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu "
                              "for NULL call");
		return -1;
	}

	return 0;
}
