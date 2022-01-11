/* 
   Copyright (C) by Peter Lieven <pl@kamp.de> 2013
   
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
#define PRId64 "ll"
#else
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#ifndef AROS
#include <sys/statvfs.h>
#endif
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../include/nfsc/libnfs.h"
#include "../include/nfsc/libnfs-raw.h"
#include "../mount/libnfs-raw-mount.h"
#include "../nfs/libnfs-raw-nfs.h"
#include "../nfs4/libnfs-raw-nfs4.h"

void print_usage(void)
{
	fprintf(stderr, "Usage: nfs-io [-?|--help|--usage] [stat|creat|trunc|unlink|mkdir|rmdir|touch|chmod] <url>\n");
}


static char *acl3_type(int type)
{
	switch(type) {
	case NFSACL_TYPE_USER_OBJ: return "USER_OBJ";
	case NFSACL_TYPE_USER: return "USER";
	case NFSACL_TYPE_GROUP_OBJ: return "GROUP_OBJ";
	case NFSACL_TYPE_GROUP: return "GROUP";
	case NFSACL_TYPE_CLASS_OBJ: return "CLASS_OBJ";
	case NFSACL_TYPE_CLASS: return "CLASS";
	case NFSACL_TYPE_DEFAULT: return "DEFAULT";
	case NFSACL_TYPE_DEFAULT_USER_OBJ: return "DEFAULT_USER_OBJ";
	case NFSACL_TYPE_DEFAULT_USER: return "DEFAULT_USER";
	case NFSACL_TYPE_DEFAULT_GROUP_OBJ: return "DEFAULT_GROUP_OBJ";
	case NFSACL_TYPE_DEFAULT_GROUP: return "DEFAULT_GROUP";
	case NFSACL_TYPE_DEFAULT_CLASS_OBJ: return "DEFAULT_CLASS_OBJ";
	case NFSACL_TYPE_DEFAULT_OTHER_OBJ: return "DEFAULT_OTHER_OBJ";
	}
	return "Unknown ACE type";
}
    
int main(int argc, char *argv[])
{
	int ret = 1;
	struct nfs_context *nfs = NULL;
	struct nfsfh *nfsfh = NULL;
	struct nfs_url *url = NULL;
	fattr4_acl acl4;
	fattr3_acl acl3;
	int i;

#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		exit(10);
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

	if (argc < 3) {
		fprintf(stderr, "No URL specified.\n");
		goto finished;
	}

	nfs = nfs_init_context();
	if (nfs == NULL) {
		printf("failed to init context\n");
		goto finished;
	}

	url = nfs_parse_url_full(nfs, argv[argc - 1]);
	if (url == NULL) {
		fprintf(stderr, "%s\n", nfs_get_error(nfs));
		goto finished;
	}

	if (nfs_mount(nfs, url->server, url->path) != 0) {
 		fprintf(stderr, "Failed to mount nfs share : %s\n", nfs_get_error(nfs));
		goto finished;
	}

	if (!strncmp(argv[1], "creat", 5)) {
		ret = nfs_creat(nfs, url->file, 0600, &nfsfh);
	} else if (!strncmp(argv[1], "unlink", 6)) {
		ret = nfs_unlink(nfs, url->file);
	} else if (!strncmp(argv[1], "mkdir", 5)) {
		ret = nfs_mkdir(nfs, url->file);
	} else if (!strncmp(argv[1], "rmdir", 5)) {
		ret = nfs_rmdir(nfs, url->file);
	} else if (!strncmp(argv[1], "trunc", 5)) {
		ret = nfs_truncate(nfs, url->file, 0);
	} else if (!strncmp(argv[1], "touch", 5)) {
		struct timeval times[2];
		gettimeofday(&times[0], NULL);
		gettimeofday(&times[1], NULL);
		ret = nfs_utimes(nfs, url->file, times);
	} else if (!strncmp(argv[1], "chmod", 5)) {
		if (argc < 4) {
			fprintf(stderr, "Invalid arguments for chmod");
			goto finished;
		}
		int mode = strtol(argv[2], NULL, 8);
		ret = nfs_chmod(nfs, url->file, mode);
	} else if (!strncmp(argv[1], "chown", 5)) {
		if (argc < 5) {
			fprintf(stderr, "Invalid arguments for chown");
			goto finished;
		}
		int uid = strtol(argv[2], NULL, 10);
		int gid = strtol(argv[3], NULL, 10);
		ret = nfs_chown(nfs, url->file, uid, gid);
	} else if (!strncmp(argv[1], "stat", 4)) {
		struct nfs_stat_64 st;
		ret = nfs_stat64(nfs, url->file, &st);
		if (!ret) {
			switch (st.nfs_mode & S_IFMT) {
	#ifndef WIN32
			case S_IFLNK:
				printf("l");
				break;
	#endif
			case S_IFREG:
				printf("-");
				break;
			case S_IFDIR:
				printf("d");
				break;
			case S_IFCHR:
				printf("c");
				break;
			case S_IFBLK:
				printf("b");
				break;
			}
			printf("%c%c%c",
			       "-r"[!!(st.nfs_mode & S_IRUSR)],
			       "-w"[!!(st.nfs_mode & S_IWUSR)],
			       "-xSs"[  !!(st.nfs_mode & S_IXUSR) +
				      2*!!(st.nfs_mode & S_ISUID)]
			       );
			printf("%c%c%c",
			       "-r"[!!(st.nfs_mode & S_IRGRP)],
			       "-w"[!!(st.nfs_mode & S_IWGRP)],
			       "-xSs"[  !!(st.nfs_mode & S_IXGRP) +
				      2*!!(st.nfs_mode & S_ISGID)]
			);
			printf("%c%c%c",
			       "-r"[!!(st.nfs_mode & S_IROTH)],
			       "-w"[!!(st.nfs_mode & S_IWOTH)],
			       "-xTt"[  !!(st.nfs_mode & S_IXOTH) +
				      2*!!(st.nfs_mode & S_ISVTX)]
			);
			printf(" %2d", (int)st.nfs_nlink);
			printf(" %5d", (int)st.nfs_uid);
			printf(" %5d", (int)st.nfs_gid);
			printf(" size: %12" PRId64, st.nfs_size);
			printf(" mtime: %lu %lu", st.nfs_mtime, st.nfs_mtime_nsec);
			printf("\n");
		}
	} else if (!strncmp(argv[1], "acl", 3)) {
		ret = nfs_open(nfs, url->file, 0600, &nfsfh);
		if (ret != 0) {
			printf("failed to open %s. %s\n", url->file, nfs_get_error(nfs));
			goto finished;
		}

		printf("ACL version:%d\n", nfs_get_version(nfs));
		
		if (nfs_get_version(nfs) == NFS_V3) {
			printf("Get v3 ACL\n");
			memset(&acl3, 0, sizeof(fattr3_acl));
			if (nfs3_getacl(nfs, nfsfh, &acl3) != 0) {
				printf("nfs3_getacl_async failed\n");
			}
			printf("Number of ACEs: %d\n", acl3.ace_count);
			for (i = 0; i < acl3.ace_count; i++) {
				printf("%s(%d) ", acl3_type(acl3.ace[i].type), acl3.ace[i].type);
				printf("Id: %d ", acl3.ace[i].id);
				printf("Perm: 0x%x: %s%s%s\n", acl3.ace[i].perm,
				       acl3.ace[i].perm & NFSACL_PERM_READ ? "READ ":"",
				       acl3.ace[i].perm & NFSACL_PERM_WRITE ? "WRITE ":"",
				       acl3.ace[i].perm & NFSACL_PERM_EXEC ? "EXEC ":"");
			}
			nfs3_acl_free(&acl3);
			goto finished;
		}

		/* NFS_V4 */
		if (nfs4_getacl(nfs, nfsfh, &acl4)) {
			printf("Failed to read ACLs %s\n", nfs_get_error(nfs));
			goto finished;
		}
		for (i = 0; i < acl4.fattr4_acl_len; i++) {
			printf("Type:%d Flag:%d Mask:0x%08x Who:%s\n",
			       acl4.fattr4_acl_val[i].type,
			       acl4.fattr4_acl_val[i].flag,
			       acl4.fattr4_acl_val[i].access_mask,
			       acl4.fattr4_acl_val[i].who.utf8string_val);
		}
		nfs4_acl_free(&acl4);
		ret = 0;
	} else {
		goto finished;
	}
	
	if (ret) {
		fprintf(stderr, "ERROR: %s\n", nfs_get_error(nfs));
	}

finished:
	if (ret > 0) {
		print_usage();
	}
	nfs_destroy_url(url);
	if (nfs != NULL) {		
		if (nfsfh) {
			nfs_close(nfs, nfsfh);
		}
		nfs_destroy_context(nfs);
	}
	return !!ret;
}

