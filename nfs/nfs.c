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

#ifdef WIN32
#include "win32_compat.h"
#else
#include <sys/stat.h>
#endif/*WIN32*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#include "libnfs-raw-nfs.h"

char *nfsstat3_to_str(int error)
{
	switch (error) {
	case NFS3_OK: return "NFS3_OK"; break;
	case NFS3ERR_PERM: return "NFS3ERR_PERM"; break;
	case NFS3ERR_NOENT: return "NFS3ERR_NOENT"; break;
	case NFS3ERR_IO: return "NFS3ERR_IO"; break;
	case NFS3ERR_NXIO: return "NFS3ERR_NXIO"; break;
	case NFS3ERR_ACCES: return "NFS3ERR_ACCES"; break;
	case NFS3ERR_EXIST: return "NFS3ERR_EXIST"; break;
	case NFS3ERR_XDEV: return "NFS3ERR_XDEV"; break;
	case NFS3ERR_NODEV: return "NFS3ERR_NODEV"; break;
	case NFS3ERR_NOTDIR: return "NFS3ERR_NOTDIR"; break;
	case NFS3ERR_ISDIR: return "NFS3ERR_ISDIR"; break;
	case NFS3ERR_INVAL: return "NFS3ERR_INVAL"; break;
	case NFS3ERR_FBIG: return "NFS3ERR_FBIG"; break;
	case NFS3ERR_NOSPC: return "NFS3ERR_NOSPC"; break;
	case NFS3ERR_ROFS: return "NFS3ERR_ROFS"; break;
	case NFS3ERR_MLINK: return "NFS3ERR_MLINK"; break;
	case NFS3ERR_NAMETOOLONG: return "NFS3ERR_NAMETOOLONG"; break;
	case NFS3ERR_NOTEMPTY: return "NFS3ERR_NOTEMPTY"; break;
	case NFS3ERR_DQUOT: return "NFS3ERR_DQUOT"; break;
	case NFS3ERR_STALE: return "NFS3ERR_STALE"; break;
	case NFS3ERR_REMOTE: return "NFS3ERR_REMOTE"; break;
	case NFS3ERR_BADHANDLE: return "NFS3ERR_BADHANDLE"; break;
	case NFS3ERR_NOT_SYNC: return "NFS3ERR_NOT_SYNC"; break;
	case NFS3ERR_BAD_COOKIE: return "NFS3ERR_BAD_COOKIE"; break;
	case NFS3ERR_NOTSUPP: return "NFS3ERR_NOTSUPP"; break;
	case NFS3ERR_TOOSMALL: return "NFS3ERR_TOOSMALL"; break;
	case NFS3ERR_SERVERFAULT: return "NFS3ERR_SERVERFAULT"; break;
	case NFS3ERR_BADTYPE: return "NFS3ERR_BADTYPE"; break;
	case NFS3ERR_JUKEBOX: return "NFS3ERR_JUKEBOX"; break;
	};
	return "unknown nfs error";
}

int nfsstat3_to_errno(int error)
{
	switch (error) {
	case NFS3_OK:             return 0; break;
	case NFS3ERR_PERM:        return -EPERM; break;
	case NFS3ERR_NOENT:       return -ENOENT; break;
	case NFS3ERR_IO:          return -EIO; break;
	case NFS3ERR_NXIO:        return -ENXIO; break;
	case NFS3ERR_ACCES:       return -EACCES; break;
	case NFS3ERR_EXIST:       return -EEXIST; break;
	case NFS3ERR_XDEV:        return -EXDEV; break;
	case NFS3ERR_NODEV:       return -ENODEV; break;
	case NFS3ERR_NOTDIR:      return -ENOTDIR; break;
	case NFS3ERR_ISDIR:       return -EISDIR; break;
	case NFS3ERR_INVAL:       return -EINVAL; break;
	case NFS3ERR_FBIG:        return -EFBIG; break;
	case NFS3ERR_NOSPC:       return -ENOSPC; break;
	case NFS3ERR_ROFS:        return -EROFS; break;
	case NFS3ERR_MLINK:       return -EMLINK; break;
	case NFS3ERR_NAMETOOLONG: return -ENAMETOOLONG; break;
	case NFS3ERR_NOTEMPTY:    return -ENOTEMPTY; break;
	case NFS3ERR_DQUOT:       return -ERANGE; break;
	case NFS3ERR_STALE:       return -EIO; break;
	case NFS3ERR_REMOTE:      return -EIO; break;
	case NFS3ERR_BADHANDLE:   return -EIO; break;
	case NFS3ERR_NOT_SYNC:    return -EIO; break;
	case NFS3ERR_BAD_COOKIE:  return -EIO; break;
	case NFS3ERR_NOTSUPP:     return -EINVAL; break;
	case NFS3ERR_TOOSMALL:    return -EIO; break;
	case NFS3ERR_SERVERFAULT: return -EIO; break;
	case NFS3ERR_BADTYPE:     return -EINVAL; break;
	case NFS3ERR_JUKEBOX:     return -EAGAIN; break;
	};
	return -ERANGE;
}


/*
 * NFSv3
 */
int rpc_nfs3_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_NULL, cb, private_data, (zdrproc_t)zdr_void, 0);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/NULL call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/NULL call");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	return 0;
}

int rpc_nfs_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	return rpc_nfs3_null_async(rpc, cb, private_data);
}

int rpc_nfs3_getattr_async(struct rpc_context *rpc, rpc_cb cb, struct GETATTR3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_GETATTR, cb, private_data, (zdrproc_t)zdr_GETATTR3res, sizeof(GETATTR3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/GETATTR call");
		return -1;
	}

	if (zdr_GETATTR3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode GETATTR3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/GETATTR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_getattr_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data)
{
	GETATTR3args args;

	memset(&args, 0, sizeof(GETATTR3args));
	args.object.data.data_len = fh->data.data_len; 
	args.object.data.data_val = fh->data.data_val; 

	return rpc_nfs3_getattr_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_pathconf_async(struct rpc_context *rpc, rpc_cb cb, struct PATHCONF3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_PATHCONF, cb, private_data, (zdrproc_t)zdr_PATHCONF3res, sizeof(PATHCONF3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/PATHCONF call");
		return -1;
	}

	if (zdr_PATHCONF3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode PATHCONF3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/PATHCONF call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_pathconf_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data)
{
	PATHCONF3args args;

	memset(&args, 0, sizeof(PATHCONF3args));
	args.object.data.data_len = fh->data.data_len; 
	args.object.data.data_val = fh->data.data_val; 

	return rpc_nfs3_pathconf_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_lookup_async(struct rpc_context *rpc, rpc_cb cb, struct LOOKUP3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_LOOKUP, cb, private_data, (zdrproc_t)zdr_LOOKUP3res, sizeof(LOOKUP3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/LOOKUP call");
		return -1;
	}

	if (zdr_LOOKUP3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode LOOKUP3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/LOOKUP call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_lookup_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *name, void *private_data)
{
	LOOKUP3args args;

	memset(&args, 0, sizeof(LOOKUP3args));
	args.what.dir.data.data_len = fh->data.data_len; 
	args.what.dir.data.data_val = fh->data.data_val; 
	args.what.name              = name;

	return rpc_nfs3_lookup_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_access_async(struct rpc_context *rpc, rpc_cb cb, struct ACCESS3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_ACCESS, cb, private_data, (zdrproc_t)zdr_ACCESS3res, sizeof(ACCESS3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/ACCESS call");
		return -1;
	}

	if (zdr_ACCESS3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode ACCESS3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/ACCESS call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_access_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, int access, void *private_data)
{
	ACCESS3args args;

	memset(&args, 0, sizeof(ACCESS3args));
	args.object.data.data_len = fh->data.data_len;
	args.object.data.data_val = fh->data.data_val;
	args.access = access;

	return rpc_nfs3_access_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_read_async(struct rpc_context *rpc, rpc_cb cb, struct READ3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_READ, cb, private_data, (zdrproc_t)zdr_READ3res, sizeof(READ3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/READ call");
		return -1;
	}

	if (zdr_READ3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode READ3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/READ call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_read_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, uint64_t offset, uint64_t count, void *private_data)
{
	READ3args args;

	memset(&args, 0, sizeof(READ3args));
	args.file.data.data_len = fh->data.data_len;
	args.file.data.data_val = fh->data.data_val;
	args.offset = offset;
	args.count = count;

	return rpc_nfs3_read_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_write_async(struct rpc_context *rpc, rpc_cb cb, struct WRITE3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_WRITE, cb, private_data, (zdrproc_t)zdr_WRITE3res, sizeof(WRITE3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/WRITE call");
		return -1;
	}

	if (zdr_WRITE3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode WRITE3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/WRITE call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_write_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *buf, uint64_t offset, uint64_t count, int stable_how, void *private_data)
{
	WRITE3args args;

	memset(&args, 0, sizeof(WRITE3args));
	args.file.data.data_len = fh->data.data_len;
	args.file.data.data_val = fh->data.data_val;
	args.offset = offset;
	args.count  = count;
	args.stable = stable_how;
	args.data.data_len = count;
	args.data.data_val = buf;

	return rpc_nfs3_write_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_commit_async(struct rpc_context *rpc, rpc_cb cb, struct COMMIT3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_COMMIT, cb, private_data, (zdrproc_t)zdr_COMMIT3res, sizeof(COMMIT3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/COMMIT call");
		return -1;
	}

	if (zdr_COMMIT3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode COMMIT3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/COMMIT call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_commit_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data)
{
	COMMIT3args args;

	memset(&args, 0, sizeof(COMMIT3args));
	args.file.data.data_len = fh->data.data_len;
	args.file.data.data_val = fh->data.data_val;
	args.offset = 0;
	args.count  = 0;

	return rpc_nfs3_commit_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_setattr_async(struct rpc_context *rpc, rpc_cb cb, SETATTR3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_SETATTR, cb, private_data, (zdrproc_t)zdr_SETATTR3res, sizeof(SETATTR3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/SETATTR call");
		return -1;
	}

	if (zdr_SETATTR3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode SETATTR3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/SETATTR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_setattr_async(struct rpc_context *rpc, rpc_cb cb, SETATTR3args *args, void *private_data)
{
	return rpc_nfs3_setattr_async(rpc, cb, args, private_data);
}

int rpc_nfs3_mkdir_async(struct rpc_context *rpc, rpc_cb cb, MKDIR3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_MKDIR, cb, private_data, (zdrproc_t)zdr_MKDIR3res, sizeof(MKDIR3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/MKDIR call");
		return -1;
	}

	if (zdr_MKDIR3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode MKDIR3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/MKDIR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_mkdir_async(struct rpc_context *rpc, rpc_cb cb, MKDIR3args *args, void *private_data)
{
	return rpc_nfs3_mkdir_async(rpc, cb, args, private_data);
}

int rpc_nfs3_rmdir_async(struct rpc_context *rpc, rpc_cb cb, struct RMDIR3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_RMDIR, cb, private_data, (zdrproc_t)zdr_RMDIR3res, sizeof(RMDIR3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/RMDIR call");
		return -1;
	}

	if (zdr_RMDIR3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode RMDIR3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/RMDIR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_rmdir_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *dir, void *private_data)
{
	RMDIR3args args;

	memset(&args, 0, sizeof(RMDIR3args));
	args.object.dir.data.data_len = fh->data.data_len;
	args.object.dir.data.data_val = fh->data.data_val;
	args.object.name = dir;

	return rpc_nfs3_rmdir_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_create_async(struct rpc_context *rpc, rpc_cb cb, CREATE3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_CREATE, cb, private_data, (zdrproc_t)zdr_CREATE3res, sizeof(CREATE3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/CREATE call");
		return -1;
	}

	if (zdr_CREATE3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode CREATE3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/CREATE call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_create_async(struct rpc_context *rpc, rpc_cb cb, CREATE3args *args, void *private_data)
{
	return rpc_nfs3_create_async(rpc, cb, args, private_data);
}

int rpc_nfs3_mknod_async(struct rpc_context *rpc, rpc_cb cb, struct MKNOD3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_MKNOD, cb, private_data, (zdrproc_t)zdr_MKNOD3res, sizeof(MKNOD3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/MKNOD call");
		return -1;
	}

	if (zdr_MKNOD3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode MKNOD3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/MKNOD call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_mknod_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *file, int mode, int major, int minor, void *private_data)
{
	MKNOD3args args;

	memset(&args, 0, sizeof(MKNOD3args));
	args.where.dir.data.data_len = fh->data.data_len;
	args.where.dir.data.data_val = fh->data.data_val;
	args.where.name = file;

	switch (mode & S_IFMT) {
	case S_IFCHR:
		args.what.type = NF3CHR;
		args.what.mknoddata3_u.chr_device.dev_attributes.mode.set_it = 1;
		args.what.mknoddata3_u.chr_device.dev_attributes.mode.set_mode3_u.mode = mode & (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
		args.what.mknoddata3_u.chr_device.spec.specdata1 = major;
		args.what.mknoddata3_u.chr_device.spec.specdata2 = minor;
		break;
	case S_IFBLK:
		args.what.type = NF3BLK;
		args.what.mknoddata3_u.blk_device.dev_attributes.mode.set_it = 1;
		args.what.mknoddata3_u.blk_device.dev_attributes.mode.set_mode3_u.mode = mode & (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
		args.what.mknoddata3_u.blk_device.spec.specdata1 = major;
		args.what.mknoddata3_u.blk_device.spec.specdata2 = minor;
	case S_IFSOCK:
		args.what.type = NF3SOCK;
		args.what.mknoddata3_u.sock_attributes.mode.set_it = 1;
		args.what.mknoddata3_u.sock_attributes.mode.set_mode3_u.mode = mode & (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
		break;
	case S_IFIFO:
		args.what.type = NF3FIFO;
		args.what.mknoddata3_u.pipe_attributes.mode.set_it = 1;
		args.what.mknoddata3_u.pipe_attributes.mode.set_mode3_u.mode = mode & (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
		break;
	default:
		rpc_set_error(rpc, "Invalid file type for NFS3/MKNOD call");
		return -1;
	}

	return rpc_nfs3_mknod_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_remove_async(struct rpc_context *rpc, rpc_cb cb, struct REMOVE3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_REMOVE, cb, private_data, (zdrproc_t)zdr_REMOVE3res, sizeof(REMOVE3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/REMOVE call");
		return -1;
	}

	if (zdr_REMOVE3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode REMOVE3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/REMOVE call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_remove_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *file, void *private_data)
{
	REMOVE3args args;

	memset(&args, 0, sizeof(REMOVE3args));
	args.object.dir.data.data_len = fh->data.data_len;
	args.object.dir.data.data_val = fh->data.data_val;
	args.object.name = file;

	return rpc_nfs3_remove_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_readdir_async(struct rpc_context *rpc, rpc_cb cb, struct READDIR3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_READDIR, cb, private_data, (zdrproc_t)zdr_READDIR3res, sizeof(READDIR3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/READDIR call");
		return -1;
	}

	if (zdr_READDIR3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode READDIR3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/READDIR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_readdir_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, uint64_t cookie, char *cookieverf, int count, void *private_data)
{
	READDIR3args args;

	memset(&args, 0, sizeof(READDIR3args));
	args.dir.data.data_len = fh->data.data_len;
	args.dir.data.data_val = fh->data.data_val;
	args.cookie = cookie;
	memcpy(&args.cookieverf, cookieverf, sizeof(cookieverf3)); 
	args.count = count;

	return rpc_nfs3_readdir_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_readdirplus_async(struct rpc_context *rpc, rpc_cb cb, struct READDIRPLUS3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_READDIRPLUS, cb, private_data, (zdrproc_t)zdr_READDIRPLUS3res, sizeof(READDIRPLUS3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/READDIRPLUS call");
		return -1;
	}

	if (zdr_READDIRPLUS3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode READDIRPLUS3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/READDIRPLUS call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_readdirplus_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, uint64_t cookie, char *cookieverf, int count, void *private_data)
{
	READDIRPLUS3args args;

	memset(&args, 0, sizeof(READDIRPLUS3args));
	args.dir.data.data_len = fh->data.data_len;
	args.dir.data.data_val = fh->data.data_val;
	args.cookie = cookie;
	memcpy(&args.cookieverf, cookieverf, sizeof(cookieverf3)); 
	args.dircount = count;
	args.maxcount = count * 8;

	return rpc_nfs3_readdirplus_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_fsstat_async(struct rpc_context *rpc, rpc_cb cb, struct FSSTAT3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_FSSTAT, cb, private_data, (zdrproc_t)zdr_FSSTAT3res, sizeof(FSSTAT3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/FSSTAT call");
		return -1;
	}

	if (zdr_FSSTAT3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode FSSTAT3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/FSSTAT call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_fsstat_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data)
{
	FSSTAT3args args;

	memset(&args, 0, sizeof(FSSTAT3args));
	args.fsroot.data.data_len = fh->data.data_len; 
	args.fsroot.data.data_val = fh->data.data_val; 

	return rpc_nfs3_fsstat_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_fsinfo_async(struct rpc_context *rpc, rpc_cb cb, struct FSINFO3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_FSINFO, cb, private_data, (zdrproc_t)zdr_FSINFO3res, sizeof(FSINFO3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/FSINFO call");
		return -1;
	}

	if (zdr_FSINFO3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode FSINFO3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/FSINFO call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_fsinfo_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data)
{
	FSINFO3args args;

	memset(&args, 0, sizeof(FSINFO3args));
	args.fsroot.data.data_len = fh->data.data_len; 
	args.fsroot.data.data_val = fh->data.data_val; 

	return rpc_nfs3_fsinfo_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_readlink_async(struct rpc_context *rpc, rpc_cb cb, READLINK3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_READLINK, cb, private_data, (zdrproc_t)zdr_READLINK3res, sizeof(READLINK3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/READLINK call");
		return -1;
	}

	if (zdr_READLINK3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode READLINK3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/READLINK call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_readlink_async(struct rpc_context *rpc, rpc_cb cb, READLINK3args *args, void *private_data)
{
	return rpc_nfs3_readlink_async(rpc, cb, args, private_data);
}

int rpc_nfs3_symlink_async(struct rpc_context *rpc, rpc_cb cb, SYMLINK3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_SYMLINK, cb, private_data, (zdrproc_t)zdr_SYMLINK3res, sizeof(SYMLINK3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/SYMLINK call");
		return -1;
	}

	if (zdr_SYMLINK3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode SYMLINK3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/SYMLINK call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_symlink_async(struct rpc_context *rpc, rpc_cb cb, SYMLINK3args *args, void *private_data)
{
	return rpc_nfs3_symlink_async(rpc, cb, args, private_data);
}

int rpc_nfs3_rename_async(struct rpc_context *rpc, rpc_cb cb, struct RENAME3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_RENAME, cb, private_data, (zdrproc_t)zdr_RENAME3res, sizeof(RENAME3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/RENAME call");
		return -1;
	}

	if (zdr_RENAME3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode RENAME3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/RENAME call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_rename_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *olddir, char *oldname, struct nfs_fh3 *newdir, char *newname, void *private_data)
{
	RENAME3args args;

	memset(&args, 0, sizeof(RENAME3args));
	args.from.dir.data.data_len = olddir->data.data_len;
	args.from.dir.data.data_val = olddir->data.data_val;
	args.from.name = oldname;
	args.to.dir.data.data_len = newdir->data.data_len;
	args.to.dir.data.data_val = newdir->data.data_val;
	args.to.name = newname;

	return rpc_nfs3_rename_async(rpc, cb, &args, private_data);
}

int rpc_nfs3_link_async(struct rpc_context *rpc, rpc_cb cb, struct LINK3args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V3, NFS3_LINK, cb, private_data, (zdrproc_t)zdr_LINK3res, sizeof(LINK3res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/LINK call");
		return -1;
	}

	if (zdr_LINK3args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode LINK3args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS3/LINK call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs_link_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *file, struct nfs_fh3 *newdir, char *newname, void *private_data)
{
	LINK3args args;

	memset(&args, 0, sizeof(LINK3args));
	args.file.data.data_len = file->data.data_len;
	args.file.data.data_val = file->data.data_val;
	args.link.dir.data.data_len = newdir->data.data_len;
	args.link.dir.data.data_val = newdir->data.data_val;
	args.link.name = newname;

	return rpc_nfs3_link_async(rpc, cb, &args, private_data);
}

/*
 * NFSv2
 */
int rpc_nfs2_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_NULL, cb, private_data, (zdrproc_t)zdr_void, 0);
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/NULL call");
		return -1;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/NULL call");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	return 0;
}

int rpc_nfs2_getattr_async(struct rpc_context *rpc, rpc_cb cb, struct GETATTR2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_GETATTR, cb, private_data, (zdrproc_t)zdr_GETATTR2res, sizeof(GETATTR2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/GETATTR call");
		return -1;
	}

	if (zdr_GETATTR2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode GETATTR2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/GETATTR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_setattr_async(struct rpc_context *rpc, rpc_cb cb, SETATTR2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_SETATTR, cb, private_data, (zdrproc_t)zdr_SETATTR2res, sizeof(SETATTR2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/SETATTR call");
		return -1;
	}

	if (zdr_SETATTR2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode SETATTR2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/SETATTR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_lookup_async(struct rpc_context *rpc, rpc_cb cb, struct LOOKUP2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_LOOKUP, cb, private_data, (zdrproc_t)zdr_LOOKUP2res, sizeof(LOOKUP2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/LOOKUP call");
		return -1;
	}

	if (zdr_LOOKUP2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode LOOKUP2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/LOOKUP call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_readlink_async(struct rpc_context *rpc, rpc_cb cb, READLINK2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_READLINK, cb, private_data, (zdrproc_t)zdr_READLINK2res, sizeof(READLINK2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/READLINK call");
		return -1;
	}

	if (zdr_READLINK2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode READLINK2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/READLINK call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_read_async(struct rpc_context *rpc, rpc_cb cb, struct READ2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_READ, cb, private_data, (zdrproc_t)zdr_READ2res, sizeof(READ2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/READ call");
		return -1;
	}

	if (zdr_READ2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode READ2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/READ call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_write_async(struct rpc_context *rpc, rpc_cb cb, struct WRITE2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_WRITE, cb, private_data, (zdrproc_t)zdr_WRITE2res, sizeof(WRITE2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/WRITE call");
		return -1;
	}

	if (zdr_WRITE2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode WRITE2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/WRITE call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_create_async(struct rpc_context *rpc, rpc_cb cb, CREATE2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_CREATE, cb, private_data, (zdrproc_t)zdr_CREATE2res, sizeof(CREATE2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/CREATE call");
		return -1;
	}

	if (zdr_CREATE2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode CREATE2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/CREATE call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_remove_async(struct rpc_context *rpc, rpc_cb cb, struct REMOVE2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_REMOVE, cb, private_data, (zdrproc_t)zdr_REMOVE2res, sizeof(REMOVE2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS3/REMOVE call");
		return -1;
	}

	if (zdr_REMOVE2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode REMOVE2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/REMOVE call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_rename_async(struct rpc_context *rpc, rpc_cb cb, struct RENAME2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_RENAME, cb, private_data, (zdrproc_t)zdr_RENAME2res, sizeof(RENAME2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/RENAME call");
		return -1;
	}

	if (zdr_RENAME2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode RENAME2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/RENAME call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_link_async(struct rpc_context *rpc, rpc_cb cb, LINK2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_LINK, cb, private_data, (zdrproc_t)zdr_LINK2res, sizeof(LINK2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/LINK call");
		return -1;
	}

	if (zdr_LINK2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode LINK2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/LINK call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_symlink_async(struct rpc_context *rpc, rpc_cb cb, SYMLINK2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_SYMLINK, cb, private_data, (zdrproc_t)zdr_SYMLINK2res, sizeof(SYMLINK2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/SYMLINK call");
		return -1;
	}

	if (zdr_SYMLINK2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode SYMLINK2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/SYMLINK call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_mkdir_async(struct rpc_context *rpc, rpc_cb cb, MKDIR2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_MKDIR, cb, private_data, (zdrproc_t)zdr_MKDIR2res, sizeof(MKDIR2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/MKDIR call");
		return -1;
	}

	if (zdr_MKDIR2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode MKDIR2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/MKDIR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_rmdir_async(struct rpc_context *rpc, rpc_cb cb, struct RMDIR2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_RMDIR, cb, private_data, (zdrproc_t)zdr_RMDIR2res, sizeof(RMDIR2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/RMDIR call");
		return -1;
	}

	if (zdr_RMDIR2args(&pdu->zdr, args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode RMDIR2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/RMDIR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_readdir_async(struct rpc_context *rpc, rpc_cb cb, struct READDIR2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_READDIR, cb, private_data, (zdrproc_t)zdr_READDIR2res, sizeof(READDIR2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/READDIR call");
		return -1;
	}

	if (zdr_READDIR2args(&pdu->zdr,  args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode READDIR2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/READDIR call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}

int rpc_nfs2_statfs_async(struct rpc_context *rpc, rpc_cb cb, struct STATFS2args *args, void *private_data)
{
	struct rpc_pdu *pdu;

	pdu = rpc_allocate_pdu(rpc, NFS_PROGRAM, NFS_V2, NFS2_STATFS, cb, private_data, (zdrproc_t)zdr_STATFS2res, sizeof(STATFS2res));
	if (pdu == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate pdu for NFS2/STATFS call");
		return -1;
	}

	if (zdr_STATFS2args(&pdu->zdr,  args) == 0) {
		rpc_set_error(rpc, "ZDR error: Failed to encode STATFS2args");
		rpc_free_pdu(rpc, pdu);
		return -2;
	}

	if (rpc_queue_pdu(rpc, pdu) != 0) {
		rpc_set_error(rpc, "Out of memory. Failed to queue pdu for NFS2/STATFS call");
		rpc_free_pdu(rpc, pdu);
		return -3;
	}

	return 0;
}
