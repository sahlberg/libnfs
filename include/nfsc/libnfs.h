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
 * This is the highlevel interface to access NFS resources using a posix-like interface
 */

#ifndef _LIBNFS_H_
#define _LIBNFS_H_

#include <stdint.h>
#if defined(ANDROID)
#include <sys/time.h>
#endif
#if defined(AROS)
#include <sys/time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct nfs_context;
struct rpc_context;

struct nfs_url {
	char *server;
	char *path;
	char *file;
};

#if defined(WIN32)
#define EXTERN __declspec( dllexport )
#else
#define EXTERN
#endif

#if defined(WIN32)
struct statvfs {
	uint32_t	f_bsize;
	uint32_t	f_frsize;
	uint64_t	f_blocks;
	uint64_t	f_bfree;
	uint64_t	f_bavail;
	uint32_t	f_files;
	uint32_t	f_ffree;
	uint32_t	f_favail;
	uint32_t	f_fsid;
	uint32_t	f_flag;
	uint32_t	f_namemax;
};
struct utimbuf {
	time_t actime;
	time_t modtime;
};
#define R_OK	4
#define W_OK	2
#define X_OK	1
#endif

/*
 * Used for interfacing the async version of the api into an external eventsystem
 */
EXTERN int nfs_get_fd(struct nfs_context *nfs);
EXTERN int nfs_which_events(struct nfs_context *nfs);
EXTERN int nfs_service(struct nfs_context *nfs, int revents);
EXTERN int nfs_queue_length(struct nfs_context *nfs);

/*
 * Used if you need different credentials than the default for the current user.
 */
struct AUTH;
EXTERN void nfs_set_auth(struct nfs_context *nfs, struct AUTH *auth);

/*
 * When an operation failed, this function can extract a detailed error string.
 */
EXTERN char *nfs_get_error(struct nfs_context *nfs);


/*
 * Callback for all ASYNC nfs functions
 */
typedef void (*nfs_cb)(int err, struct nfs_context *nfs, void *data, void *private_data);

/*
 * Callback for all ASYNC rpc functions
 */
typedef void (*rpc_cb)(struct rpc_context *rpc, int status, void *data, void *private_data);



/*
 * NFS CONTEXT.
 */
/*
 * Create an NFS c, the context.
 * Function returns
 *  NULL : Failed to create a context.
 *  *nfs : A pointer to an nfs context.
 */
EXTERN struct nfs_context *nfs_init_context(void);
/*
 * Destroy an nfs context.
 */
EXTERN void nfs_destroy_context(struct nfs_context *nfs);


/*
 * URL parsing functions.
 * These functions all parse a URL of the form
 * nfs://server/path/file?argv=val[&arg=val]*
 * and returns a nfs_url.
 *
 * Apart from parsing the URL the functions will also update
 * the nfs context to reflect settings controlled via url arguments.
 *
 * Current URL arguments are :
 * tcp-syncnt=<int>  : Number of SYNs to send during the seccion establish
 *                     before failing settin up the tcp connection to the
 *                     server.
 * uid=<int>         : UID value to use when talking to the server.
 *                     default it 65534 on Windows and getuid() on unixen.
 * gid=<int>         : GID value to use when talking to the server.
 *                     default it 65534 on Windows and getgid() on unixen.
 */
/*
 * Parse a complete NFS URL including, server, path and
 * filename. Fail if any component is missing.
 */
EXTERN struct nfs_url *nfs_parse_url_full(struct nfs_context *nfs, const char *url);

/*
 * Parse an NFS URL, but do not split path and file. File
 * in the resulting struct remains NULL.
 */
EXTERN struct nfs_url *nfs_parse_url_dir(struct nfs_context *nfs, const char *url);

/*
 * Parse an NFS URL, but do not fail if file, path or even server is missing.
 * Check elements of the resulting struct for NULL.
 */
EXTERN struct nfs_url *nfs_parse_url_incomplete(struct nfs_context *nfs, const char *url);


/*
 * Free the URL struct returned by the nfs_parse_url_* functions.
 */
EXTERN void nfs_destroy_url(struct nfs_url *url);


struct nfsfh;

/*
 * Get the maximum supported READ3 size by the server
 */
EXTERN uint64_t nfs_get_readmax(struct nfs_context *nfs);

/*
 * Get the maximum supported WRITE3 size by the server
 */
EXTERN uint64_t nfs_get_writemax(struct nfs_context *nfs);

/*
 *  MODIFY CONNECT PARAMTERS
 */

EXTERN void nfs_set_tcp_syncnt(struct nfs_context *nfs, int v);
EXTERN void nfs_set_uid(struct nfs_context *nfs, int uid);
EXTERN void nfs_set_gid(struct nfs_context *nfs, int gid);

/*
 * MOUNT THE EXPORT
 */
/*
 * Async nfs mount.
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_mount_async(struct nfs_context *nfs, const char *server, const char *exportname, nfs_cb cb, void *private_data);
/*
 * Sync nfs mount.
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_mount(struct nfs_context *nfs, const char *server, const char *exportname);




/*
 * STAT()
 */
/*
 * Async stat(<filename>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is struct stat *
 * -errno : An error occured.
 *          data is the error string.
 */
struct stat;
EXTERN int nfs_stat_async(struct nfs_context *nfs, const char *path, nfs_cb cb, void *private_data);
/*
 * Sync stat(<filename>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
#ifdef WIN32
EXTERN int nfs_stat(struct nfs_context *nfs, const char *path, struct __stat64 *st);
#else
EXTERN int nfs_stat(struct nfs_context *nfs, const char *path, struct stat *st);
#endif

/*
 * FSTAT()
 */
/*
 * Async fstat(nfsfh *)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is struct stat *
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_fstat_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb, void *private_data);
/*
 * Sync fstat(nfsfh *)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
#ifdef WIN32
EXTERN int nfs_fstat(struct nfs_context *nfs, struct nfsfh *nfsfh, struct __stat64 *st);
#else
EXTERN int nfs_fstat(struct nfs_context *nfs, struct nfsfh *nfsfh, struct stat *st);
#endif



/*
 * OPEN()
 */
/*
 * Async open(<filename>)
 *
 * mode is a combination of the flags : O_RDOLNY, O_WRONLY, O_RDWR , O_SYNC
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * Supported flags are
 * O_RDONLY
 * O_WRONLY
 * O_RDWR
 * O_TRUNC (Only valid with O_RDWR or O_WRONLY. Ignored otherwise.)
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is a struct *nfsfh;
 *          The nfsfh is close using nfs_close().
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_open_async(struct nfs_context *nfs, const char *path, int flags, nfs_cb cb, void *private_data);
/*
 * Sync open(<filename>)
 * Function returns
 *      0 : The operation was successfull. *nfsfh is filled in.
 * -errno : The command failed.
 */
EXTERN int nfs_open(struct nfs_context *nfs, const char *path, int flags, struct nfsfh **nfsfh);




/*
 * CLOSE
 */
/*
 * Async close(nfsfh)
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_close_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb, void *private_data);
/*
 * Sync close(nfsfh)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_close(struct nfs_context *nfs, struct nfsfh *nfsfh);


/*
 * PREAD()
 */
/*
 * Async pread()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Success.
 *          status is numer of bytes read.
 *          data is a pointer to the returned data.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_pread_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t offset, uint64_t count, nfs_cb cb, void *private_data);
/*
 * Sync pread()
 * Function returns
 *    >=0 : numer of bytes read.
 * -errno : An error occured.
 */
EXTERN int nfs_pread(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t offset, uint64_t count, char *buf);



/*
 * READ()
 */
/*
 * Async read()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Success.
 *          status is numer of bytes read.
 *          data is a pointer to the returned data.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_read_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t count, nfs_cb cb, void *private_data);
/*
 * Sync read()
 * Function returns
 *    >=0 : numer of bytes read.
 * -errno : An error occured.
 */
EXTERN int nfs_read(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t count, char *buf);




/*
 * PWRITE()
 */
/*
 * Async pwrite()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Success.
 *          status is numer of bytes written.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_pwrite_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t offset, uint64_t count, char *buf, nfs_cb cb, void *private_data);
/*
 * Sync pwrite()
 * Function returns
 *    >=0 : numer of bytes written.
 * -errno : An error occured.
 */
EXTERN int nfs_pwrite(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t offset, uint64_t count, char *buf);


/*
 * WRITE()
 */
/*
 * Async write()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Success.
 *          status is numer of bytes written.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_write_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t count, char *buf, nfs_cb cb, void *private_data);
/*
 * Sync write()
 * Function returns
 *    >=0 : numer of bytes written.
 * -errno : An error occured.
 */
EXTERN int nfs_write(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t count, char *buf);


/*
 * LSEEK()
 */
/*
 * Async lseek()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Success.
 *          data is uint64_t * for the current position.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_lseek_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t offset, int whence, nfs_cb cb, void *private_data);
/*
 * Sync lseek()
 * Function returns
 *    >=0 : numer of bytes read.
 * -errno : An error occured.
 */
EXTERN int nfs_lseek(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t offset, int whence, uint64_t *current_offset);


/*
 * FSYNC()
 */
/*
 * Async fsync()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_fsync_async(struct nfs_context *nfs, struct nfsfh *nfsfh, nfs_cb cb, void *private_data);
/*
 * Sync fsync()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_fsync(struct nfs_context *nfs, struct nfsfh *nfsfh);



/*
 * TRUNCATE()
 */
/*
 * Async truncate()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_truncate_async(struct nfs_context *nfs, const char *path, uint64_t length, nfs_cb cb, void *private_data);
/*
 * Sync truncate()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_truncate(struct nfs_context *nfs, const char *path, uint64_t length);



/*
 * FTRUNCATE()
 */
/*
 * Async ftruncate()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_ftruncate_async(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t length, nfs_cb cb, void *private_data);
/*
 * Sync ftruncate()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_ftruncate(struct nfs_context *nfs, struct nfsfh *nfsfh, uint64_t length);






/*
 * MKDIR()
 */
/*
 * Async mkdir()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_mkdir_async(struct nfs_context *nfs, const char *path, nfs_cb cb, void *private_data);
/*
 * Sync mkdir()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_mkdir(struct nfs_context *nfs, const char *path);



/*
 * RMDIR()
 */
/*
 * Async rmdir()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_rmdir_async(struct nfs_context *nfs, const char *path, nfs_cb cb, void *private_data);
/*
 * Sync rmdir()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_rmdir(struct nfs_context *nfs, const char *path);




/*
 * CREAT()
 */
/*
 * Async creat()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is a struct *nfsfh;
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_creat_async(struct nfs_context *nfs, const char *path, int mode, nfs_cb cb, void *private_data);
/*
 * Sync creat()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_creat(struct nfs_context *nfs, const char *path, int mode, struct nfsfh **nfsfh);


/*
 * MKNOD()
 */
/*
 * Async mknod()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_mknod_async(struct nfs_context *nfs, const char *path, int mode, int dev, nfs_cb cb, void *private_data);
/*
 * Sync mknod()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_mknod(struct nfs_context *nfs, const char *path, int mode, int dev);



/*
 * UNLINK()
 */
/*
 * Async unlink()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_unlink_async(struct nfs_context *nfs, const char *path, nfs_cb cb, void *private_data);
/*
 * Sync unlink()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_unlink(struct nfs_context *nfs, const char *path);




/*
 * OPENDIR()
 */
struct nfsdir;
/*
 * Async opendir()
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When struct nfsdir * is returned, this resource is closed/freed by calling nfs_closedir()
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is struct nfsdir *
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_opendir_async(struct nfs_context *nfs, const char *path, nfs_cb cb, void *private_data);
/*
 * Sync opendir()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
EXTERN int nfs_opendir(struct nfs_context *nfs, const char *path, struct nfsdir **nfsdir);



/*
 * READDIR()
 */
struct nfsdirent  {
       struct nfsdirent *next;
       char *name;
       uint64_t inode;

       /* Some extra fields we get for free through the READDIRPLUS3 call.
	  You need libnfs-raw-nfs.h for type/mode constants */
       uint32_t type; /* NF3REG, NF3DIR, NF3BLK, ... */
       uint32_t mode;
       uint64_t size;
       struct timeval atime;
       struct timeval mtime;
       struct timeval ctime;
       uint32_t uid;
       uint32_t gid;
};
/*
 * nfs_readdir() never blocks, so no special sync/async versions are available
 */
EXTERN struct nfsdirent *nfs_readdir(struct nfs_context *nfs, struct nfsdir *nfsdir);



/*
 * CLOSEDIR()
 */
/*
 * nfs_closedir() never blocks, so no special sync/async versions are available
 */
EXTERN void nfs_closedir(struct nfs_context *nfs, struct nfsdir *nfsdir);


/*
 * CHDIR()
 */
/*
 * Async chdir(<path>)
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL;
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_chdir_async(struct nfs_context *nfs, const char *path, nfs_cb cb, void *private_data);
/*
 * Sync chdir(<path>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_chdir(struct nfs_context *nfs, const char *path);

/*
 * GETCWD()
 */
/*
 * nfs_getcwd() never blocks, so no special sync/async versions are available
 */
/*
 * Sync getcwd()
 * This function returns a pointer to the current working directory.
 * This pointer is only stable until the next [f]chdir or when the
 * context is destroyed.
 *
 * Function returns
 *      0 : The operation was successfull and *cwd is filled in.
 * -errno : The command failed.
 */
EXTERN void nfs_getcwd(struct nfs_context *nfs, const char **cwd);


/*
 * STATVFS()
 */
/*
 * Async statvfs(<dirname>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is struct statvfs *
 * -errno : An error occured.
 *          data is the error string.
 */
struct statvfs;
EXTERN int nfs_statvfs_async(struct nfs_context *nfs, const char *path, nfs_cb cb, void *private_data);
/*
 * Sync statvfs(<dirname>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_statvfs(struct nfs_context *nfs, const char *path, struct statvfs *svfs);


/*
 * READLINK()
 */
/*
 * Async readlink(<name>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is a char *
 *          data is only valid during the callback and is automatically freed when the callback returns.
 * -errno : An error occured.
 *          data is the error string.
 */
struct statvfs;
EXTERN int nfs_readlink_async(struct nfs_context *nfs, const char *path, nfs_cb cb, void *private_data);
/*
 * Sync readlink(<name>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_readlink(struct nfs_context *nfs, const char *path, char *buf, int bufsize);



/*
 * CHMOD()
 */
/*
 * Async chmod(<name>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_chmod_async(struct nfs_context *nfs, const char *path, int mode, nfs_cb cb, void *private_data);
/*
 * Sync chmod(<name>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_chmod(struct nfs_context *nfs, const char *path, int mode);



/*
 * FCHMOD()
 */
/*
 * Async fchmod(<handle>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_fchmod_async(struct nfs_context *nfs, struct nfsfh *nfsfh, int mode, nfs_cb cb, void *private_data);
/*
 * Sync fchmod(<handle>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_fchmod(struct nfs_context *nfs, struct nfsfh *nfsfh, int mode);



/*
 * CHOWN()
 */
/*
 * Async chown(<name>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_chown_async(struct nfs_context *nfs, const char *path, int uid, int gid, nfs_cb cb, void *private_data);
/*
 * Sync chown(<name>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_chown(struct nfs_context *nfs, const char *path, int uid, int gid);



/*
 * FCHOWN()
 */
/*
 * Async fchown(<handle>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_fchown_async(struct nfs_context *nfs, struct nfsfh *nfsfh, int uid, int gid, nfs_cb cb, void *private_data);
/*
 * Sync fchown(<handle>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_fchown(struct nfs_context *nfs, struct nfsfh *nfsfh, int uid, int gid);




/*
 * UTIMES()
 */
/*
 * Async utimes(<path>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_utimes_async(struct nfs_context *nfs, const char *path, struct timeval *times, nfs_cb cb, void *private_data);
/*
 * Sync utimes(<path>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_utimes(struct nfs_context *nfs, const char *path, struct timeval *times);


/*
 * UTIME()
 */
/*
 * Async utime(<path>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
struct utimbuf;
EXTERN int nfs_utime_async(struct nfs_context *nfs, const char *path, struct utimbuf *times, nfs_cb cb, void *private_data);
/*
 * Sync utime(<path>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_utime(struct nfs_context *nfs, const char *path, struct utimbuf *times);




/*
 * ACCESS()
 */
/*
 * Async access(<path>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_access_async(struct nfs_context *nfs, const char *path, int mode, nfs_cb cb, void *private_data);
/*
 * Sync access(<path>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_access(struct nfs_context *nfs, const char *path, int mode);




/*
 * SYMLINK()
 */
/*
 * Async symlink(<path>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_symlink_async(struct nfs_context *nfs, const char *oldpath, const char *newpath, nfs_cb cb, void *private_data);
/*
 * Sync symlink(<path>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_symlink(struct nfs_context *nfs, const char *oldpath, const char *newpath);


/*
 * RENAME()
 */
/*
 * Async rename(<oldpath>, <newpath>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_rename_async(struct nfs_context *nfs, const char *oldpath, const char *newpath, nfs_cb cb, void *private_data);
/*
 * Sync rename(<oldpath>, <newpath>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_rename(struct nfs_context *nfs, const char *oldpath, const char *newpath);



/*
 * LINK()
 */
/*
 * Async link(<oldpath>, <newpath>)
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is NULL
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int nfs_link_async(struct nfs_context *nfs, const char *oldpath, const char *newpath, nfs_cb cb, void *private_data);
/*
 * Sync link(<oldpath>, <newpath>)
 * Function returns
 *      0 : The operation was successfull.
 * -errno : The command failed.
 */
EXTERN int nfs_link(struct nfs_context *nfs, const char *oldpath, const char *newpath);


/*
 * GETEXPORTS()
 */
/*
 * Async getexports()
 * NOTE: You must include 'libnfs-raw-mount.h' to get the definitions of the
 * returned structures.
 *
 * This function will return the list of exports from an NFS server.
 *
 * Function returns
 *  0 : The operation was initiated. Once the operation finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the operation. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          data is a pointer to an exports pointer:
 *          exports export = *(exports *)data;
 * -errno : An error occured.
 *          data is the error string.
 */
EXTERN int mount_getexports_async(struct rpc_context *rpc, const char *server, rpc_cb cb, void *private_data);
/*
 * Sync getexports(<server>)
 * Function returns
 *            NULL : something failed
 *  exports export : a linked list of exported directories
 *
 * returned data must be freed by calling mount_free_export_list(exportnode);
 */
EXTERN struct exportnode *mount_getexports(const char *server);

EXTERN void mount_free_export_list(struct exportnode *exports);


//qqq replace later with lseek(cur, 0)
uint64_t nfs_get_current_offset(struct nfsfh *nfsfh);





struct nfs_server_list {
       struct nfs_server_list *next;
       char *addr;
};

/*
 * Sync find_local_servers(<server>)
 * This function will probe all local networks for NFS server. This function will
 * block for one second while awaiting for all nfs servers to respond.
 *
 * Function returns
 * NULL : something failed
 *
 * struct nfs_server_list : a linked list of all discovered servers
 *
 * returned data must be freed by nfs_free_srvr_list(srv);
 */
struct nfs_server_list *nfs_find_local_servers(void);
void free_nfs_srvr_list(struct nfs_server_list *srv);

#ifdef __cplusplus
}
#endif

#endif /* !_LIBNFS_H_ */
