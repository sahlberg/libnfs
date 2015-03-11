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
 * This is the lowlevel interface to access NFS resources.
 * Through this interface you have access to the full gamut of nfs and nfs related
 * protocol as well as the XDR encoded/decoded structures.
 */
#ifndef _LIBNFS_RAW_H_
#define _LIBNFS_RAW_H_

#include <stdint.h>
#include <nfsc/libnfs-zdr.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rpc_data {
       int size;
       unsigned char *data;
};

struct rpc_context;
struct rpc_context *rpc_init_context(void);
void rpc_destroy_context(struct rpc_context *rpc);

void rpc_set_auth(struct rpc_context *rpc, struct AUTH *auth);

int rpc_get_fd(struct rpc_context *rpc);
int rpc_which_events(struct rpc_context *rpc);
int rpc_service(struct rpc_context *rpc, int revents);
char *rpc_get_error(struct rpc_context *rpc);
int rpc_queue_length(struct rpc_context *rpc);

/* Utility function to get an RPC context from a NFS context. Useful for doing low level NFSACL
 * calls on a NFS context.
 */
struct rpc_context *nfs_get_rpc_context(struct nfs_context *nfs);

/* This function returns the nfs_fh3 structure from a nfsfh structure.
   This allows to use a file onened with nfs_open() together with low-level
   rpc functions that thake a nfs filehandle
*/
struct nfs_fh3 *nfs_get_fh(struct nfsfh *nfsfh);

/* Control what the next XID value to be used on the context will be.
   This can be used when multiple contexts are used to the same server
   to avoid that the two contexts have xid collissions.
 */
void rpc_set_next_xid(struct rpc_context *rpc, uint32_t xid);

/* This function can be used to set the file descriptor used for
 * the RPC context. It is primarily useful when emulating dup2()
 * and similar or where you want full control of the filedescriptor numbers
 * used by the rpc socket.
 *
 * ...
 * oldfd = rpc_get_fd(rpc);
 * dup2(oldfd, newfd);
 * rpc_set_fd(rpc, newfd);
 * close(oldfd);
 * ...
 */
void rpc_set_fd(struct rpc_context *rpc, int fd);

#define RPC_STATUS_SUCCESS	   	0
#define RPC_STATUS_ERROR		1
#define RPC_STATUS_CANCEL		2

/*
 * Async connection to the tcp port at server:port.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : The tcp connection was successfully established.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : The connection failed to establish.
 *                      data is the erro string.
 * RPC_STATUS_CANCEL  : The connection attempt was aborted before it could complete.
 *                    : data is NULL.
 */
int rpc_connect_async(struct rpc_context *rpc, const char *server, int port, rpc_cb cb, void *private_data);
/*
 * Async function to connect to a specific RPC program/version
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : The tcp connection was successfully established.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : The connection failed to establish.
 *                      data is the erro string.
 * RPC_STATUS_CANCEL  : The connection attempt was aborted before it could complete.
 *                    : data is NULL.
 */
int rpc_connect_program_async(struct rpc_context *rpc, const char *server, int program, int version, rpc_cb cb, void *private_data);
/*
 * When disconnecting a connection in flight. All commands in flight will be called with the callback
 * and status RPC_STATUS_ERROR. Data will be the error string for the disconnection.
 */
int rpc_disconnect(struct rpc_context *rpc, const char *error);


/*
 * PORTMAP v2 FUNCTIONS
 */

/*
 * Call PORTMAPPER2/NULL
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap2_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);


/*
 * Call PORTMAPPER2/GETPORT.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is a (uint32_t *), containing the port returned.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap2_getport_async(struct rpc_context *rpc, int program, int version, int protocol, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER2/SET
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is a (uint32_t *), containing status
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap2_set_async(struct rpc_context *rpc, int program, int version, int protocol, int port, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER2/UNSET
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is a (uint32_t *), containing status
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap2_unset_async(struct rpc_context *rpc, int program, int version, int protocol, int port, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER2/DUMP.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is struct pmap2_dump_result.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap2_dump_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER2/CALLIT.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon
 *                      data is a 'pmap2_call_result' pointer.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap2_callit_async(struct rpc_context *rpc, int program, int version, int procedure, char *data, int datalen, rpc_cb cb, void *private_data);

/*
 * PORTMAP v3 FUNCTIONS
 */

/*
 * Call PORTMAPPER3/NULL
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap3_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER3/SET.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is uint32_t *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct pmap3_mapping;
EXTERN int rpc_pmap3_set_async(struct rpc_context *rpc, struct pmap3_mapping *map, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER3/UNSET.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is uint32_t *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap3_unset_async(struct rpc_context *rpc, struct pmap3_mapping *map, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER3/GETADDR.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is struct pmap3_string_result.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap3_getaddr_async(struct rpc_context *rpc, struct pmap3_mapping *map, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER3/DUMP.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is struct pmap3_dump_result.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap3_dump_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER3/CALLIT.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon
 *                      data is a 'pmap3_call_result' pointer.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap3_callit_async(struct rpc_context *rpc, int program, int version, int procedure, char *data, int datalen, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER3/GETTIME.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is a uint32_t *.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap3_gettime_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER3/UADDR2TADDR.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is a struct pmap3_netbuf *.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_pmap3_uaddr2taddr_async(struct rpc_context *rpc, char *uaddr, rpc_cb cb, void *private_data);

/*
 * Call PORTMAPPER3/TADDR2UADDR.
 * Function returns
 *  0 : The connection was initiated. Once the connection establish finishes, the callback will be invoked.
 * <0 : An error occured when trying to set up the connection. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the portmapper daemon.
 *                      data is a struct pmap3_string_result *.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the portmapper.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct pmap3_netbuf;
EXTERN int rpc_pmap3_taddr2uaddr_async(struct rpc_context *rpc, struct pmap3_netbuf *netbuf, rpc_cb cb, void *private_data);

/*
 * MOUNT v3 FUNCTIONS
 */
char *mountstat3_to_str(int stat);
int mountstat3_to_errno(int error);

/*
 * Call MOUNT3/NULL
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount3_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);
EXTERN int rpc_mount_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call MOUNT3/MNT
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data is union mountres3.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount3_mnt_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, void *private_data);
EXTERN int rpc_mount_mnt_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, void *private_data);

/*
 * Call MOUNT3/DUMP
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data is a mountlist.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount3_dump_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);
EXTERN int rpc_mount_dump_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call MOUNT3/UMNT
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount3_umnt_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, void *private_data);
EXTERN int rpc_mount_umnt_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, void *private_data);

/*
 * Call MOUNT3/UMNTALL
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount3_umntall_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);
EXTERN int rpc_mount_umntall_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call MOUNT3/EXPORT
 * NOTE: You must include 'libnfs-raw-mount.h' to get the definitions of the
 * returned structures.
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data is a pointer to an exports pointer:
 *                      exports export = *(exports *)data;
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount3_export_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);
EXTERN int rpc_mount_export_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * MOUNT v1 FUNCTIONS (Used with NFSv2)
 */
/*
 * Call MOUNT1/NULL
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount1_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call MOUNT1/MNT
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data is union mountres1.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount1_mnt_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, void *private_data);

/*
 * Call MOUNT1/DUMP
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data is a mountlist.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount1_dump_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call MOUNT1/UMNT
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount1_umnt_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, void *private_data);

/*
 * Call MOUNT1/UMNTALL
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount1_umntall_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call MOUNT1/EXPORT
 * NOTE: You must include 'libnfs-raw-mount.h' to get the definitions of the
 * returned structures.
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the mount daemon.
 *                      data is a pointer to an exports pointer:
 *                      exports export = *(exports *)data;
 * RPC_STATUS_ERROR   : An error occured when trying to contact the mount daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_mount1_export_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);


/*
 * NFS v3 FUNCTIONS
 */
struct nfs_fh3;
char *nfsstat3_to_str(int error);
int nfsstat3_to_errno(int error);

/*
 * Call NFS3/NULL
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_nfs3_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);
EXTERN int rpc_nfs_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call NFS3/GETATTR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is GETATTR3res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct GETATTR3args;
EXTERN int rpc_nfs3_getattr_async(struct rpc_context *rpc, rpc_cb cb, struct GETATTR3args *args, void *private_data);
EXTERN int rpc_nfs_getattr_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data);

/*
 * Call NFS3/PATHCONF
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is PATHCONF3res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct PATHCONF3args;
EXTERN int rpc_nfs3_pathconf_async(struct rpc_context *rpc, rpc_cb cb, struct PATHCONF3args *args, void *private_data);
EXTERN int rpc_nfs_pathconf_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data);

/*
 * Call NFS3/LOOKUP
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is LOOKUP3res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct LOOKUP3args;
EXTERN int rpc_nfs3_lookup_async(struct rpc_context *rpc, rpc_cb cb, struct LOOKUP3args *args, void *private_data);
EXTERN int rpc_nfs_lookup_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *name, void *private_data);

/*
 * Call NFS3/ACCESS
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is ACCESS3res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct ACCESS3args;
EXTERN int rpc_nfs3_access_async(struct rpc_context *rpc, rpc_cb cb, struct ACCESS3args *args, void *private_data);
EXTERN int rpc_nfs_access_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, int access, void *private_data);

/*
 * Call NFS3/READ
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is READ3res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct READ3args;
EXTERN int rpc_nfs3_read_async(struct rpc_context *rpc, rpc_cb cb, struct READ3args *args, void *private_data);
EXTERN int rpc_nfs_read_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, uint64_t offset, uint64_t count, void *private_data);

/*
 * Call NFS3/WRITE
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is WRITE3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct WRITE3args;
EXTERN int rpc_nfs3_write_async(struct rpc_context *rpc, rpc_cb cb, struct WRITE3args *args, void *private_data);
EXTERN int rpc_nfs_write_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *buf, uint64_t offset, uint64_t count, int stable_how, void *private_data);

/*
 * Call NFS3/COMMIT
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is COMMIT3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct COMMIT3args;
EXTERN int rpc_nfs3_commit_async(struct rpc_context *rpc, rpc_cb cb, struct COMMIT3args *args, void *private_data);
EXTERN int rpc_nfs_commit_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data);

/*
 * Call NFS3/SETATTR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is SETATTR3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct SETATTR3args;
EXTERN int rpc_nfs3_setattr_async(struct rpc_context *rpc, rpc_cb cb, struct SETATTR3args *args, void *private_data);
EXTERN int rpc_nfs_setattr_async(struct rpc_context *rpc, rpc_cb cb, struct SETATTR3args *args, void *private_data);

/*
 * Call NFS3/MKDIR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is MKDIR3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct MKDIR3args;
EXTERN int rpc_nfs3_mkdir_async(struct rpc_context *rpc, rpc_cb cb, struct MKDIR3args *args, void *private_data);
EXTERN int rpc_nfs_mkdir_async(struct rpc_context *rpc, rpc_cb cb, struct MKDIR3args *args, void *private_data);

/*
 * Call NFS3/RMDIR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is RMDIR3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct RMDIR3args;
EXTERN int rpc_nfs3_rmdir_async(struct rpc_context *rpc, rpc_cb cb, struct RMDIR3args *args, void *private_data);
EXTERN int rpc_nfs_rmdir_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *dir, void *private_data);

/*
 * Call NFS3/CREATE
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is CREATE3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct CREATE3args;
EXTERN int rpc_nfs3_create_async(struct rpc_context *rpc, rpc_cb cb, struct CREATE3args *args, void *private_data);
EXTERN int rpc_nfs_create_async(struct rpc_context *rpc, rpc_cb cb, struct CREATE3args *args, void *private_data);

/*
 * Call NFS3/MKNOD
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is MKNOD3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct MKNOD3args;
EXTERN int rpc_nfs3_mknod_async(struct rpc_context *rpc, rpc_cb cb, struct MKNOD3args *args, void *private_data);
EXTERN int rpc_nfs_mknod_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *file, int mode, int major, int minor, void *private_data);

/*
 * Call NFS3/REMOVE
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is REMOVE3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct REMOVE3args;
EXTERN int rpc_nfs3_remove_async(struct rpc_context *rpc, rpc_cb cb, struct REMOVE3args *args, void *private_data);
EXTERN int rpc_nfs_remove_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, char *name, void *private_data);

/*
 * Call NFS3/READDIR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is READDIR3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct READDIR3args;
EXTERN int rpc_nfs3_readdir_async(struct rpc_context *rpc, rpc_cb cb, struct READDIR3args *args, void *private_data);
EXTERN int rpc_nfs_readdir_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, uint64_t cookie, char *cookieverf, int count, void *private_data);

/*
 * Call NFS3/READDIRPLUS
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is READDIRPLUS3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct READDIRPLUS3args;
EXTERN int rpc_nfs3_readdirplus_async(struct rpc_context *rpc, rpc_cb cb, struct READDIRPLUS3args *args, void *private_data);
EXTERN int rpc_nfs_readdirplus_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, uint64_t cookie, char *cookieverf, int count, void *private_data);

/*
 * Call NFS3/FSSTAT
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is FSSTAT3res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct FSSTAT3args;
EXTERN int rpc_nfs3_fsstat_async(struct rpc_context *rpc, rpc_cb cb, struct FSSTAT3args *args, void *private_data);
EXTERN int rpc_nfs_fsstat_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data);

/*
 * Call NFS3/FSINFO
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is FSINFO3res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct FSINFO3args;
EXTERN int rpc_nfs3_fsinfo_async(struct rpc_context *rpc, rpc_cb cb, struct FSINFO3args *args, void *private_data);
EXTERN int rpc_nfs_fsinfo_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *fh, void *private_data);

/*
 * Call NFS3/READLINK
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is READLINK3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct READLINK3args;
EXTERN int rpc_nfs3_readlink_async(struct rpc_context *rpc, rpc_cb cb, struct READLINK3args *args, void *private_data);
EXTERN int rpc_nfs_readlink_async(struct rpc_context *rpc, rpc_cb cb, struct READLINK3args *args, void *private_data);

/*
 * Call NFS3/SYMLINK
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is SYMLINK3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct SYMLINK3args;
EXTERN int rpc_nfs3_symlink_async(struct rpc_context *rpc, rpc_cb cb, struct SYMLINK3args *args, void *private_data);
EXTERN int rpc_nfs_symlink_async(struct rpc_context *rpc, rpc_cb cb, struct SYMLINK3args *args, void *private_data);

/*
 * Call NFS3/RENAME
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is RENAME3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct RENAME3args;
EXTERN int rpc_nfs3_rename_async(struct rpc_context *rpc, rpc_cb cb, struct RENAME3args *args, void *private_data);
EXTERN int rpc_nfs_rename_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *olddir, char *oldname, struct nfs_fh3 *newdir, char *newname, void *private_data);

/*
 * Call NFS3/LINK
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is LINK3res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct LINK3args;
EXTERN int rpc_nfs3_link_async(struct rpc_context *rpc, rpc_cb cb, struct LINK3args *args, void *private_data);
EXTERN int rpc_nfs_link_async(struct rpc_context *rpc, rpc_cb cb, struct nfs_fh3 *file, struct nfs_fh3 *newdir, char *newname, void *private_data);

/*
 * NFS v2 FUNCTIONS
 */

/*
 * Call NFS2/NULL
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_nfs2_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call NFS2/GETATTR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is GETATTR2res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct GETATTR2args;
EXTERN int rpc_nfs2_getattr_async(struct rpc_context *rpc, rpc_cb cb, struct GETATTR2args *args, void *private_data);

/*
 * Call NFS2/SETATTR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is SETATTR2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct SETATTR2args;
EXTERN int rpc_nfs2_setattr_async(struct rpc_context *rpc, rpc_cb cb, struct SETATTR2args *args, void *private_data);

/*
 * Call NFS2/LOOKUP
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is LOOKUP2res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct LOOKUP2args;
EXTERN int rpc_nfs2_lookup_async(struct rpc_context *rpc, rpc_cb cb, struct LOOKUP2args *args, void *private_data);

/*
 * Call NFS2/READLINK
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is READLINK2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct READLINK2args;
EXTERN int rpc_nfs32_readlink_async(struct rpc_context *rpc, rpc_cb cb, struct READLINK2args *args, void *private_data);

/*
 * Call NFS2/READ
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is READ2res
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct READ2args;
EXTERN int rpc_nfs2_read_async(struct rpc_context *rpc, rpc_cb cb, struct READ2args *args, void *private_data);

/*
 * Call NFS2/WRITE
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is WRITE2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct WRITE2args;
EXTERN int rpc_nfs2_write_async(struct rpc_context *rpc, rpc_cb cb, struct WRITE2args *args, void *private_data);

/*
 * Call NFS2/CREATE
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is CREATE2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct CREATE2args;
EXTERN int rpc_nfs2_create_async(struct rpc_context *rpc, rpc_cb cb, struct CREATE2args *args, void *private_data);

/*
 * Call NFS2/REMOVE
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is REMOVE2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct REMOVE2args;
EXTERN int rpc_nfs2_remove_async(struct rpc_context *rpc, rpc_cb cb, struct REMOVE2args *args, void *private_data);

/*
 * Call NFS2/RENAME
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is RENAME2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct RENAME2args;
EXTERN int rpc_nfs2_rename_async(struct rpc_context *rpc, rpc_cb cb, struct RENAME2args *args, void *private_data);

/*
 * Call NFS2/LINK
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is LINK2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct LINK2args;
EXTERN int rpc_nfs2_link_async(struct rpc_context *rpc, rpc_cb cb, struct LINK2args *args, void *private_data);

/*
 * Call NFS2/SYMLINK
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is SYMLINK2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct SYMLINK2args;
EXTERN int rpc_nfs2_symlink_async(struct rpc_context *rpc, rpc_cb cb, struct SYMLINK2args *args, void *private_data);

/*
 * Call NFS2/MKDIR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is MKDIR2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct MKDIR2args;
EXTERN int rpc_nfs2_mkdir_async(struct rpc_context *rpc, rpc_cb cb, struct MKDIR2args *args, void *private_data);

/*
 * Call NFS2/RMDIR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is RMDIR2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct RMDIR2args;
EXTERN int rpc_nfs2_rmdir_async(struct rpc_context *rpc, rpc_cb cb, struct RMDIR2args *args, void *private_data);

/*
 * Call NFS2/READDIR
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is READDIR2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct READDIR2args;
EXTERN int rpc_nfs2_readdir_async(struct rpc_context *rpc, rpc_cb cb, struct READDIR2args *args, void *private_data);

/*
 * Call NFS2/STATFS
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is STATFS2res *
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct STATFS2args;
EXTERN int rpc_nfs2_statfs_async(struct rpc_context *rpc, rpc_cb cb, struct STATFS2args *args, void *private_data);

/*
 * RQUOTA FUNCTIONS
 */
char *rquotastat_to_str(int error);
int rquotastat_to_errno(int error);

/*
 * Call RQUOTA1/NULL
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the rquota daemon.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the rquota daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_rquota1_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call RQUOTA1/GETQUOTA
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the rquota daemon.
 *                      data is a RQUOTA1res structure.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the rquota daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_rquota1_getquota_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, int uid, void *private_data);

/*
 * Call RQUOTA1/GETACTIVEQUOTA
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the rquota daemon.
 *                      data is a RQUOTA1res structure.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the rquota daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_rquota1_getactivequota_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, int uid, void *private_data);




/*
 * Call RQUOTA2/NULL
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the rquota daemon.
 *                      data is NULL.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the rquota daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
int rpc_rquota2_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call RQUOTA2/GETQUOTA
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the rquota daemon.
 *                      data is a RQUOTA1res structure.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the rquota daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
int rpc_rquota2_getquota_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, int type, int uid, void *private_data);

/*
 * Call RQUOTA2/GETACTIVEQUOTA
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the rquota daemon.
 *                      data is a RQUOTA1res structure.
 * RPC_STATUS_ERROR   : An error occured when trying to contact the rquota daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
int rpc_rquota2_getactivequota_async(struct rpc_context *rpc, rpc_cb cb, char *exportname, int type, int uid, void *private_data);






/*
 * NFSACL functions
 */

/*
 * Call NFSACL/NULL
 * Call the NULL procedure for the NFSACL
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the rquota daemon.
 *                      data is NULL
 * RPC_STATUS_ERROR   : An error occured when trying to contact the rquota daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_nfsacl_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call NFSACL/GETACL
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is a GETACL3res pointer
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct GETACL3args;
EXTERN int rpc_nfsacl_getacl_async(struct rpc_context *rpc, rpc_cb cb, struct GETACL3args *args, void *private_data);



/*
 * Call NFSACL/SETACL
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nfs daemon.
 *                      data is a SETACL3res pointer
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nfs daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct SETACL3args;
EXTERN int rpc_nfsacl_setacl_async(struct rpc_context *rpc, rpc_cb cb, struct SETACL3args *args, void *private_data);




/*
 * NLM functions
 */
char *nlmstat4_to_str(int stat);

/*
 * Call NLM/NULL
 * Call the NULL procedure for the NLM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nlm daemon.
 *                      data is NULL
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nlm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_nlm4_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call NLM/TEST
 * Call the TEST procedure for the NLM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nlm daemon.
 *                      data is NLM4_TESTres
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nlm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NLM4_TESTargs;
EXTERN int rpc_nlm4_test_async(struct rpc_context *rpc, rpc_cb cb, struct NLM4_TESTargs *args, void *private_data);

/*
 * Call NLM/LOCK
 * Call the LOCK procedure for the NLM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nlm daemon.
 *                      data is NLM4_LOCKres
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nlm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NLM4_LOCKargs;
EXTERN int rpc_nlm4_lock_async(struct rpc_context *rpc, rpc_cb cb, struct NLM4_LOCKargs *args, void *private_data);

/*
 * Call NLM/CANCEL
 * Call the CANCEL procedure for the NLM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nlm daemon.
 *                      data is NLM4_CANCres
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nlm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NLM4_CANCargs;
EXTERN int rpc_nlm4_cancel_async(struct rpc_context *rpc, rpc_cb cb, struct NLM4_CANCargs *args, void *private_data);

/*
 * Call NLM/UNLOCK
 * Call the UNLOCK procedure for the NLM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nlm daemon.
 *                      data is NLM4_UNLOCKres
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nlm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NLM4_UNLOCKargs;
EXTERN int rpc_nlm4_unlock_async(struct rpc_context *rpc, rpc_cb cb, struct NLM4_UNLOCKargs *args, void *private_data);

/*
 * NSM functions
 */
char *nsmstat1_to_str(int stat);

/*
 * Call NSM/NULL
 * Call the NULL procedure for the NSM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nsm daemon.
 *                      data is NULL
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nsm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_nsm1_null_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call NSM/STAT
 * Call the STAT procedure for the NSM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nsm daemon.
 *                      data is NSM1_STATres
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nsm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NSM1_STATargs;
EXTERN int rpc_nsm1_stat_async(struct rpc_context *rpc, rpc_cb cb, struct NSM1_STATargs *args, void *private_data);

/*
 * Call NSM/MON
 * Call the MON procedure for the NSM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nsm daemon.
 *                      data is NSM1_MONres
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nsm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NSM1_MONargs;
EXTERN int rpc_nsm1_mon_async(struct rpc_context *rpc, rpc_cb cb, struct NSM1_MONargs *args, void *private_data);

/*
 * Call NSM/UNMON
 * Call the UNMON procedure for the NSM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nsm daemon.
 *                      data is NSM1_UNMONres
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nsm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NSM1_UNMONargs;
EXTERN int rpc_nsm1_unmon_async(struct rpc_context *rpc, rpc_cb cb, struct NSM1_UNMONargs *args, void *private_data);

/*
 * Call NSM/UNMONALL
 * Call the UNMONALL procedure for the NSM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nsm daemon.
 *                      data is NSM1_UNMONALLres
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nsm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NSM1_UNMONALLargs;
EXTERN int rpc_nsm1_unmonall_async(struct rpc_context *rpc, rpc_cb cb, struct NSM1_UNMONALLargs *args, void *private_data);

/*
 * Call NSM/SIMUCRASH
 * Call the SIMUCRASH procedure for the NSM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nsm daemon.
 *                      data is NULL
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nsm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
EXTERN int rpc_nsm1_simucrash_async(struct rpc_context *rpc, rpc_cb cb, void *private_data);

/*
 * Call NSM/NOTIFY
 * Call the NOTIFY procedure for the NSM protocol
 *
 * Function returns
 *  0 : The call was initiated. The callback will be invoked when the call completes.
 * <0 : An error occured when trying to set up the call. The callback will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 * RPC_STATUS_SUCCESS : We got a successful response from the nsm daemon.
 *                      data is NULL
 * RPC_STATUS_ERROR   : An error occured when trying to contact the nsm daemon.
 *                      data is the error string.
 * RPC_STATUS_CANCEL : The connection attempt was aborted before it could complete.
 *                     data is NULL.
 */
struct NSM1_NOTIFYargs;
EXTERN int rpc_nsm1_notify_async(struct rpc_context *rpc, rpc_cb cb, struct NSM1_NOTIFYargs *args, void *private_data);

#ifdef __cplusplus
}
#endif

#endif
