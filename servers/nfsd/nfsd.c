/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
  Copyright 2025 Ronnie Sahlberg

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the “Software”),
  to deal in the Software without restriction, including without
  limitation the rights to use, copy, modify, merge, publish, distribute,
  sublicense, and/or sell copies of the Software, and to permit persons
  to whom the Software is furnished to do so, subject to the following
  conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE


#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <talloc.h>
#include <tevent.h>
#include <time.h>
#include <unistd.h>

#include "mountd.h"

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-raw-nlm.h"
#include "../libnfs-server.h"

struct nfsd_state {
        struct tevent_context *tevent;
        struct rpc_context *rpc;
};

static int nfs3_null_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
}

static int nlm4_null_proc(struct rpc_context *rpc, struct rpc_msg *call, void *opaque)
{
        return rpc_send_reply(rpc, call, NULL, (zdrproc_t)zdr_void, 0);
}

static int nfsd_destructor(struct nfsd_state *nfsd)
{
        if (nfsd->rpc) {
                rpc_destroy_context(nfsd->rpc);
        }
        return 0;
}

int main(int argc, char *argv[])
{
        TALLOC_CTX *ctx = talloc_new(NULL);
        struct nfsd_state *nfsd = talloc(NULL, struct nfsd_state);
        struct mountd_state *mountd;
        struct libnfs_servers *servers;
        int rc = 1;

        struct service_proc nfs3_pt[] = {
                {NFS3_NULL, nfs3_null_proc,
                 (zdrproc_t)zdr_void, 0, nfsd},
#if 0
                {NFS3_GETATTR, nfs3_getattr_proc,
                 (zdrproc_t)zdr_NFS3_GETATTRargs, sizeof(NFS3_GETATTRargs), nfsd},
                {NFS3_SETATTR, nfs3_setattr_proc,
                 (zdrproc_t)zdr_NFS3_SETATTRargs, sizeof(NFS3_SETATTRargs), nfsd},
                {NFS3_LOOKUP, nfs3_lookup_proc,
                 (zdrproc_t)zdr_NFS3_LOOKUPargs, sizeof(NFS3_LOOKUPargs), nfsd},
                {NFS3_ACCESS, nfs3_access_proc,
                 (zdrproc_t)zdr_NFS3_ACCESSargs, sizeof(NFS3_ACCESSargs), nfsd},
                {NFS3_READLINK, nfs3_readlink_proc,
                 (zdrproc_t)zdr_NFS3_READLINKargs, sizeof(NFS3_READLINKargs), nfsd},
                {NFS3_READ, nfs3_read_proc,
                 (zdrproc_t)zdr_NFS3_READargs, sizeof(NFS3_READargs), nfsd},
                {NFS3_WRITE, nfs3_write_proc,
                 (zdrproc_t)zdr_NFS3_WRITEargs, sizeof(NFS3_WRITEargs), nfsd},
                {NFS3_CREATE, nfs3_create_proc,
                 (zdrproc_t)zdr_NFS3_CREATEargs, sizeof(NFS3_CREATEargs), nfsd},
                {NFS3_MKDIR, nfs3_mkdir_proc,
                 (zdrproc_t)zdr_NFS3_MKDIRargs, sizeof(NFS3_MKDIRargs), nfsd},
                {NFS3_SYMLINK, nfs3_symlink_proc,
                 (zdrproc_t)zdr_NFS3_SYMLINKargs, sizeof(NFS3_SYMLINKargs), nfsd},
                {NFS3_MKNOD, nfs3_mknod_proc,
                 (zdrproc_t)zdr_NFS3_MKNODargs, sizeof(NFS3_MKNODargs), nfsd},
                {NFS3_REMOVE, nfs3_remove_proc,
                 (zdrproc_t)zdr_NFS3_REMOVEargs, sizeof(NFS3_REMOVEargs), nfsd},
                {NFS3_RMDIR, nfs3_rmdir_proc,
                 (zdrproc_t)zdr_NFS3_RMDIRargs, sizeof(NFS3_RMDIRargs), nfsd},
                {NFS3_RENAME, nfs3_rename_proc,
                 (zdrproc_t)zdr_NFS3_RENAMEargs, sizeof(NFS3_RENAMEargs), nfsd},
                {NFS3_LINK, nfs3_link_proc,
                 (zdrproc_t)zdr_NFS3_LINKargs, sizeof(NFS3_LINKargs), nfsd},
                {NFS3_READDIR, nfs3_readdir_proc,
                 (zdrproc_t)zdr_NFS3_READDIRargs, sizeof(NFS3_READDIRargs), nfsd},
                {NFS3_READDIRPLUS, nfs3_readdirplus_proc,
                 (zdrproc_t)zdr_NFS3_READDIRPLUSargs, sizeof(NFS3_READDIRPLUSargs), nfsd},
                {NFS3_FSSTAT, nfs3_fsstat_proc,
                 (zdrproc_t)zdr_NFS3_FSSTATargs, sizeof(NFS3_FSSTATargs), nfsd},
                {NFS3_FSINFO, nfs3_fsinfo_proc,
                 (zdrproc_t)zdr_NFS3_FSINFOargs, sizeof(NFS3_FSINFOargs), nfsd},
                {NFS3_PATHCONF, nfs3_pathconf_proc,
                 (zdrproc_t)zdr_NFS3_PATHCONFargs, sizeof(NFS3_PATHCONFargs), nfsd},
                {NFS3_COMMIT, nfs3_commit_proc,
                 (zdrproc_t)zdr_NFS3_COMMITargs, sizeof(NFS3_COMMITargs), nfsd},
#endif
        };
        struct service_proc nlm4_pt[] = {
                {NLM4_NULL, nlm4_null_proc,
                 (zdrproc_t)zdr_void, 0, nfsd},
#if 0
                {NLM4_TEST, nlm4_test_proc,
                 (zdrproc_t)zdr_NLM4_TESTargs, sizeof(NLM4_TESTargs), nfsd},
                {NLM4_LOCK, nlm4_lock_proc,
                 (zdrproc_t)zdr_NLM4_LOCKargs, sizeof(NLM4_LOCKargs), nfsd},
                {NLM4_UNLOCK, nlm4_unlock_proc,
                 (zdrproc_t)zdr_NLM4_UNLOCKargs, sizeof(NLM4_UNLOCKargs), nfsd},
                /* _GRANTED is sent from a server back to the client when a pending
                 * lock has been fulfilled. No need to implement this in a server.
                 */
                {NLM4_GRANTED, nlm4_granted_proc,
                 (zdrproc_t)zdr_NLM4_GRANTEDargs, sizeof(NLM4_GRANTEDargs), nfsd},
                /* The other functions are all fo special clients, like _MSG/_RES are
                 * async versions of the protocol, used for example by HP-UX ...
                 * So we don't need to care about them for now.
                 */
#endif
        };
        struct libnfs_server_procs server_procs[] = {
                { NLM_PROGRAM, NLM_V4, nlm4_pt, sizeof(nlm4_pt) / sizeof(nlm4_pt[0]) },
                { NFS_PROGRAM, NFS_V3, nfs3_pt, sizeof(nfs3_pt) / sizeof(nfs3_pt[0]) },
                { 0, 0, 0, 0}
        };
        
        if (nfsd == NULL) {
                printf("Failed to talloc nfsd\n");
                goto out;
        }
        nfsd->rpc = NULL;
        nfsd->tevent = tevent_context_init(nfsd);
        if (nfsd->tevent == NULL) {
                printf("Failed create tevent context\n");
                goto out;
        }
        talloc_set_destructor(nfsd, nfsd_destructor);

        servers = libnfs_create_server(nfsd, nfsd->tevent, 2049, "libnfs nfsd",
                                       TRANSPORT_UDP | TRANSPORT_UDP6 |
                                       TRANSPORT_TCP | TRANSPORT_TCP6,
                                       &server_procs[0]);
        if (servers == NULL) {
                printf("Failed to set set up server\n");
                goto out;
        }

        mountd = mountd_init(ctx, nfsd->tevent);
        if (mountd == NULL) {
                printf("Failed to set set up mountd\n");
                goto out;
        }
        /* Add a dummy export */
        char data_handle[8] = {0,1,2,3,4,5,6,7};
        mountd_add_export(mountd, "/data", sizeof(data_handle), &data_handle[0]); 

        
        printf("Ready to serve\n");
        //qqq daemon(0, 1);

        /*
         * Everything is now set up. Start the event loop.
         */
        tevent_loop_wait(nfsd->tevent);

        rc = 0;
 out:
        talloc_free(nfsd);
        talloc_free(ctx);
        return rc;
}
