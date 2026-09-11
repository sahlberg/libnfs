// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Fuzzes libnfs decoding of RPC replies from an NFS server. The first
// input byte selects one of the generated ZDR reply decoders (NFS v2/v3,
// mount v1/v3, NLM v4, portmap v2/v3, rquota, NFSv4.x compound); the
// remaining bytes are the decoded reply payload, mirroring how
// rpc_process_pdu hands server data to the per procedure decoder.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libnfs-zdr.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include "libnfs-raw-nfs4.h"
#include "libnfs-raw-nlm.h"
#include "libnfs-raw-portmap.h"
#include "libnfs-raw-rquota.h"

struct decoder_entry {
	zdrproc_t fn;
	size_t size;
};

static const struct decoder_entry decoders[] = {
	{ (zdrproc_t)zdr_WRITE3res, sizeof(WRITE3res) },
	{ (zdrproc_t)zdr_LOOKUP3res, sizeof(LOOKUP3res) },
	{ (zdrproc_t)zdr_COMMIT3res, sizeof(COMMIT3res) },
	{ (zdrproc_t)zdr_ACCESS3res, sizeof(ACCESS3res) },
	{ (zdrproc_t)zdr_GETATTR3res, sizeof(GETATTR3res) },
	{ (zdrproc_t)zdr_CREATE3res, sizeof(CREATE3res) },
	{ (zdrproc_t)zdr_REMOVE3res, sizeof(REMOVE3res) },
	{ (zdrproc_t)zdr_READ3res, sizeof(READ3res) },
	{ (zdrproc_t)zdr_FSINFO3res, sizeof(FSINFO3res) },
	{ (zdrproc_t)zdr_FSSTAT3res, sizeof(FSSTAT3res) },
	{ (zdrproc_t)zdr_PATHCONF3res, sizeof(PATHCONF3res) },
	{ (zdrproc_t)zdr_SYMLINK3res, sizeof(SYMLINK3res) },
	{ (zdrproc_t)zdr_READLINK3res, sizeof(READLINK3res) },
	{ (zdrproc_t)zdr_MKNOD3res, sizeof(MKNOD3res) },
	{ (zdrproc_t)zdr_MKDIR3res, sizeof(MKDIR3res) },
	{ (zdrproc_t)zdr_RMDIR3res, sizeof(RMDIR3res) },
	{ (zdrproc_t)zdr_RENAME3res, sizeof(RENAME3res) },
	{ (zdrproc_t)zdr_READDIRPLUS3res, sizeof(READDIRPLUS3res) },
	{ (zdrproc_t)zdr_READDIR3res, sizeof(READDIR3res) },
	{ (zdrproc_t)zdr_LINK3res, sizeof(LINK3res) },
	{ (zdrproc_t)zdr_SETATTR3res, sizeof(SETATTR3res) },
	{ (zdrproc_t)zdr_GETATTR2res, sizeof(GETATTR2res) },
	{ (zdrproc_t)zdr_SETATTR2res, sizeof(SETATTR2res) },
	{ (zdrproc_t)zdr_LOOKUP2res, sizeof(LOOKUP2res) },
	{ (zdrproc_t)zdr_READLINK2res, sizeof(READLINK2res) },
	{ (zdrproc_t)zdr_READ2res, sizeof(READ2res) },
	{ (zdrproc_t)zdr_WRITE2res, sizeof(WRITE2res) },
	{ (zdrproc_t)zdr_CREATE2res, sizeof(CREATE2res) },
	{ (zdrproc_t)zdr_REMOVE2res, sizeof(REMOVE2res) },
	{ (zdrproc_t)zdr_RENAME2res, sizeof(RENAME2res) },
	{ (zdrproc_t)zdr_LINK2res, sizeof(LINK2res) },
	{ (zdrproc_t)zdr_SYMLINK2res, sizeof(SYMLINK2res) },
	{ (zdrproc_t)zdr_MKDIR2res, sizeof(MKDIR2res) },
	{ (zdrproc_t)zdr_RMDIR2res, sizeof(RMDIR2res) },
	{ (zdrproc_t)zdr_READDIR2res, sizeof(READDIR2res) },
	{ (zdrproc_t)zdr_STATFS2res, sizeof(STATFS2res) },
	{ (zdrproc_t)zdr_GETACL3res, sizeof(GETACL3res) },
	{ (zdrproc_t)zdr_SETACL3res, sizeof(SETACL3res) },
	{ (zdrproc_t)zdr_mountres3_ok, sizeof(mountres3_ok) },
	{ (zdrproc_t)zdr_mountres3, sizeof(mountres3) },
	{ (zdrproc_t)zdr_mountres1_ok, sizeof(mountres1_ok) },
	{ (zdrproc_t)zdr_mountres1, sizeof(mountres1) },
	{ (zdrproc_t)zdr_MOUNT1MNTres, sizeof(MOUNT1MNTres) },
	{ (zdrproc_t)zdr_MOUNT1DUMPres, sizeof(MOUNT1DUMPres) },
	{ (zdrproc_t)zdr_MOUNT1DUMPres_ptr, sizeof(MOUNT1DUMPres_ptr) },
	{ (zdrproc_t)zdr_MOUNT1EXPORTres, sizeof(MOUNT1EXPORTres) },
	{ (zdrproc_t)zdr_MOUNT1EXPORTres_ptr, sizeof(MOUNT1EXPORTres_ptr) },
	{ (zdrproc_t)zdr_MOUNT3MNTres, sizeof(MOUNT3MNTres) },
	{ (zdrproc_t)zdr_MOUNT3DUMPres, sizeof(MOUNT3DUMPres) },
	{ (zdrproc_t)zdr_MOUNT3DUMPres_ptr, sizeof(MOUNT3DUMPres_ptr) },
	{ (zdrproc_t)zdr_MOUNT3EXPORTres, sizeof(MOUNT3EXPORTres) },
	{ (zdrproc_t)zdr_MOUNT3EXPORTres_ptr, sizeof(MOUNT3EXPORTres_ptr) },
	{ (zdrproc_t)zdr_nlm4_testres_denied, sizeof(nlm4_testres_denied) },
	{ (zdrproc_t)zdr_NLM4_TESTres, sizeof(NLM4_TESTres) },
	{ (zdrproc_t)zdr_NLM4_CANCres, sizeof(NLM4_CANCres) },
	{ (zdrproc_t)zdr_NLM4_UNLOCKres, sizeof(NLM4_UNLOCKres) },
	{ (zdrproc_t)zdr_NLM4_LOCKres, sizeof(NLM4_LOCKres) },
	{ (zdrproc_t)zdr_NLM4_GRANTEDres, sizeof(NLM4_GRANTEDres) },
	{ (zdrproc_t)zdr_NLM4_SHAREres, sizeof(NLM4_SHAREres) },
	{ (zdrproc_t)zdr_NLM4_UNSHAREres, sizeof(NLM4_UNSHAREres) },
	{ (zdrproc_t)zdr_GETQUOTA1res_ok, sizeof(GETQUOTA1res_ok) },
	{ (zdrproc_t)zdr_GETQUOTA1res, sizeof(GETQUOTA1res) },
	{ (zdrproc_t)zdr_pmap2_call_result, sizeof(pmap2_call_result) },
	{ (zdrproc_t)zdr_pmap2_dump_result, sizeof(pmap2_dump_result) },
	{ (zdrproc_t)zdr_pmap3_string_result, sizeof(pmap3_string_result) },
	{ (zdrproc_t)zdr_pmap3_dump_result, sizeof(pmap3_dump_result) },
	{ (zdrproc_t)zdr_rpcb_rmtcallres, sizeof(rpcb_rmtcallres) },
	{ (zdrproc_t)zdr_pmap4_string_result, sizeof(pmap4_string_result) },
	{ (zdrproc_t)zdr_pmap4_dump_result, sizeof(pmap4_dump_result) },
	{ (zdrproc_t)zdr_PMAP2CALLITres, sizeof(PMAP2CALLITres) },
	{ (zdrproc_t)zdr_PMAP2DUMPres, sizeof(PMAP2DUMPres) },
	{ (zdrproc_t)zdr_PMAP3GETADDRres, sizeof(PMAP3GETADDRres) },
	{ (zdrproc_t)zdr_PMAP3DUMPres, sizeof(PMAP3DUMPres) },
	{ (zdrproc_t)zdr_PMAP3CALLITres, sizeof(PMAP3CALLITres) },
	{ (zdrproc_t)zdr_PMAP3UADDR2TADDRres, sizeof(PMAP3UADDR2TADDRres) },
	{ (zdrproc_t)zdr_PMAP3TADDR2UADDRres, sizeof(PMAP3TADDR2UADDRres) },
	{ (zdrproc_t)zdr_PMAP4GETADDRres, sizeof(PMAP4GETADDRres) },
	{ (zdrproc_t)zdr_PMAP4DUMPres, sizeof(PMAP4DUMPres) },
	{ (zdrproc_t)zdr_PMAP4BCASTres, sizeof(PMAP4BCASTres) },
	{ (zdrproc_t)zdr_PMAP4UADDR2TADDRres, sizeof(PMAP4UADDR2TADDRres) },
	{ (zdrproc_t)zdr_PMAP4TADDR2UADDRres, sizeof(PMAP4TADDR2UADDRres) },
	{ (zdrproc_t)zdr_PMAP4GETVERSADDRres, sizeof(PMAP4GETVERSADDRres) },
	{ (zdrproc_t)zdr_PMAP4INDIRECTres, sizeof(PMAP4INDIRECTres) },
	{ (zdrproc_t)zdr_PMAP4GETADDRLISTres, sizeof(PMAP4GETADDRLISTres) },
	{ (zdrproc_t)zdr_fattr4_case_preserving, sizeof(fattr4_case_preserving) },
	{ (zdrproc_t)zdr_fattr4_chown_restricted, sizeof(fattr4_chown_restricted) },
	{ (zdrproc_t)zdr_ACCESS4res, sizeof(ACCESS4res) },
	{ (zdrproc_t)zdr_CLOSE4res, sizeof(CLOSE4res) },
	{ (zdrproc_t)zdr_COMMIT4res, sizeof(COMMIT4res) },
	{ (zdrproc_t)zdr_CREATE4res, sizeof(CREATE4res) },
	{ (zdrproc_t)zdr_DELEGPURGE4res, sizeof(DELEGPURGE4res) },
	{ (zdrproc_t)zdr_DELEGRETURN4res, sizeof(DELEGRETURN4res) },
	{ (zdrproc_t)zdr_GETATTR4res, sizeof(GETATTR4res) },
	{ (zdrproc_t)zdr_GETFH4res, sizeof(GETFH4res) },
	{ (zdrproc_t)zdr_LINK4res, sizeof(LINK4res) },
	{ (zdrproc_t)zdr_LOCK4res, sizeof(LOCK4res) },
	{ (zdrproc_t)zdr_LOCKT4res, sizeof(LOCKT4res) },
	{ (zdrproc_t)zdr_LOCKU4res, sizeof(LOCKU4res) },
	{ (zdrproc_t)zdr_LOOKUP4res, sizeof(LOOKUP4res) },
	{ (zdrproc_t)zdr_LOOKUPP4res, sizeof(LOOKUPP4res) },
	{ (zdrproc_t)zdr_NVERIFY4res, sizeof(NVERIFY4res) },
	{ (zdrproc_t)zdr_OPEN4res, sizeof(OPEN4res) },
	{ (zdrproc_t)zdr_OPENATTR4res, sizeof(OPENATTR4res) },
	{ (zdrproc_t)zdr_OPEN_CONFIRM4res, sizeof(OPEN_CONFIRM4res) },
	{ (zdrproc_t)zdr_OPEN_DOWNGRADE4res, sizeof(OPEN_DOWNGRADE4res) },
	{ (zdrproc_t)zdr_PUTFH4res, sizeof(PUTFH4res) },
	{ (zdrproc_t)zdr_PUTPUBFH4res, sizeof(PUTPUBFH4res) },
	{ (zdrproc_t)zdr_PUTROOTFH4res, sizeof(PUTROOTFH4res) },
	{ (zdrproc_t)zdr_READ4res, sizeof(READ4res) },
	{ (zdrproc_t)zdr_READDIR4res, sizeof(READDIR4res) },
	{ (zdrproc_t)zdr_READLINK4res, sizeof(READLINK4res) },
	{ (zdrproc_t)zdr_REMOVE4res, sizeof(REMOVE4res) },
	{ (zdrproc_t)zdr_RENAME4res, sizeof(RENAME4res) },
	{ (zdrproc_t)zdr_RENEW4res, sizeof(RENEW4res) },
	{ (zdrproc_t)zdr_RESTOREFH4res, sizeof(RESTOREFH4res) },
	{ (zdrproc_t)zdr_SAVEFH4res, sizeof(SAVEFH4res) },
	{ (zdrproc_t)zdr_SECINFO4res, sizeof(SECINFO4res) },
	{ (zdrproc_t)zdr_SETATTR4res, sizeof(SETATTR4res) },
	{ (zdrproc_t)zdr_SETCLIENTID4res, sizeof(SETCLIENTID4res) },
	{ (zdrproc_t)zdr_SETCLIENTID_CONFIRM4res, sizeof(SETCLIENTID_CONFIRM4res) },
	{ (zdrproc_t)zdr_VERIFY4res, sizeof(VERIFY4res) },
	{ (zdrproc_t)zdr_WRITE4res, sizeof(WRITE4res) },
	{ (zdrproc_t)zdr_RELEASE_LOCKOWNER4res, sizeof(RELEASE_LOCKOWNER4res) },
	{ (zdrproc_t)zdr_BIND_CONN_TO_SESSION4res, sizeof(BIND_CONN_TO_SESSION4res) },
	{ (zdrproc_t)zdr_EXCHANGE_ID4res, sizeof(EXCHANGE_ID4res) },
	{ (zdrproc_t)zdr_CREATE_SESSION4res, sizeof(CREATE_SESSION4res) },
	{ (zdrproc_t)zdr_DESTROY_SESSION4res, sizeof(DESTROY_SESSION4res) },
	{ (zdrproc_t)zdr_FREE_STATEID4res, sizeof(FREE_STATEID4res) },
	{ (zdrproc_t)zdr_GET_DIR_DELEGATION4res_non_fatal, sizeof(GET_DIR_DELEGATION4res_non_fatal) },
	{ (zdrproc_t)zdr_GET_DIR_DELEGATION4res, sizeof(GET_DIR_DELEGATION4res) },
	{ (zdrproc_t)zdr_GETDEVICEINFO4res, sizeof(GETDEVICEINFO4res) },
	{ (zdrproc_t)zdr_GETDEVICELIST4res, sizeof(GETDEVICELIST4res) },
	{ (zdrproc_t)zdr_LAYOUTCOMMIT4res, sizeof(LAYOUTCOMMIT4res) },
	{ (zdrproc_t)zdr_LAYOUTGET4res, sizeof(LAYOUTGET4res) },
	{ (zdrproc_t)zdr_LAYOUTRETURN4res, sizeof(LAYOUTRETURN4res) },
	{ (zdrproc_t)zdr_SECINFO_NO_NAME4res, sizeof(SECINFO_NO_NAME4res) },
	{ (zdrproc_t)zdr_SEQUENCE4res, sizeof(SEQUENCE4res) },
	{ (zdrproc_t)zdr_SET_SSV4res, sizeof(SET_SSV4res) },
	{ (zdrproc_t)zdr_TEST_STATEID4res, sizeof(TEST_STATEID4res) },
	{ (zdrproc_t)zdr_WANT_DELEGATION4res, sizeof(WANT_DELEGATION4res) },
	{ (zdrproc_t)zdr_DESTROY_CLIENTID4res, sizeof(DESTROY_CLIENTID4res) },
	{ (zdrproc_t)zdr_RECLAIM_COMPLETE4res, sizeof(RECLAIM_COMPLETE4res) },
	{ (zdrproc_t)zdr_ILLEGAL4res, sizeof(ILLEGAL4res) },
	{ (zdrproc_t)zdr_ALLOCATE4res, sizeof(ALLOCATE4res) },
	{ (zdrproc_t)zdr_DEALLOCATE4res, sizeof(DEALLOCATE4res) },
	{ (zdrproc_t)zdr_READ_PLUS4res, sizeof(READ_PLUS4res) },
	{ (zdrproc_t)zdr_write_response4, sizeof(write_response4) },
	{ (zdrproc_t)zdr_WRITE_SAME4res, sizeof(WRITE_SAME4res) },
	{ (zdrproc_t)zdr_SEEK4res, sizeof(SEEK4res) },
	{ (zdrproc_t)zdr_nfs_resop4, sizeof(nfs_resop4) },
	{ (zdrproc_t)zdr_COMPOUND4res, sizeof(COMPOUND4res) },
	{ (zdrproc_t)zdr_CB_GETATTR4res, sizeof(CB_GETATTR4res) },
	{ (zdrproc_t)zdr_CB_RECALL4res, sizeof(CB_RECALL4res) },
	{ (zdrproc_t)zdr_CB_ILLEGAL4res, sizeof(CB_ILLEGAL4res) },
	{ (zdrproc_t)zdr_nfs_cb_resop4, sizeof(nfs_cb_resop4) },
	{ (zdrproc_t)zdr_CB_COMPOUND4res, sizeof(CB_COMPOUND4res) },
	{ (zdrproc_t)zdr_rpc_gss_init_res, sizeof(rpc_gss_init_res) },
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 2)
		return 0;
	const unsigned idx = data[0];
	if (idx >= sizeof(decoders) / sizeof(decoders[0]))
		return 0;

	ZDR zdr;
	memset(&zdr, 0, sizeof(zdr));
	zdrmem_create(&zdr, (caddr_t)(data + 1), (uint32_t)(size - 1),
	              ZDR_DECODE);

	void *obj = calloc(1, decoders[idx].size);
	if (obj != NULL) {
		decoders[idx].fn(&zdr, obj);
		free(obj);
	}
	zdr_destroy(&zdr);
	return 0;
}
