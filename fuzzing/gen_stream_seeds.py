#!/usr/bin/env python3
# Copyright 2026 Kun-Wei Wu
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Generate the seed corpora for the socket-level fuzzers.

    python3 fuzzing/gen_stream_seeds.py fuzzing

writes one seeds_<name>/ directory per fuzzer (see CORPORA below) under the
given directory. Every seed is a small, well-formed RPC exchange, so the
fuzzer starts from inputs that already get past record marking and the RPC
header. See the "Input layout" comment at the top of each fuzzer for the
leading control bytes.
"""

import os
import struct
import sys

XID = 0x11223344
FH = b"fuzzfh00"


def u32(*v):
    return struct.pack(">%dI" % len(v), *v)


def u64(v):
    return struct.pack(">Q", v)


def opaque(b):
    """XDR variable-length opaque / string: length, bytes, pad to 4."""
    return u32(len(b)) + b + bytes(-len(b) % 4)


def record(msg):
    """One record-marked message, sent as a single last fragment."""
    return u32(0x80000000 | len(msg)) + msg


def fragments(msg, cut):
    """The same message split into two fragments at byte `cut`."""
    return u32(cut) + msg[:cut] + u32(0x80000000 | (len(msg) - cut)) + msg[cut:]


def write_seeds(directory, seeds):
    os.makedirs(directory, exist_ok=True)
    for name, data in seeds.items():
        with open(os.path.join(directory, name), "wb") as f:
            f.write(data)


# Reply header: REPLY(1), MSG_ACCEPTED(0), verifier AUTH_NONE (0, len 0),
# SUCCESS(0).
ACCEPTED_OK = u32(1, 0, 0, 0, 0)


def reply_stream_seeds():
    """libnfs_rpc_reply_stream_fuzzer: [request selector][chunk][stream]."""
    ok = ACCEPTED_OK
    # REG, mode, nlink, uid, gid; sizes/times 0
    fattr3 = u32(1, 0o644, 1, 0, 0) + bytes(64)

    def rec(body):
        return record(u32(XID) + body)

    def frags(body, cut):
        return fragments(u32(XID) + body, cut)

    streams = {
        "null_ok": (0, rec(ok)),
        "null_prog_mismatch": (0, rec(u32(1, 0, 0, 0, 2, 2, 4))),
        # MSG_DENIED, AUTH_ERROR, AUTH_BADCRED
        "null_denied_auth": (0, rec(u32(1, 1, 1, 1))),
        "null_denied_rpcmismatch": (0, rec(u32(1, 1, 0, 2, 2))),
        "getattr_ok": (1, rec(ok + u32(0) + fattr3)),
        "getattr_frag": (1, frags(ok + u32(0) + fattr3, 16)),
        "getattr_err": (1, rec(ok + u32(13))),  # NFS3ERR_ACCES
        "lookup_err": (2, rec(ok + u32(2, 0))),  # NOENT, no dir attrs
        "access_ok": (3, rec(ok + u32(0, 0, 0x3f))),
        "readlink_ok": (4, rec(ok + u32(0, 0, 4) + b"targ")),
        "readdirplus_ok": (5, rec(ok + u32(0, 0) + bytes(8) + u32(1, 0, 3)
                                  + bytes(8) + b"abc\0" + bytes(8)
                                  + u32(0, 0, 0, 1))),
        "fsinfo_err": (6, rec(ok + u32(70, 0))),  # STALE, no attrs
        "mnt_ok": (7, rec(ok + u32(0, 8) + FH + u32(1, 1))),
        "export_empty": (8, rec(ok + u32(0))),
        "export_one": (8, rec(ok + u32(1, 7) + b"/export\0" + u32(0, 0))),
        "getport": (9, rec(ok + u32(2049))),
        "getaddr": (10, rec(ok + u32(12) + b"0.0.0.0.8.1\0")),
        "unknown_xid_then_ok": (0, u32(0x80000000 | 8) + u32(0xdeadbeef, 1)
                                + rec(ok)),
    }
    # 3-byte writes split every field. A few of these are enough to reach the
    # partial-read paths; the fuzzer varies the chunk byte by itself.
    chunked = ("null_ok", "getattr_frag", "readdirplus_ok",
               "unknown_xid_then_ok")
    seeds = {}
    for name, (sel, stream) in streams.items():
        seeds[name] = bytes([sel, 0]) + stream  # chunk 0: write all at once
        if name in chunked:
            seeds[name + "_chunk3"] = bytes([sel, 3]) + stream
    return seeds


def server_call_seeds():
    """libnfs_rpc_server_call_fuzzer: [chunk][stream of CALLs]."""
    none = u32(0, 0)  # AUTH_NONE, length 0
    # AUTH_UNIX: flavor 1, body = stamp, machine name, uid, gid, 1 aux gid
    unix = u32(1) + opaque(u32(0) + opaque(b"fuzz") + u32(1000, 1000, 1, 1000))

    def call(prog, vers, proc, args=b"", cred=none, xid=XID, rpcvers=2):
        return u32(xid, 0, rpcvers, prog, vers, proc) + cred + none + args

    NFS, MNT, PMAP, NLM = 100003, 100005, 100000, 100021
    RQ, NSM, ACL = 100011, 100024, 100227
    fh = opaque(FH)
    sattr = u32(1, 0o644, 0, 0, 0, 0, 0)  # sattr3: set mode only
    lock = (opaque(b"client") + fh + opaque(b"owner") + u32(1) + u64(0)
            + u64(100))
    # PUTROOTFH, GETATTR
    compound = opaque(b"") + u32(0, 2) + u32(24) + u32(9, 1, 0x0010011a)
    calls = {
        "nfs3_null": call(NFS, 3, 0),
        "nfs3_getattr": call(NFS, 3, 1, fh),
        "nfs3_getattr_unix": call(NFS, 3, 1, fh, cred=unix),
        "nfs3_setattr": call(NFS, 3, 2, fh + sattr + u32(0)),
        "nfs3_lookup": call(NFS, 3, 3, fh + opaque(b"name")),
        "nfs3_access": call(NFS, 3, 4, fh + u32(0x3f)),
        "nfs3_read": call(NFS, 3, 6, fh + u64(0) + u32(4096)),
        "nfs3_write": call(NFS, 3, 7,
                           fh + u64(0) + u32(5, 2) + opaque(b"hello")),
        "nfs3_create": call(NFS, 3, 8, fh + opaque(b"f") + u32(0) + sattr),
        "nfs3_rename": call(NFS, 3, 14, fh + opaque(b"a") + fh + opaque(b"b")),
        "nfs3_readdirplus": call(NFS, 3, 17,
                                 fh + u64(0) + bytes(8) + u32(4096, 8192)),
        "nfs3_commit": call(NFS, 3, 21, fh + u64(0) + u32(0)),
        "nfs2_getattr": call(NFS, 2, 1, bytes(32)),
        "nfs4_compound": call(NFS, 4, 1, compound),
        "nfsacl_getacl": call(ACL, 3, 1, fh + u32(0xf)),
        "mnt3_mnt": call(MNT, 3, 1, opaque(b"/export")),
        "mnt3_export": call(MNT, 3, 5),
        "mnt1_umnt": call(MNT, 1, 3, opaque(b"/export")),
        "pmap2_getport": call(PMAP, 2, 3, u32(NFS, 3, 6, 0)),
        "pmap2_callit": call(PMAP, 2, 5, u32(NFS, 3, 0) + opaque(b"")),
        "pmap3_getaddr": call(PMAP, 3, 3, u32(NFS, 3) + opaque(b"tcp")
                              + opaque(b"") + opaque(b"")),
        "pmap4_getversaddr": call(PMAP, 4, 9, u32(NFS, 3) + opaque(b"tcp")
                                  + opaque(b"") + opaque(b"")),
        "nlm4_test": call(NLM, 4, 1, opaque(b"ck") + u32(1) + lock),
        "nlm4_lock": call(NLM, 4, 2,
                          opaque(b"ck") + u32(0, 1) + lock + u32(0, 1)),
        "nsm1_stat": call(NSM, 1, 1, opaque(b"host")),
        "rquota1_getquota": call(RQ, 1, 1, opaque(b"/export") + u32(1000)),
        # error replies
        "prog_mismatch": call(NFS, 5, 0),
        "prog_unavail": call(123456, 1, 0),
        "proc_unavail": call(NFS, 3, 99),
        "rpc_mismatch": call(NFS, 3, 0, rpcvers=3),
        "garbage_args": call(NFS, 3, 3, u32(64)),
    }
    # chunk 0: write all at once
    seeds = {name: bytes([0]) + record(msg) for name, msg in calls.items()}
    two = (record(call(NFS, 3, 1, fh))
           + record(call(MNT, 3, 1, opaque(b"/x"), xid=2)))
    seeds["two_calls"] = bytes([0]) + two
    # 3-byte writes split every field
    seeds["two_calls_chunk3"] = bytes([3]) + two
    seeds["frag_lookup"] = bytes([0]) + fragments(
        call(NFS, 3, 3, fh + opaque(b"name")), 20)
    return seeds


def zero_copy_seeds():
    """libnfs_nfs3_read_zero_copy_fuzzer:
    [iovcnt-1][chunk hi][chunk lo][4 iovec lengths][stream].

    iovec length = 1 + byte * 16. The reply is a READ3res: status,
    post_op_attr, count, eof, opaque data.
    """
    ok = ACCEPTED_OK
    # attributes_follow + fattr3
    attr = u32(1) + u32(1, 0o644, 1, 0, 0) + bytes(64)

    def read_ok(n, attrs=True):  # NFS3_OK, attrs, count, eof, data, pad
        body = u32(0) + (attr if attrs else u32(0))
        body += u32(n, 1, n) + bytes((i * 7) & 0xff for i in range(n))
        return ok + body + bytes(-n % 4)

    def rec(body):
        return record(u32(XID) + body)

    def frags(body, cut):
        return fragments(u32(XID) + body, cut)

    def hdr(niov, chunk, lens):
        lens = (lens + [0, 0, 0, 0])[:4]
        return bytes([niov - 1, chunk >> 8, chunk & 0xff] + lens)

    seeds = {
        # small read: all data arrives in the first (ZCRP-clamped) recv
        "small_1iov": (hdr(1, 0, [15]), rec(read_ok(200))),
        # odd length -> XDR padding after the data
        "small_pad": (hdr(2, 0, [3, 3]), rec(read_ok(97))),
        # > ZCRP: rest of the data is readv()'d into the iovecs, then padding
        "big_iovec": (hdr(4, 0, [64, 64, 64, 64]), rec(read_ok(4000 - 3))),
        "big_iovec_chunk": (hdr(3, 300, [100, 20, 150]),
                            rec(read_ok(4100 + 1))),
        "big_chunk7": (hdr(2, 7, [200, 200]), rec(read_ok(3000 + 2))),
        # short read: server returns less than requested (rpc_shrink_cursor)
        "short_read": (hdr(4, 0, [255, 255, 255, 255]), rec(read_ok(1500))),
        # server returns more than requested (clamped, extra discarded)
        "over_read": (hdr(1, 0, [10]), rec(read_ok(2000))),
        # no post_op_attr
        "noattr": (hdr(2, 0, [40, 40]), rec(read_ok(1200, attrs=False))),
        # fragmented record: reassembly branch
        "frag": (hdr(2, 0, [64, 64]), frags(read_ok(1800), 100)),
        "frag_small": (hdr(1, 5, [16]), frags(read_ok(100), 40)),
        # READ error: NFS3ERR_IO, no attrs
        "read_err": (hdr(1, 0, [16]), rec(ok + u32(5, 0))),
        # a reply with an unknown xid first, then the READ reply
        "unknown_then_read": (hdr(1, 0, [16]),
                              u32(0x80000000 | 8) + u32(0xdeadbeef, 1)
                              + rec(read_ok(150))),
    }
    return {name: h + stream for name, (h, stream) in seeds.items()}


CORPORA = {
    "seeds_rpc_reply_stream": reply_stream_seeds,
    "seeds_rpc_server_call": server_call_seeds,
    "seeds_nfs3_read_zero_copy": zero_copy_seeds,
}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_stream_seeds.py <fuzzing directory>")
    for name, generate in CORPORA.items():
        write_seeds(os.path.join(sys.argv[1], name), generate())


if __name__ == "__main__":
    main()
