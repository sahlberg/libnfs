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


CORPORA = {
    "seeds_rpc_reply_stream": reply_stream_seeds,
}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_stream_seeds.py <fuzzing directory>")
    for name, generate in CORPORA.items():
        write_seeds(os.path.join(sys.argv[1], name), generate())


if __name__ == "__main__":
    main()
