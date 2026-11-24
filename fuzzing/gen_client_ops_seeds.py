#!/usr/bin/env python3
# Copyright 2026 Kun-Wei Wu
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Generate the seed corpora for libnfs_client_ops_fuzzer.c.

    python3 fuzzing/gen_client_ops_seeds.py <output directory>

writes seeds_nfs3_client_ops/, seeds_nfs40_client_ops/,
seeds_nfs41_client_ops/ and seeds_nfs42_client_ops/ under the given
directory, one per fuzzer binary. The seeds are not kept in the tree.

Each seed is a whole conversation: the option byte, four operations and the
replies a well-behaved server would give, so the fuzzer starts from inputs
that get through the mount and into each operation's reply handler.
Replies are XDR (RFC 1813 for NFSv3, RFC 7530/8881 for NFSv4); the fuzzer
adds the record marker, the XID and the RPC "accepted/success" header.
See the "Input layout" comment at the top of the fuzzer.
"""

import os
import struct
import sys

SKIP = (13, 0)  # close without an open file: the fuzzer skips it


def u32(*v):
    return struct.pack(">%dI" % len(v), *v)


def u64(v):
    return struct.pack(">Q", v)


def opaque(b):
    return u32(len(b)) + b + bytes(-len(b) % 4)


def entry(body, raw=False, unsolicited=False):
    """One reply entry: u16 LE header (length + flag bits), then the body."""
    assert len(body) < 0x2000
    hdr = len(body) | (0x8000 if raw else 0) | (0x4000 if unsolicited else 0)
    return struct.pack("<H", hdr) + body


def arg(path, hi, mod=8):
    """Operation argument byte: low part picks the path (arg % 10), the high
    nibble picks open flags (mod 8) or the second path (mod 10)."""
    for a in range(256):
        if a % 10 == path and (a >> 4) % mod == hi:
            return a
    raise ValueError((path, hi))


def seed(opts, ops, replies):
    ops = (list(ops) + [SKIP] * 4)[:4]
    head = bytes([opts]) + b"".join(bytes(o) for o in ops)
    return head + b"".join(entry(r) if isinstance(r, bytes) else entry(*r)
                           for r in replies)


# ------------------------------------------------------------------ NFSv3
NF3REG, NF3DIR, NF3LNK = 1, 2, 5
FH = opaque(b"fuzzfh00")


def fattr3(ftype=NF3REG, mode=0o644, size=100, fileid=7):
    return (u32(ftype, mode, 1, 1000, 1000) + u64(size) + u64(size) +
            u64(0) + u64(1) + u64(fileid) + u64(1) + u64(2) + u64(3))


def post_attr(**kw):
    return u32(1) + fattr3(**kw)


WCC = u32(1) + u64(100) + u64(2) + u64(3) + post_attr()   # pre + post attrs


def lookup3(ftype=NF3REG):
    return u32(0) + FH + post_attr(ftype=ftype) + post_attr(ftype=NF3DIR)


def v3_seeds():
    null = b""
    mnt = u32(0) + FH + u32(1, 1)                     # fh, auth flavors {1}
    fsinfo = (u32(0) + post_attr(ftype=NF3DIR) + u32(65536, 65536, 512) +
              u32(65536, 65536, 512) + u32(4096) + u64(1 << 40) + u32(0, 1) +
              u32(0x1b))
    getattr_dir = u32(0) + fattr3(ftype=NF3DIR)
    getattr_reg = u32(0) + fattr3()
    # MOUNT NULL, MNT, then on the NFS connection: NULL, FSINFO, GETATTR
    # export list: one export, no groups
    export = u32(1) + opaque(b"/export") + u32(0) + u32(0)
    mount = [null, mnt, export, null, fsinfo, getattr_dir]
    # same with the portmapper in front of each connection
    pmap_mount = [null, u32(20048), null, mnt, export, null, u32(2049), null,
                  fsinfo, getattr_dir]
    def access(mask=1):
        # nfs_open() wants exactly the bits it asked for: 1 read, 4 modify
        return u32(0) + post_attr() + u32(mask)

    read = u32(0) + post_attr() + u32(4, 1) + opaque(b"data")
    def write(count):
        return u32(0) + WCC + u32(count, 2) + u64(0x1122334455667788)

    noent = u32(2, 0)
    commit = u32(0) + WCC + u64(0x1122334455667788)
    readdirplus = (u32(0) + post_attr(ftype=NF3DIR) + u64(0) +
                   u32(1) + u64(11) + opaque(b"abc") + u64(1) + post_attr() +
                   u32(1) + FH +
                   u32(1) + u64(12) + opaque(b"sub") + u64(2) +
                   post_attr(ftype=NF3DIR) + u32(0) +
                   u32(0, 1))
    readlink = u32(0) + post_attr(ftype=NF3LNK) + opaque(b"t")
    create = u32(0) + u32(1) + FH + post_attr() + WCC
    wcc_only = u32(0) + WCC
    rename = u32(0) + WCC + WCC
    fsstat = (u32(0) + post_attr(ftype=NF3DIR) + u64(1 << 30) * 3 +
              u64(1000) * 3 + u32(0))
    link = u32(0) + post_attr() + WCC
    lk = lookup3()
    lkdir = lookup3(NF3DIR)
    lklnk = lookup3(NF3LNK)
    # paths (see paths[] in the fuzzer): 0 "/", 1 "a", 2 "/a/b", 4 "/link/x"
    # open flags index: 0 RDONLY, 1 RDWR, 2 WRONLY|CREAT, 7 WRONLY|CREAT|TRUNC
    s = {
        "mount": seed(0, [], mount),
        "mount_notraverse": seed(
            8, [], [null, mnt, null, fsinfo, getattr_dir]),
        "mount_pmap": seed(1, [], pmap_mount),
        "mount_mnt_err": seed(0, [], [null, u32(13)]),
        "stat": seed(0, [(0, 1)], mount + [lk, getattr_reg]),
        "stat_deep": seed(0, [(0, 2)], mount + [lkdir, lk, getattr_reg]),
        "stat_symlink": seed(
            0, [(0, 4)],
            mount + [lklnk, readlink, lkdir, lk, getattr_reg]),
        "stat_noent": seed(0, [(0, 1)], mount + [u32(2, 0)]),
        "open_read_close": seed(
            0, [(2, arg(1, 0)), (5, 3), (6, 200), (13, 0)],
            mount + [lk, access(1), read, read]),
        "open_read_smallio": seed(
            0x10, [(2, arg(1, 0)), (5, 255), (9, 0), (11, 2)],
            mount + [lk, access(1), read, getattr_reg,
                     getattr_reg]),
        "open_write_fsync": seed(
            0, [(2, arg(1, 1)), (7, 9), (8, 3), (12, 0)],
            mount + [lk, access(5), write(10), write(4), commit]),
        "creat_write_close": seed(
            0, [(4, 2), (7, 1), (10, 5), (13, 0)],
            mount + [lkdir, noent, lkdir, create, write(2), wcc_only,
                     commit]),
        "open_creat_trunc": seed(
            0, [(3, arg(2, 7)), (9, 0), (32, 0), (33, 0)],
            mount + [lkdir, noent, lkdir, create,
                     getattr_reg, wcc_only, wcc_only]),
        "opendir": seed(0, [(14, 0)], mount + [readdirplus]),
        "opendir_nocache": seed(
            0x24, [(14, 2), (14, 2)],
            mount + [lkdir, lkdir, readdirplus] * 2),
        "readlink": seed(0, [(21, 1)], mount + [lklnk, readlink]),
        "mkdir_rmdir": seed(
            0, [(15, 2), (16, 2)],
            mount + [lkdir, create, lkdir, wcc_only]),
        "unlink_rename": seed(
            0, [(17, 2), (18, arg(2, 2))],
            mount + [lkdir, wcc_only, lkdir, lkdir, rename]),
        "symlink_link": seed(
            0, [(19, arg(2, 1)), (20, arg(2, 2))],
            mount + [lkdir, create, lkdir, lk, lkdir, link]),
        "chmod_chown_utimes": seed(
            0, [(22, 1), (23, 1), (24, 1), (25, 1)],
            mount + [lk, wcc_only] * 4),
        "statvfs_access": seed(
            0, [(26, 0), (27, 1), (28, 1), (30, 2)],
            mount + [fsstat, lk, access(0), lk, access(0x3f),
                     lkdir, lkdir]),
        "mknod": seed(
            0, [(29, 2), (31, 1)],
            mount + [lkdir, create, lk, wcc_only]),
        "reconnect": seed(
            2, [(0, 1)], mount + [(u32(1, 1, 1), True), lk,
                                  getattr_reg]),
        # GETACL3 (program 100227): attributes, mask, two ACL arrays
        "getacl": seed(
            0, [(2, arg(1, 0)), (47, 0), (36, 0), (13, 0)],
            mount + [lk, access(1),
                     u32(0) + post_attr() + u32(0xf) +
                     u32(2, 2) + u32(1, 0, 7) + u32(4, 100, 5) +
                     u32(1, 1) + u32(0x1001, 0, 6),
                     getattr_reg]),
        "readv_stat_statvfs": seed(
            0, [(2, arg(1, 0)), (38, 9), (35, 1), (37, 0)],
            mount + [lk, access(1), read, lk, getattr_reg,
                     fsstat]),
        "utime_lchmod_mkdir": seed(
            0, [(40, 1), (41, 1), (45, 1), (46, 2)],
            mount + [lk, wcc_only] * 3 + [lkdir, create]),
        "umount": seed(
            0, [(0, 1), (34, 0)],
            mount + [lk, getattr_reg, null, null]),
        # selector | 0x80: do not wait, so these requests are all in flight
        # and the replies come back in the order the calls were sent
        "pipelined_stats": seed(
            0, [(0x80, 1), (0x80 | 21, 1), (0x80 | 26, 0), (0, 2)],
            mount + [lk, lklnk, fsstat, lkdir, getattr_reg,
                     readlink, lk, getattr_reg]),
        "pipelined_io": seed(
            0, [(2, arg(1, 1)), (0x80 | 5, 3), (0x80 | 7, 9), (9, 0)],
            mount + [lk, access(5), read, write(10), getattr_reg]),
        # READDIRPLUS not supported -> the client falls back to READDIR
        "opendir_readdir_fallback": seed(0, [(14, 0)], mount + [
            u32(10004, 0),
            u32(0) + post_attr(ftype=NF3DIR) + u64(0) +
            u32(1) + u64(11) + opaque(b"abc") + u64(1) + u32(0, 1),
            lk]),
        # the export list has an export below ours: nested mount traversal
        "mount_nested": seed(0, [(0, 1)], [
            null, mnt,
            u32(1) + opaque(b"/export") + u32(0) +
            u32(1) + opaque(b"/export/a") + u32(0) + u32(0),
            mnt, null, fsinfo, getattr_dir, getattr_dir, lk, getattr_reg,
            lk, getattr_reg]),
    }
    return s


# ------------------------------------------------------------------ NFSv4
OP_ACCESS, OP_CLOSE, OP_COMMIT, OP_CREATE = 3, 4, 5, 6
OP_GETATTR, OP_GETFH, OP_LINK = 9, 10, 11
OP_LOCK, OP_LOCKT, OP_LOCKU = 12, 13, 14
OP_LOOKUP, OP_OPEN, OP_OPEN_CONFIRM = 15, 18, 20
OP_PUTFH, OP_PUTROOTFH, OP_READ, OP_READDIR, OP_READLINK = 22, 24, 25, 26, 27
OP_REMOVE, OP_RENAME, OP_RESTOREFH, OP_SAVEFH, OP_SETATTR = 28, 29, 31, 32, 34
OP_SETCLIENTID, OP_SETCLIENTID_CONFIRM, OP_WRITE = 35, 36, 38
OP_EXCHANGE_ID, OP_CREATE_SESSION = 42, 43
OP_SEQUENCE, OP_RECLAIM_COMPLETE = 53, 58
OP_SEEK, OP_ALLOCATE = 69, 59
SESSION = b"fuzzsession00000"
STATEID = u32(1) + b"stateid-0123"


def compound(*ops, status=0):
    """COMPOUND4res: status, empty tag, then the per-operation results."""
    return u32(status) + u32(0) + u32(len(ops)) + b"".join(ops)


def op(num, body=b"", status=0):
    return u32(num, status) + body


def fattr4(ftype=1, size=100):
    """The attributes libnfs asks for in its standard GETATTR, in bitmap order:
    type, size, fsid, fileid | mode, numlinks, owner, owner_group, rawdev,
    space_used, time_access, time_metadata, time_modify."""
    w0 = (1 << 1) | (1 << 4) | (1 << 8) | (1 << 20)
    w1 = sum(1 << (b - 32) for b in (33, 35, 36, 37, 41, 45, 47, 52, 53))
    vals = (u32(ftype) + u64(size) + u64(1) + u64(2) + u64(77) +
            u32(0o644) + u32(1) + opaque(b"1000") + opaque(b"users@example") +
            u64(0) + u64(size) + (u64(1) + u32(2)) * 3)
    return u32(2, w0, w1) + opaque(vals)


def fattr4_statvfs():
    """fsid, files_avail, files_free, files_total, maxname | space_avail,
    space_free, space_total."""
    w0 = (1 << 8) | (1 << 21) | (1 << 22) | (1 << 23) | (1 << 29)
    w1 = sum(1 << (b - 32) for b in (42, 43, 44))
    vals = u64(1) + u64(2) + u64(10) * 3 + u32(255) + u64(1 << 30) * 3
    return u32(2, w0, w1) + opaque(vals)


def seq():
    """SEQUENCE4resok (NFSv4.1+): session, seqid, slot, highest slots,
    flags."""
    return op(OP_SEQUENCE, SESSION + u32(1, 0, 0, 0, 0))


def v4_seeds(minor):
    null = b""
    fh = opaque(b"fuzzfh04")

    def c(*ops, **kw):
        if minor >= 1:
            ops = (seq(),) + ops
        return compound(*ops, **kw)

    getattr_dir = op(OP_GETATTR, fattr4(ftype=2))
    getattr_reg = op(OP_GETATTR, fattr4())
    getattr_lnk = op(OP_GETATTR, fattr4(ftype=5))
    if minor == 0:
        setclientid = op(OP_SETCLIENTID, u64(0x1122334455667788) + bytes(8))
        hello = [null, compound(setclientid),
                 compound(op(OP_SETCLIENTID_CONFIRM))]
    else:
        exch = op(OP_EXCHANGE_ID,
                  u64(0x1122334455667788) + u32(1, 0x00010003, 0) +  # SP4_NONE
                  u64(1) + opaque(b"major") + opaque(b"scope") + u32(0))
        chan = u32(0, 65536, 65536, 65536, 16, 8, 0)
        crs = op(OP_CREATE_SESSION, SESSION + u32(1, 0) + chan + chan)
        hello = [null, compound(exch), compound(crs),
                 c(op(OP_RECLAIM_COMPLETE))]
    root = c(op(OP_PUTROOTFH), op(OP_LOOKUP), op(OP_GETFH, fh), getattr_dir)
    # last mount step: lease time (4.0 only) and the server's read/write limits
    if minor == 0:
        limits = u32(1, (1 << 10) | (1 << 30) | (1 << 31)) + opaque(
            u32(90) + u64(65536) + u64(65536))
    else:
        limits = u32(1, (1 << 30) | (1 << 31)) + opaque(
            u64(65536) + u64(65536))
    mount = hello + [root, c(op(OP_PUTFH), op(OP_GETATTR, limits))]
    lookup1 = c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_GETFH, fh), getattr_reg)
    stat1 = c(op(OP_PUTFH), op(OP_LOOKUP), getattr_reg)
    s = {
        "mount": seed(0, [], mount),
        "mount_err": seed(
            0, [], hello + [c(op(OP_PUTROOTFH),
                              op(OP_LOOKUP, status=2), status=2)]),
        "stat": seed(0, [(0, 1)], mount + [stat1]),
        "stat4": seed(0, [(31, 1)], mount + [stat1]),
        "lstat_link": seed(0, [(1, 1)], mount + [
            c(op(OP_PUTFH), op(OP_LOOKUP), getattr_lnk)]),
        "readlink": seed(0, [(21, 1)], mount + [
            c(op(OP_PUTFH), op(OP_LOOKUP),
              op(OP_READLINK, opaque(b"../x/y")))]),
        "statvfs": seed(0, [(26, 0)], mount + [
            c(op(OP_PUTFH), op(OP_GETATTR, fattr4_statvfs()))]),
        "access": seed(0, [(27, 1), (28, 1)], mount + [
            c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_ACCESS, u32(0x3f, 0x3f)),
              getattr_reg)] * 2),
        "mkdir": seed(0, [(15, 1), (16, 1), (17, 1)], mount + [
            c(op(OP_PUTFH),
              op(OP_CREATE, u64(1) + u64(2) + u64(3) + u32(0)))] +
            [c(op(OP_PUTFH), op(OP_REMOVE, u64(1) + u64(2) + u64(3)))] * 2),
    }
    cinfo = u32(1) + u64(1) + u64(2)                    # change_info4
    no_bitmap = u32(0)
    # OPEN4resok: stateid, cinfo, rflags, attrset, delegation none.
    # rflags 2 = OPEN4_RESULT_CONFIRM: NFSv4.0 then sends OPEN_CONFIRM.
    def open_ok(rflags=0):
        return op(OP_OPEN, STATEID + cinfo + u32(rflags) + no_bitmap + u32(0))

    def open_res(access=0x3f, rflags=0):
        return c(op(OP_PUTFH), op(OP_ACCESS, u32(0x3f, access)),
                 open_ok(rflags), op(OP_GETFH, fh), getattr_reg)

    confirm = c(op(OP_PUTFH), op(OP_OPEN_CONFIRM, STATEID))
    read = c(op(OP_PUTFH), op(OP_READ, u32(1) + opaque(b"data")))

    def write(count):
        return c(op(OP_PUTFH), op(OP_WRITE, u32(count, 2) + bytes(8)),
                 getattr_reg)

    close = c(op(OP_PUTFH), op(OP_COMMIT, bytes(8)), op(OP_CLOSE, STATEID))
    close_ro = c(op(OP_PUTFH), op(OP_CLOSE, STATEID))
    getattr = c(op(OP_PUTFH), getattr_reg)
    setattr = c(op(OP_PUTFH), op(OP_SETATTR, no_bitmap), getattr_reg)
    dirent = (u32(1) + u64(1) + opaque(b"abc") + fattr4() +
              u32(1) + u64(2) + opaque(b"sub") + fattr4(ftype=2) + u32(0))
    readdir = c(op(OP_PUTFH), op(OP_GETFH, fh),
                op(OP_READDIR, bytes(8) + dirent + u32(1)))
    lock = c(op(OP_PUTFH), op(OP_LOCK, STATEID))
    locku = c(op(OP_PUTFH), op(OP_LOCKU, STATEID))
    lockt = c(op(OP_PUTFH), op(OP_LOCKT))
    lockt_denied = c(op(OP_PUTFH), op(OP_LOCKT, u64(0) + u64(10) + u32(1) +
                                      u64(7) + opaque(b"owner"), status=10010),
                     status=10010)
    rename = c(op(OP_PUTFH), op(OP_SAVEFH), op(OP_PUTFH),
               op(OP_RENAME, cinfo + cinfo))
    link = c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_SAVEFH), op(OP_PUTFH),
             op(OP_LINK, cinfo))
    create = c(op(OP_PUTFH), op(OP_CREATE, cinfo + no_bitmap))
    s.update({
        "open_read_close": seed(
            0, [(2, arg(1, 0)), (5, 3), (6, 200), (13, 0)],
            mount + [open_res(), read, read, close_ro]),
        "open_confirm_fstat": seed(
            0, [(2, arg(1, 1)), (9, 0), (11, 2), (13, 0)],
            mount + [open_res(rflags=2), confirm, getattr,
                     getattr, close]),
        "open_write_fsync": seed(
            0, [(2, arg(1, 1)), (7, 9), (8, 3), (12, 0)],
            mount + [open_res(), write(10), write(4),
                     c(op(OP_PUTFH), op(OP_COMMIT, bytes(8)))]),
        "creat_trunc_chmod": seed(
            0, [(4, 1), (10, 5), (32, 0), (33, 0)],
            mount + [open_res(), setattr, setattr, setattr,
                     setattr, getattr, close]),
        "open_trunc_append": seed(
            0, [(3, arg(1, 7)), (8, 1), (10, 1), (13, 0)],
            mount + [open_res(), setattr, write(2), setattr,
                     close]),
        "locks": seed(
            0, [(2, arg(1, 1)), (32, 0), (32, 3), (32, 2)],
            mount + [open_res(), lock, lockt, locku]),
        "lock_denied": seed(
            0, [(2, arg(1, 1)), (32, 3), (33, 1), (33, 2)],
            mount + [open_res(), lockt_denied, lock, locku]),
        "opendir": seed(0, [(14, 0), (14, 1)], mount + [readdir, c(
            op(OP_PUTFH), op(OP_LOOKUP), op(OP_GETFH, fh),
            op(OP_READDIR, bytes(8) + dirent + u32(1)))]),
        "rename_link_symlink": seed(
            0, [(18, arg(1, 1, 10)), (20, arg(1, 1, 10)),
                (19, arg(1, 1, 10)), (29, 1)],
            mount + [rename, lookup1, link, create, create]),
        "chmod_chown_utimes": seed(
            0, [(22, 1), (23, 1), (24, 1), (25, 1)],
            mount + [c(op(OP_PUTFH), op(OP_LOOKUP),
                       op(OP_SETATTR, no_bitmap))] * 3 +
            [open_res(), setattr, close]),
        "lseek_chdir": seed(
            0, [(2, arg(1, 0)), (11, 2), (30, 1), (0, 1)],
            mount + [open_res(), getattr, c(
                op(OP_PUTFH), op(OP_LOOKUP), getattr_dir), stat1]),
        "stat_symlink": seed(0, [(0, 4)], mount + [
            c(op(OP_PUTFH), op(OP_LOOKUP), getattr_lnk),
            c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_READLINK, opaque(b"t"))),
            c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_LOOKUP), getattr_reg)]),
    })
    acl = u32(1, 1 << 12) + opaque(
        u32(2) + u32(0, 0, 0x1f) + opaque(b"OWNER@") +
        u32(1, 0x40, 0x3) + opaque(b"users@example"))
    s.update({
        "getacl": seed(
            0, [(2, arg(1, 0)), (47, 0), (55, 0), (13, 0)],
            mount + [open_res(), c(op(OP_PUTFH), op(OP_GETATTR, acl)),
                     getattr, close_ro]),
        "readv_utime_lchmod": seed(
            0, [(2, arg(1, 0)), (38, 9), (40, 1), (41, 1)],
            mount + [open_res(), read] +
            [c(op(OP_PUTFH), op(OP_LOOKUP),
               op(OP_SETATTR, no_bitmap))] * 2),
        "fchmod_fchown_statvfs": seed(
            0, [(2, arg(1, 1)), (43, 0), (44, 0), (37, 0)],
            mount + [open_res(), setattr, setattr, c(
                op(OP_PUTFH),
                op(OP_GETATTR, fattr4_statvfs()))]),
        # OPENATTR (19) gives the named attribute directory
        "namedattr": seed(
            0, [(49, 1), (51, 1), (50, arg(1, 2)), (13, 0)], mount + [
            c(op(OP_PUTFH), op(OP_LOOKUP), op(19), op(OP_GETFH, fh),
              op(OP_READDIR, bytes(8) + dirent + u32(1))),
            c(op(OP_PUTFH), op(OP_LOOKUP), op(19), op(OP_REMOVE, cinfo)),
            c(op(OP_PUTFH), op(OP_LOOKUP), op(19),
              op(OP_ACCESS, u32(0x3f, 0x3f)), open_ok(), op(OP_GETFH, fh),
              getattr_reg),
            close_ro]),
        "umount": seed(0, [(0, 1), (34, 0)], mount + [stat1, c(), c()]),
        "pipelined_stats": seed(
            0, [(0x80, 1), (0x80 | 31, 1), (0x80 | 26, 0), (0, 1)],
            mount + [stat1, stat1, c(
                op(OP_PUTFH), op(OP_GETATTR, fattr4_statvfs())),
                stat1]),
        "pipelined_io": seed(
            0, [(2, arg(1, 1)), (0x80 | 5, 3), (0x80 | 7, 9), (9, 0)],
            mount + [open_res(), read, write(10), getattr]),
        # OPEN answers NFS4ERR_SYMLINK (10029): the client reads the link
        # and opens the target instead
        "open_symlink": seed(0, [(2, arg(1, 0)), (9, 0), (13, 0)], mount + [
            c(op(OP_PUTFH), op(OP_ACCESS, u32(0x3f, 0x3f)),
              op(OP_OPEN, status=10029), status=10029),
            c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_READLINK, opaque(b"t"))),
            open_res(), getattr, close_ro]),
        # a symlink in the middle of the path: LOOKUP fails with SYMLINK
        "stat_midpath_symlink": seed(0, [(0, 4)], mount + [
            c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_LOOKUP, status=10029),
              status=10029),
            c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_READLINK, opaque(b"/a"))),
            c(op(OP_PUTFH), op(OP_LOOKUP), op(OP_LOOKUP), getattr_reg)]),
        # NFS4ERR_DELAY (10008) / GRACE (10013): the client retries later
        "stat_delay": seed(0, [(0, 1)], mount + [
            c(op(OP_PUTFH, status=10008), status=10008), stat1]),
    })
    if minor >= 2:
        # READ_PLUS (68): eof, then data and hole extents. WRITE_SAME (70):
        # write_response4. ALLOCATE (59) / DEALLOCATE (62): status only.
        read_plus = c(op(OP_PUTFH), op(
            68, u32(1, 2) + u32(0) + u64(0) + opaque(b"data") +
            u32(1) + u64(4) + u64(100)))
        write_same = c(op(OP_PUTFH), op(
            70, u32(0) + u64(8) + u32(2) + bytes(8)))
        s.update({
            "read_plus_write_same": seed(
                0, [(2, arg(1, 1)), (52, 9), (53, 0x11),
                    (11, 3)],
                mount + [open_res(), read_plus, write_same,
                         c(op(OP_PUTFH),
                           op(OP_SEEK, u32(0) + u64(64)))]),
            "fallocate": seed(
                0, [(2, arg(1, 1)), (48, 0x10), (48, 0x11), (48, 0x12)],
                mount + [open_res(), c(op(OP_PUTFH), op(OP_ALLOCATE)),
                         c(op(OP_PUTFH), op(62)),
                         c(op(OP_PUTFH), op(62))]),
        })
    if minor >= 1:
        # NFSv4.1 back channel: the server sends CB_COMPOUND calls on the same
        # connection. RPC call header (program 0x40000000, version 1,
        # procedure 1, AUTH_NONE twice), then tag, minorversion,
        # callback_ident and the operations, CB_SEQUENCE (11) first.
        def cb_call(xid, seqid, *ops):
            return (u32(xid, 0, 2, 0x40000000, 1, 1, 0, 0, 0, 0) +
                    u32(0, minor, 0, 1 + len(ops)) +
                    u32(11) + SESSION + u32(seqid, 0, 0, 0, 0) + b"".join(ops))

        def unsol(body):
            return (body, True, True)

        cb_recall = u32(4) + STATEID + u32(0) + fh
        cb_getattr = u32(3) + fh + u32(2, 0x10, 0)
        cb_recall_any = u32(8) + u32(1) + u32(1, 1)
        cb_obj_avail = u32(9)
        cb_null = u32(0x98, 0, 2, 0x40000000, 1, 0, 0, 0, 0, 0)
        crs_bc = op(OP_CREATE_SESSION, SESSION + u32(1, 2) + chan + chan)
        bc_mount = [null, compound(exch), compound(crs_bc),
                    c(op(OP_RECLAIM_COMPLETE)), root,
                    c(op(OP_PUTFH), op(OP_GETATTR, limits))]
        s["bc_no_handler"] = seed(0, [(0, 1)], mount + [
            unsol(cb_call(0x99, 1)), stat1])
        s["bc_null_sequence"] = seed(0x40, [(0, 1)], bc_mount + [
            unsol(cb_null), unsol(cb_call(0x99, 1)), stat1])
        s["bc_recall"] = seed(0xc0, [(0, 1), (0, 1)], bc_mount + [
            unsol(cb_call(0x99, 1, cb_recall)), stat1,
            unsol(cb_call(0x9a, 2, cb_getattr, cb_recall_any)), stat1])
        s["bc_notsupp_replay"] = seed(0x40, [(0, 1), (0, 1)], bc_mount + [
            unsol(cb_call(0x99, 1, cb_obj_avail, cb_recall)), stat1,
            unsol(cb_call(0x99, 1, cb_obj_avail)),      # replay of seqid 1
            unsol(cb_call(0x9b, 7)), stat1])            # misordered
    return s


CORPORA = {
    "seeds_nfs3_client_ops": v3_seeds,
    "seeds_nfs40_client_ops": lambda: v4_seeds(0),
    "seeds_nfs41_client_ops": lambda: v4_seeds(1),
    "seeds_nfs42_client_ops": lambda: v4_seeds(2),
}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_client_ops_seeds.py <output directory>")
    for name, generate in CORPORA.items():
        out = os.path.join(sys.argv[1], name)
        os.makedirs(out, exist_ok=True)
        for seed_name, data in generate().items():
            with open(os.path.join(out, seed_name), "wb") as f:
                f.write(data)


if __name__ == "__main__":
    main()
