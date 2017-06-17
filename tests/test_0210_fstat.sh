#!/bin/sh

. ./functions.sh

echo "basic fstat test"

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null
chmod 644 testdata/testfile

./prog_fstat "${TESTURL}/testfile" > "${TESTDIR}/output" || failure

echo -n "Testing nfs_ino ... "
INO=`stat --printf="%i" testdata/testfile`
grep "nfs_ino:$INO" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Testing nfs_mode ... "
grep "nfs_mode:100644" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Testing nfs_nlink ... "
grep "nfs_nlink:1" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Testing nfs_uid ... "
grep "nfs_uid:$UID" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Testing nfs_gid ... "
grep "nfs_gid:$GID" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Testing nfs_size ... "
grep "nfs_size:32768" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Testing nfs_atime ... "
ATIME=`stat --printf="%X" testdata/testfile`
grep "nfs_atime:$ATIME" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Testing nfs_mtime ... "
MTIME=`stat --printf="%Y" testdata/testfile`
grep "nfs_mtime:$MTIME" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Testing nfs_ctime ... "
CTIME=`stat --printf="%Z" testdata/testfile`
grep "nfs_ctime:$CTIME" "${TESTDIR}/output" >/dev/null || failure
success

stop_share

exit 0
