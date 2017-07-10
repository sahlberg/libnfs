#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} nfs_stat64() test on symlink."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null
chmod 644 "${TESTDIR}/testfile"
ln -s testfile "${TESTDIR}/lstat1"


echo -n "test nfs_stat64() ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." /lstat1 > "${TESTDIR}/output" || failure
success

echo -n "test nfs_ino ... "
INO=`stat --printf="%i" testdata/testfile`
grep "nfs_ino:$INO" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_mode ... "
grep "nfs_mode:100644" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_nlink ... "
grep "nfs_nlink:1" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_uid ... "
grep "nfs_uid:$UID" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_gid ... "
grep "nfs_gid:$GID" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_size ... "
grep "nfs_size:32768" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_atime ... "
ATIME=`stat --printf="%X" testdata/testfile`
grep "nfs_atime:$ATIME" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_mtime ... "
MTIME=`stat --printf="%Y" testdata/testfile`
grep "nfs_mtime:$MTIME" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_ctime ... "
CTIME=`stat --printf="%Z" testdata/testfile`
grep "nfs_ctime:$CTIME" "${TESTDIR}/output" >/dev/null || failure
success

stop_share

exit 0
