#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic nfs_utimes() tests."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null
chmod 644 "${TESTDIR}/testfile"

echo -n "test nfs_utimes() ... "
./prog_utimes "${TESTURL}/?version=${VERS}" "." /testfile 12345 23456 || failure
success

echo -n "test nfs_stat64() ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." /testfile > "${TESTDIR}/output" || failure
success

echo -n "test nfs_atime ... "
grep "nfs_atime:12345" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs_mtime ... "
grep "nfs_mtime:23456" "${TESTDIR}/output" >/dev/null || failure
success


stop_share

exit 0
