#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic nfs_truncate() tests."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null

echo -n "test nfs_truncate() ... "
./prog_truncate "${TESTURL}/?version=${VERS}" "." /testfile 1998 || failure
success

echo -n "test nfs_fstat64() ... "
./prog_fstat "${TESTURL}/?version=${VERS}" "." testfile > "${TESTDIR}/output" || failure
success

echo -n "test nfs_size ... "
grep "nfs_size:1998" "${TESTDIR}/output" >/dev/null || failure
success

stop_share

exit 0
