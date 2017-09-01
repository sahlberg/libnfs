#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic fchown tests."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null

echo -n "test fchown(1000, 2000) ... "
./prog_fchown "${TESTURL}/?uid=0&version=${VERS}" "." /testfile 1000 2000 || failure
success

echo -n "Stat the file ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." testfile > "${TESTDIR}/output" || failure
success

echo -n "Verifying the uid is 1000 ... "
grep "nfs_uid:1000" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Verifying the gid is 2000 ... "
grep "nfs_gid:2000" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test fchown(2000, 3000) ... "
./prog_fchown "${TESTURL}/?uid=0&version=${VERS}" "." /testfile 2000 3000 || failure
success

echo -n "Stat the file ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." testfile > "${TESTDIR}/output" || failure
success

echo -n "Verifying the uid is 2000 ... "
grep "nfs_uid:2000" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Verifying the gid is 3000 ... "
grep "nfs_gid:3000" "${TESTDIR}/output" >/dev/null || failure
success


stop_share

exit 0
