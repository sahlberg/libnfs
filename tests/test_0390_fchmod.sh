#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic fchmod tests."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null

echo -n "test fchmod(0600) ... "
./prog_fchmod "${TESTURL}/?version=${VERS}" "." /testfile 0600 || failure
success

echo -n "Stat the file ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." testfile > "${TESTDIR}/output" || failure
success

echo -n "Verifying the mode is 0600 ... "
grep "nfs_mode:100600" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test fchmod(0755) ... "
./prog_fchmod "${TESTURL}/?version=${VERS}" "." /testfile 0755 || failure
success

echo -n "Stat the file ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." testfile > "${TESTDIR}/output" || failure
success

echo -n "Verifying the mode is 0755 ... "
grep "nfs_mode:100755" "${TESTDIR}/output" >/dev/null || failure
success


stop_share

exit 0
