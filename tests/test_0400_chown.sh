#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic chown tests."

start_share

dd if=/dev/zero of=${TESTDIR}/testfile count=1 bs=32768 2>/dev/null

echo -n "test chown(1000, 2000) ... "
./prog_chown "${TESTURL}/?uid=0&version=${VERS}" "." /testfile 1000 2000 || failure
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

echo -n "test chown(2000, 3000) ... "
./prog_chown "${TESTURL}/?uid=0&version=${VERS}" "." /testfile 2000 3000 || failure
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

mkdir ${TESTDIR}/testdir

echo -n "test chown(1000, 2000) on dir ... "
./prog_chown "${TESTURL}/?uid=0&version=${VERS}" "." /testdir 1000 2000 || failure
success

echo -n "Stat the dir ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." testdir > "${TESTDIR}/output" || failure
success

echo -n "Verifying the uid is 1000 on dir ... "
grep "nfs_uid:1000" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Verifying the gid is 2000 on dir ... "
grep "nfs_gid:2000" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test chown(2000, 3000) on dir ... "
./prog_chown "${TESTURL}/?uid=0&version=${VERS}" "." /testdir 2000 3000 || failure
success

echo -n "Stat the dir ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." testdir > "${TESTDIR}/output" || failure
success

echo -n "Verifying the uid is 2000 on dir ... "
grep "nfs_uid:2000" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Verifying the gid is 3000 on dir ... "
grep "nfs_gid:3000" "${TESTDIR}/output" >/dev/null || failure
success

stop_share

exit 0
