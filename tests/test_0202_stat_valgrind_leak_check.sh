#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind leak check for nfs_stat64()"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"


echo -n "test nfs_stat64() (1) ... "
touch "${TESTDIR}/stat1"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_stat "${TESTURL}/?version=${VERS}" "." /stat1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_stat64() (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_stat "${TESTURL}/?version=${VERS}" "." stat1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_stat64() (3) ... "
touch "${TESTDIR}/subdir/stat3"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_stat "${TESTURL}/?version=${VERS}" "." /subdir/stat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_stat64() (4) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_stat "${TESTURL}/?version=${VERS}" "." subdir/stat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_stat64() (5) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_stat "${TESTURL}/?version=${VERS}" "subdir2" ../subdir/stat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_stat64() (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_stat "${TESTURL}/?version=${VERS}" "subdir2" ../../subdir/stat3 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
