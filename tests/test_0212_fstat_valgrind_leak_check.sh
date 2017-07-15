#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind leak check for nfs_fstat64()."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"


echo -n "test nfs_fstat64() (1) ... "
touch "${TESTDIR}/fstat1"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_fstat "${TESTURL}/?version=${VERS}" "." /fstat1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_fstat64() (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_fstat "${TESTURL}/?version=${VERS}" "." fstat1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_fstat64() (3) ... "
touch "${TESTDIR}/subdir/fstat3"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_fstat "${TESTURL}/?version=${VERS}" "." /subdir/fstat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_fstat64() (4) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_fstat "${TESTURL}/?version=${VERS}" "." subdir/fstat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_fstat64() (5) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_fstat "${TESTURL}/?version=${VERS}" "subdir2" ../subdir/fstat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_fstat64() (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_fstat "${TESTURL}/?version=${VERS}" "subdir2" ../../subdir/fstat3 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
