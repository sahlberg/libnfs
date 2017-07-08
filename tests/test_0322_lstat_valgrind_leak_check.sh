#!/bin/sh

. ./functions.sh

echo "basic valgrind leak check for nfs_lstat64()"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"


echo -n "test nfs_lstat64() (1) ... "
ln -s foo "${TESTDIR}/stat1"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_lstat "${TESTURL}/" "." /stat1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_lstat64() (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_lstat "${TESTURL}/" "." stat1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_lstat64() (3) ... "
ln -s foo "${TESTDIR}/subdir/stat3"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_lstat "${TESTURL}/" "." /subdir/stat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_lstat64() (4) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_lstat "${TESTURL}/" "." subdir/stat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_lstat64() (5) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_lstat "${TESTURL}/" "subdir2" ../subdir/stat3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_lstat64() (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_lstat "${TESTURL}/" "subdir2" ../../subdir/stat3 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
