#!/bin/sh

. ./functions.sh

echo "basic valgrind leak check for nfs_mkdir()/nfs_rmdir()"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Test nfs_mkdir() (1) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_mkdir "${TESTURL}/" "." /mkdir1 2>/dev/null || failure
success

echo -n "Test nfs_rmdir() (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rmdir "${TESTURL}/" "." /mkdir1 2>/dev/null || failure
success

echo -n "Test nfs_mkdir() (3) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_mkdir "${TESTURL}/" "." mkdir3 2>/dev/null || failure
success

echo -n "Test nfs_rmdir() (4) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rmdir "${TESTURL}/" "." mkdir3 2>/dev/null || failure
success

echo -n "Test nfs_mkdir() (5) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_mkdir "${TESTURL}/" "." /subdir/mkdir5 2>/dev/null || failure
success

echo -n "Test nfs_rmdir() (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rmdir "${TESTURL}/" "." /subdir/mkdir5 2>/dev/null || failure
success

echo -n "Test nfs_mkdir() (7) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_mkdir "${TESTURL}/" "." subdir/mkdir7 2>/dev/null || failure
success

echo -n "Test nfs_rmdir() (8) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rmdir "${TESTURL}/" "." subdir/mkdir7 2>/dev/null || failure
success

echo -n "Test nfs_mkdir() (9) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_mkdir "${TESTURL}/" "subdir" ../subdir2/mkdir9 2>/dev/null || failure
success

echo -n "Test nfs_rmdir() (10) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rmdir "${TESTURL}/" "subdir" ../subdir2/mkdir9 2>/dev/null || failure
success

echo -n "Test nfs_mkdir() (11) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_mkdir "${TESTURL}/" "subdir" ../../subdir2/mkdir9 2>/dev/null || expr $? != 99 >/dev/null || failure
success

echo -n "Test nfs_rmdir() (12) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rmdir "${TESTURL}/" "subdir" ../../subdir2/mkdir12 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
