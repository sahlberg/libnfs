#!/bin/sh

. ./functions.sh

echo "basic valgrind leak check for nfs_symlink()"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Test nfs_symlink() (1) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_symlink "${TESTURL}/" "." kangabanga /symlink1 2>/dev/null || failure
success

echo -n "Test nfs_symlink() (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_symlink "${TESTURL}/" "." kangabanga symlink2 2>/dev/null || failure
success

echo -n "Test nfs_symlink() (3) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_symlink "${TESTURL}/" "." kangabanga /subdir/symlink3 2>/dev/null || failure
success

echo -n "Test nfs_symlink() (4) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_symlink "${TESTURL}/" "." kangabanga subdir/symlink4 2>/dev/null || failure
success

echo -n "Test nfs_symlink() (5) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_symlink "${TESTURL}/" "/subdir" kangabanga symlink5 2>/dev/null || failure
success

echo -n "Test nfs_symlink() (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_symlink "${TESTURL}/" "/subdir" kangabanga ../symlink6 2>/dev/null || failure
success

echo -n "Test nfs_symlink() (7) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_symlink "${TESTURL}/" "/subdir" kangabanga ../subdir2/symlink7 2>/dev/null || failure
success

echo -n "Test nfs_symlink() (8) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_symlink "${TESTURL}/" "/subdir" kangabanga ../../symlink8 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
