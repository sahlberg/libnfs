#!/bin/sh

. ./functions.sh

echo "basic valgrind leak check for nfs_creat()"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "test nfs_creat() for memory leaks (1) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_create "${TESTURL}/" "." /creat1 0750 >/dev/null 2>&1 || failure
success

echo -n "test nfs_creat() for memory leaks (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_create "${TESTURL}/" "." creat2 0750 >/dev/null 2>&1 || failure
success

echo -n "test nfs_creat() for memory leaks (3) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_create "${TESTURL}/" "." /subdir/creat3 0750 >/dev/null 2>&1 || failure
success

echo -n "test nfs_creat() for memory leaks (4) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_create "${TESTURL}/" "." subdir/creat4 0750 >/dev/null 2>&1 || failure
success

echo -n "test nfs_creat() for memory leaks (5) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_create "${TESTURL}/" "subdir" ../subdir2/creat5 0750 >/dev/null 2>&1 || failure
success

echo -n "test nfs_creat() for memory leaks (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_create "${TESTURL}/" "subdir" ../../subdir2/creat6 0750 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
