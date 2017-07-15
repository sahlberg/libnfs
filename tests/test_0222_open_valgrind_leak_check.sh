#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind leak check for nfs_open()."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"


echo -n "test nfs_open() (1) ... "
echo -n "kangabanga" > "${TESTDIR}/open1"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_open_read "${TESTURL}/?version=${VERS}" "." /open1 O_RDONLY >/dev/null 2>&1 || failure
success

echo -n "test nfs_open() (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_open_read "${TESTURL}/?version=${VERS}" "." open1 O_RDONLY >/dev/null 2>&1 || failure
success

echo -n "test nfs_open() (3) ... "
echo -n "kangabanga" > "${TESTDIR}/subdir/open3"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_open_read "${TESTURL}/?version=${VERS}" "." /subdir/open3 O_RDONLY >/dev/null 2>&1 || failure
success

echo -n "test nfs_open() (4) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_open_read "${TESTURL}/?version=${VERS}" "." subdir/open3 O_RDONLY >/dev/null 2>&1 || failure
success

echo -n "test nfs_open() (5) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_open_read "${TESTURL}/?version=${VERS}" "subdir2" ../subdir/open3 O_RDONLY >/dev/null 2>&1 || failure
success

echo -n "test nfs_open() (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_open_read "${TESTURL}/?version=${VERS}" "subdir2" ../../subdir/open3 O_RDONLY 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
