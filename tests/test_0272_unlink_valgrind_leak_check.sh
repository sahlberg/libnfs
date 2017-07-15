#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind leak check for nfs_unlink()."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"


echo -n "test nfs_unlink() (1) ... "
touch "${TESTDIR}/unlink"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_unlink "${TESTURL}/?version=${VERS}" "."  /unlink 2>/dev/null || failure
success

echo -n "test nfs_unlink() (2) ... "
touch "${TESTDIR}/unlink"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_unlink "${TESTURL}/?version=${VERS}" "."  unlink 2>/dev/null || failure
success

echo -n "test nfs_unlink() (3) ... "
touch "${TESTDIR}/subdir/unlink"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_unlink "${TESTURL}/?version=${VERS}" "."  /subdir/unlink 2>/dev/null || failure
success

echo -n "test nfs_unlink() (4) ... "
touch "${TESTDIR}/subdir/unlink"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_unlink "${TESTURL}/?version=${VERS}" "."  subdir/unlink 2>/dev/null || failure
success

echo -n "test nfs_unlink() (5) ... "
touch "${TESTDIR}/subdir2/unlink"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_unlink "${TESTURL}/?version=${VERS}" "subdir"  ../subdir2/unlink 2>/dev/null || failure
success

echo -n "test nfs_unlink() (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_unlink "${TESTURL}/?version=${VERS}" "subdir"  ../../subdir2/unlink 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
