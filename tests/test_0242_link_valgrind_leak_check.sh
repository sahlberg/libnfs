#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind leak check for nfs_link()."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"


echo "kangabanga" > "${TESTDIR}/testfile"
echo -n "test nfs_link() (1) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "." /testfile /link1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "." /testfile link2 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (3) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "." testfile /link3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (4) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "." testfile link4 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (5) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "." /testfile /subdir/link5 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (6) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "." /subdir/link5 subdir2/link6 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (7) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "." subdir/link5 /subdir2/link7 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (8) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "." subdir2/link7 /subdir/link8 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (9) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "subdir2" link7 ../subdir/link9 >/dev/null 2>&1 || failure
success

echo -n "test nfs_link() (10) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "subdir2" ../../link7 ../subdir/link10 2>/dev/null || expr $? != 99 >/dev/null || failure
success

echo -n "test nfs_link() (11) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_link "${TESTURL}/?version=${VERS}" "subdir2" link7 ../../subdir/link11 2>/dev/null || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
