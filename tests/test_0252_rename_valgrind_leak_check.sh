#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind leak check for nfs_rename()."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"


echo -n "test nfs_rename() (1) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." /testfile /renamed1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (2) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." testfile /renamed2 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (3) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." testfile renamed3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (4) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." /testfile renamed4 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (5) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." /subdir/testfile /subdir/renamed5 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (6) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." subdir/testfile /subdir/renamed6 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (7) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." subdir/testfile subdir/renamed7 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (8) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." /subdir/testfile subdir/renamed8 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (9) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "." /subdir/testfile subdir2/renamed9 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (10) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/?version=${VERS}" "subdir" ./testfile ../subdir2/renamed10 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() (11) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rename "${TESTURL}/?version=${VERS}" "subdir" ../../testfile ../subdir2/renamed11 >/dev/null 2>&1 || expr $? != 99 >/dev/null || failure
success

echo -n "test nfs_rename() (12) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rename "${TESTURL}/?version=${VERS}" "subdir" ./testfile ../../subdir2/renamed12 >/dev/null 2>&1 || expr $? != 99 >/dev/null || failure
success


stop_share

exit 0
