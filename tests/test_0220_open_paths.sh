#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic open path tests."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Open a file in root (abs) (1) ... "
echo -n "kangabanga" > "${TESTDIR}/open1"
./prog_open_read "${TESTURL}/?version=${VERS}" "." /open1 O_RDONLY >/dev/null || failure
success

echo -n "Open a file in root (rel) (2) ... "
./prog_open_read "${TESTURL}/?version=${VERS}" "." open1 O_RDONLY >/dev/null || failure
success

echo -n "Open a file in a subdir (abs) (3) ... "
echo -n "kangabanga" > "${TESTDIR}/subdir/open3"
./prog_open_read "${TESTURL}/?version=${VERS}" "." /subdir/open3 O_RDONLY >/dev/null || failure
success

echo -n "Open a file in root (rel) (4) ... "
./prog_open_read "${TESTURL}/?version=${VERS}" "." subdir/open3 O_RDONLY >/dev/null || failure
success

echo -n "Open a file from a different cwd (rel) (5) ... "
./prog_open_read "${TESTURL}/?version=${VERS}" "subdir2" ../subdir/open3 O_RDONLY >/dev/null || failure
success

echo -n "Open a file outside the share (rel) (5) ... "
./prog_open_read "${TESTURL}/?version=${VERS}" "subdir2" ../../subdir/open3 O_RDONLY >/dev/null 2>&1 && failure
success

echo -n "Create a directory symlink (rel) (6) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "." subdir /subdir4 || failure
success

echo -n "Open a file in a symlinked subdir (rel) (7) ... "
./prog_open_read "${TESTURL}/?version=${VERS}" "." subdir4/open3 O_RDONLY >/dev/null || failure
success

echo -n "Create a file symlink (rel) (8) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "." open3 /subdir4/open8 || failure
success

echo -n "Open a symlinked file (rel) (9) ... "
./prog_open_read "${TESTURL}/?version=${VERS}" "." subdir4/open8 O_RDONLY >/dev/null || failure
success

echo -n "Open a symlinked file with O_NOFOLLOW (rel) (10) ... "
./prog_open_read "${TESTURL}/?version=${VERS}" "." subdir/open8 O_RDONLY,O_NOFOLLOW 2>/dev/null && failure
success


stop_share

exit 0
