#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} nfs_lstat64() path tests."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "test nfs_lstat64() for a root file (abs) (1)... "
ln -s foo "${TESTDIR}/stat1"
./prog_lstat "${TESTURL}/?version=${VERS}" "." /stat1 >/dev/null || failure
success

echo -n "test nfs_lstat64() for a root file (rel) (2)... "
./prog_lstat "${TESTURL}/?version=${VERS}" "." stat1 >/dev/null || failure
success

echo -n "test nfs_lstat64() for a subdir file (abs) (3)... "
ln -s foo "${TESTDIR}/subdir/stat3"
./prog_lstat "${TESTURL}/?version=${VERS}" "." /subdir/stat3 >/dev/null || failure
success

echo -n "test nfs_lstat64() for a subdir file (rel) (4)... "
./prog_lstat "${TESTURL}/?version=${VERS}" "." subdir/stat3 >/dev/null || failure
success

echo -n "test nfs_lstat64() from a different cwd (rel) (5)... "
./prog_lstat "${TESTURL}/?version=${VERS}" "subdir2" ../subdir/stat3 >/dev/null || failure
success

echo -n "test nfs_lstat64() outside the share (rel) (6)... "
./prog_lstat "${TESTURL}/?version=${VERS}" "subdir2" ../../subdir/stat3 >/dev/null 2>&1 && failure
success

echo -n "test nfs_lstat64() when target is a symlink (7)... "
touch "${TESTDIR}/stat7"
ln -s stat7 "${TESTDIR}/symlink7"
./prog_lstat "${TESTURL}/?version=${VERS}" "." symlink7 >"${TESTDIR}/output" || failure
success

echo -n "test nfs_lstat64() report it is a symlink ... "
grep "nfs_mode:120777" "${TESTDIR}/output" >/dev/null || failure
success


stop_share

exit 0
