#!/bin/sh

. ./functions.sh

echo "nfs_lstat64() path tests"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Test nfs_lstat64() for a root file (abs) (1)... "
ln -s foo "${TESTDIR}/stat1"
./prog_lstat "${TESTURL}/" "." /stat1 >/dev/null || failure
success

echo -n "Test nfs_lstat64() for a root file (rel) (2)... "
./prog_lstat "${TESTURL}/" "." stat1 >/dev/null || failure
success

echo -n "Test nfs_lstat64() for a subdir file (abs) (3)... "
ln -s foo "${TESTDIR}/subdir/stat3"
./prog_lstat "${TESTURL}/" "." /subdir/stat3 >/dev/null || failure
success

echo -n "Test nfs_lstat64() for a subdir file (rel) (4)... "
./prog_lstat "${TESTURL}/" "." subdir/stat3 >/dev/null || failure
success

echo -n "Test nfs_lstat64() from a different cwd (rel) (5)... "
./prog_lstat "${TESTURL}/" "subdir2" ../subdir/stat3 >/dev/null || failure
success

echo -n "Test nfs_lstat64() outside the share (rel) (6)... "
./prog_lstat "${TESTURL}/" "subdir2" ../../subdir/stat3 >/dev/null 2>&1 && failure
success

stop_share

exit 0
