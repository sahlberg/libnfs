#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic nfs_fstat64() test."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "test nfs_fstat64() for a root file (abs) (1)... "
touch "${TESTDIR}/fstat1"
./prog_fstat "${TESTURL}/?version=${VERS}" "." /fstat1 >/dev/null || failure
success

echo -n "test nfs_fstat64() for a root file (rel) (2)... "
./prog_fstat "${TESTURL}/?version=${VERS}" "." fstat1 >/dev/null || failure
success

echo -n "test nfs_fstat64() for a subdir file (abs) (3)... "
touch "${TESTDIR}/subdir/fstat3"
./prog_fstat "${TESTURL}/?version=${VERS}" "." /subdir/fstat3 >/dev/null || failure
success

echo -n "test nfs_fstat64() for a subdir file (rel) (4)... "
./prog_fstat "${TESTURL}/?version=${VERS}" "." subdir/fstat3 >/dev/null || failure
success

echo -n "test nfs_fstat64() from a different cwd (rel) (5)... "
./prog_fstat "${TESTURL}/?version=${VERS}" "subdir2" ../subdir/fstat3 >/dev/null || failure
success

echo -n "test nfs_fstat64() outside the share (rel) (6)... "
./prog_fstat "${TESTURL}/?version=${VERS}" "subdir2" ../../subdir/fstat3 >/dev/null 2>&1 && failure
success

stop_share

exit 0
