#!/bin/sh

. ./functions.sh

echo "basic creat path tests"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Create a file in root (abs) (1) ... "
./prog_create "${TESTURL}/" "." /creat1 0750 || failure
success

echo -n "Stat the new file ... "
./prog_stat "${TESTURL}/" "." creat1 > "${TESTDIR}/output" || failure
success

echo -n "Verifying it is a regular file ... "
grep "nfs_mode:100750" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Remove the file ... "
./prog_unlink "${TESTURL}/" "." /creat1 || failure
success

echo -n "Create a file in root (rel) (2) ... "
./prog_create "${TESTURL}/" "." creat2 0750 || failure
success

echo -n "Create a file in subdirectory (abs) (3) ... "
./prog_create "${TESTURL}/" "." /subdir/creat3 0750 || failure
success

echo -n "Create a file in subdirectory (rel) (4) ... "
./prog_create "${TESTURL}/" "." subdir/creat4 0750 || failure
success

echo -n "Create a file from a different cwd (rel) (5) ... "
./prog_create "${TESTURL}/" "subdir" ../subdir2/creat5 0750 || failure
success

echo -n "Create a file outside the share (rel) (6) ... "
./prog_create "${TESTURL}/" "subdir" ../../subdir2/creat6 0750 2>/dev/null && failure
success


stop_share

exit 0
