#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic nfs_unlink() test."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Unlink a file from the root (abs) (1)... "
touch "${TESTDIR}/unlink"
./prog_unlink "${TESTURL}/?version=${VERS}" "." /unlink || failure
success

echo -n "Verify the file is gone ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." unlink 2>/dev/null && failure
success

echo -n "Unlink a file from the root (rel) (2)... "
touch "${TESTDIR}/unlink"
./prog_unlink "${TESTURL}/?version=${VERS}" "." unlink || failure
success

echo -n "Unlink a file from a subdir (abs) (3)... "
touch "${TESTDIR}/subdir/unlink"
./prog_unlink "${TESTURL}/?version=${VERS}" "." /subdir/unlink || failure
success

echo -n "Unlink a file from a subdir (rel) (4)... "
touch "${TESTDIR}/subdir/unlink"
./prog_unlink "${TESTURL}/?version=${VERS}" "." subdir/unlink || failure
success

echo -n "Unlink a file from a different dir (rel) (5)... "
touch "${TESTDIR}/subdir2/unlink"
./prog_unlink "${TESTURL}/?version=${VERS}" "subdir" ../subdir2/unlink || failure
success

echo -n "Unlink a file from outside the share (rel) (6)... "
./prog_unlink "${TESTURL}/?version=${VERS}" "subdir" ../../subdir2/unlink 2>/dev/null && failure
success

stop_share

exit 0
