#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic chdir path test."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir/subdir2"
touch "${TESTDIR}/subdir/stat1"
ln -s subdir "${TESTDIR}/symlink1"

echo -n "Test nfs_stat64() from a different cwd (rel) (1)... "
./prog_stat "${TESTURL}/?version=${VERS}" "symlink1" stat1 >/dev/null || failure
success

stop_share

exit 0
