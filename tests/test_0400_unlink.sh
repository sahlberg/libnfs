#!/bin/sh

. ./functions.sh

echo "basic creat/unlink test"

start_share

echo -n "Create a file ... "
../examples/nfs-io create "${TESTURL}/testfile" >/dev/null || failure
success

echo -n "Stat the new file ... "
./prog_stat "${TESTURL}/testfile" > "${TESTDIR}/output" || failure
success

echo -n "Verifying it is a regular file ... "
grep "nfs_mode:10" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Unlink the file ... "
../examples/nfs-io unlink "${TESTURL}/testfile" >/dev/null || failure
success

echo -n "Verify the file is gone file ... "
./prog_stat "${TESTURL}/testfile" 2>/dev/null && failure
success

stop_share

exit 0
