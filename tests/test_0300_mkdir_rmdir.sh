#!/bin/sh

. ./functions.sh

echo "basic mkdir test"

start_share

echo -n "Create a directory ... "
../examples/nfs-io mkdir "${TESTURL}/dir" >/dev/null || failure
success

echo -n "Stat the new directory ... "
./prog_stat "${TESTURL}/dir" > "${TESTDIR}/output" || failure
success

echo -n "Verifying it is a directory ... "
grep "nfs_mode:40" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Remove the directory ... "
../examples/nfs-io rmdir "${TESTURL}/dir" >/dev/null || failure
success

stop_share

exit 0
