#!/bin/sh

. ./functions.sh

echo "basic ls test"

start_share

echo -n "Testing nfs-ls on root of export ... "
../utils/nfs-ls "${TESTURL}" > /dev/null || failure
success

echo -n "Create a file and verify nfs-ls can see it ... "
touch "${TESTDIR}/testfile"
../utils/nfs-ls "${TESTURL}" > "${TESTDIR}/output" || failure
grep testfile "${TESTDIR}/output" > /dev/null || failure
success

stop_share

exit 0
