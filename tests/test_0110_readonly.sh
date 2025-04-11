#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic readonly test."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null

echo -n "test nfs_ftruncate() on readonly mount ... "
./prog_ftruncate "${TESTURL}/?version=${VERS}\&readonly" "." testfile 12377 2>/dev/null && failure
success

echo -n "test readonly ... "
./prog_readonly "${TESTURL}/?version=${VERS}\&readonly"
success

stop_share

exit 0
