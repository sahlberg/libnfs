#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic nfs_statvfs() tests."

start_share

# check how big the local filesystem is and convert to 4kb blocks
BLOCKS=`df -k . | tail -1 | cut -d ' ' -f 2`
BLOCKS=`expr "$BLOCKS" "/" "4"`

echo -n "test nfs_statvfs() ... "
./prog_statvfs "${TESTURL}/?version=${VERS}" "." / > "${TESTDIR}/output" || failure
success

echo -n "verify total number of blobs is correct ... "
grep "blocks:$BLOCKS" "${TESTDIR}/output" >/dev/null || failure
success


stop_share

exit 0
