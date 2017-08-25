#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic lseek test."

start_share

truncate -s 1024  "${TESTDIR}/testfile"

echo -n "test nfs_lseek() ... "
./prog_lseek "${TESTURL}/?version=${VERS}" "." /testfile > /dev/null || failure
success


stop_share

exit 0

