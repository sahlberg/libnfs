#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind leak check for nfs_ftruncate()."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null

echo -n "test nfs_ftruncate() (1) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_ftruncate "${TESTURL}/?version=${VERS}" "." testfile 12377 >/dev/null 2>&1 || failure
success

stop_share

exit 0
