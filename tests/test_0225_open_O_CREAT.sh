#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Open(O_CREAT) test."

start_share

echo -n "test open(O_RDWR|O_CREAT) (1) ... "
./prog_open_write "${TESTURL}/?version=${VERS}" "." /create1 O_WRONLY,O_CREAT LordOfCinder >/dev/null || failure
success

echo -n "Verify the file content ... "
grep LordOfCinder "${TESTDIR}/create1" >/dev/null || failure
success

stop_share

exit 0
