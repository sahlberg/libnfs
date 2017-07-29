#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Open(O_TRUNC) test."

start_share

mkdir "${TESTDIR}/subdir"

echo -n "test open(O_WRONLY|O_TRUNC) (1) ... "
echo -n "kangabanga" > "${TESTDIR}/open1"
./prog_open_write "${TESTURL}/?version=${VERS}" "." /open1 O_WRONLY,O_TRUNC "" >/dev/null || failure
success

echo -n "verify the file got truncated ... "
expr `stat --printf="%s" "${TESTDIR}/open1"` "==" "0" >/dev/null || failure
success

echo -n "test open(O_RDONLY|O_TRUNC) (2) ... "
echo -n "kangabanga" > "${TESTDIR}/open1"
./prog_open_write "${TESTURL}/?version=${VERS}" "." /open1 O_RDONLY,O_TRUNC ""  >/dev/null || failure
success

echo -n "verify the file did not get truncated ... "
expr `stat --printf="%s" "${TESTDIR}/open1"` "==" "10" >/dev/null || failure
success

stop_share

exit 0
