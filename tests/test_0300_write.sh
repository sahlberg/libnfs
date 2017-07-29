#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic nfs_write() test."

start_share

echo -n "test writing to a file (1) ... "
touch "${TESTDIR}/open1"
./prog_open_write "${TESTURL}/?version=${VERS}" "." /open1 O_WRONLY "kangabanga" >/dev/null || failure
success

echo -n "verify the data is correct ... "
echo -n "kangabanga" > "${TESTDIR}/verify1"
diff "${TESTDIR}/verify1" "${TESTDIR}/open1" || failure
success

stop_share

exit 0
