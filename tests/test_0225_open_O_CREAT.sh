#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Open(O_CREAT) test."

start_share

rm ${TESTDIR}/create1 >/dev/null 2>&1

echo -n "test open(O_RDWR|O_CREAT|O_EXCL) on a new file (1) ... "
./prog_open_write "${TESTURL}/?version=${VERS}" "." /create1 O_RDWR,O_CREAT,O_EXCL LordOfCinder >/dev/null || failure
success

echo -n "test open(O_RDWR|O_CREAT|O_EXCL) on an existing file (2) ... "
./prog_open_write "${TESTURL}/?version=${VERS}" "." /create1 O_RDWR,O_CREAT,O_EXCL LordOfCinder >/dev/null 2>&1 && failure
success

chmod 631 ${TESTDIR}/create1 >/dev/null 2>&1
echo -n "test open(O_RDWR|O_CREAT) on an existing file (3) ... "
./prog_open_write "${TESTURL}/?version=${VERS}" "." /create1 O_RDWR,O_CREAT LordOfCinder >/dev/null || failure
success

echo -n "verify it did not affect the mode bits (4) ... "
stat ${TESTDIR}/create1 | grep "0631/-rw--wx--x" >/dev/null || failure
success

echo -n "Verify the file content (5) ... "
grep LordOfCinder "${TESTDIR}/create1" >/dev/null || failure
success

echo "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" > ${TESTDIR}/create1
echo -n "test open(O_RDWR) on an existing file overwriting the start (6) ... "
./prog_open_write "${TESTURL}/?version=${VERS}" "." /create1 O_RDWR LordOfCinder >/dev/null || failure
success

echo -n "Verify the file content (7) ... "
grep LordOfCinderxxxxxxxxxxx "${TESTDIR}/create1" >/dev/null || failure
success

echo "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" > ${TESTDIR}/create1
echo -n "test open(O_RDWR,O_TRUNC) on an existing file (8) ... "
./prog_open_write "${TESTURL}/?version=${VERS}" "." /create1 O_WRONLY,O_TRUNC LordOfCinder >/dev/null || failure
success

echo -n "verify it got truncated (9) ... "
stat ${TESTDIR}/create1 | grep "Size: 12" >/dev/null || failure
success

stop_share

exit 0
