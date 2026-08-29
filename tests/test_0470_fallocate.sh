#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Sparse file tests (PUNCH_HOLE, ZERO_RANGE, SEEK_HOLE, SEEK_DATA)."

if [ "${VERS}" != "4.2" ]; then
    echo "Skipping, these are NFSv4.2 only operations."
    exit 0
fi

start_share

# A 4MB file of random data, so that a zeroed range is distinguishable from
# what was there before. 4MB is 8192 blocks of 512 bytes.
dd if=/dev/urandom of=${TESTDIR}/testfile count=4 bs=1M 2>/dev/null

# Checksum the regions that must survive, so the comparison afterwards is
# against what was there before and not against itself.
BEFORE_HEAD=`dd if=${TESTDIR}/testfile bs=1M count=1 2>/dev/null | md5sum`
BEFORE_TAIL=`dd if=${TESTDIR}/testfile bs=1M skip=2 count=2 2>/dev/null | md5sum`

echo -n "Zero a 1MB range at offset 1MB and verify it ... "
./prog_fallocate "${TESTURL}/?version=${VERS}" "." /testfile 1048576 1048576 zero > "${TESTDIR}/output" || failure
success

echo -n "Verifying ZERO_RANGE kept the blocks allocated ... "
# This is what separates ZERO_RANGE from PUNCH_HOLE: the range reads as
# zeroes but the space is still there.
ALLOCATED=`stat -c %b ${TESTDIR}/testfile`
if [ "${ALLOCATED}" -lt 8192 ]; then
    echo "file lost blocks, occupies only ${ALLOCATED} 512 byte blocks"
    failure
fi
success

echo -n "Verifying the data before the zeroed range is unchanged ... "
test "${BEFORE_HEAD}" = "`dd if=${TESTDIR}/testfile bs=1M count=1 2>/dev/null | md5sum`" || failure
success

echo -n "Verifying the data after the zeroed range is unchanged ... "
test "${BEFORE_TAIL}" = "`dd if=${TESTDIR}/testfile bs=1M skip=2 count=2 2>/dev/null | md5sum`" || failure
success

echo -n "Punch a 1MB hole at offset 1MB and verify it ... "
./prog_fallocate "${TESTURL}/?version=${VERS}" "." /testfile 1048576 1048576 punch > "${TESTDIR}/output" || failure
success

echo -n "Verifying PUNCH_HOLE made the file sparse ... "
ALLOCATED=`stat -c %b ${TESTDIR}/testfile`
if [ "${ALLOCATED}" -ge 8192 ]; then
    echo "file still occupies ${ALLOCATED} 512 byte blocks"
    failure
fi
success

echo -n "Verifying the data before the hole is unchanged ... "
test "${BEFORE_HEAD}" = "`dd if=${TESTDIR}/testfile bs=1M count=1 2>/dev/null | md5sum`" || failure
success

echo -n "Verifying the data after the hole is unchanged ... "
test "${BEFORE_TAIL}" = "`dd if=${TESTDIR}/testfile bs=1M skip=2 count=2 2>/dev/null | md5sum`" || failure
success

stop_share

exit 0
