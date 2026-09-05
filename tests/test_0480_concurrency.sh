#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Deep async request pipelining."

start_share

echo -n "Create a 16M file ... "
dd if=/dev/urandom of="${TESTDIR}/testfile" bs=1M count=16 2>/dev/null || failure
success

# 1000 is far more than the slot table an NFSv4.2 session is granted, so this
# only passes if requests that cannot get a slot wait for one instead of
# failing, and if a slot is never used by two requests at the same time.
echo -n "1000 concurrent reads all complete ... "
./prog_concurrent "${TESTURL}/?version=${VERS}" "." /testfile 1000 4096 > "${TESTDIR}/output" || failure
success

echo -n "Verifying every read was answered ... "
grep "All 1000 reads completed" "${TESTDIR}/output" >/dev/null || failure
success

stop_share

exit 0
