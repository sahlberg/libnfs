#!/bin/sh

. ./functions.sh

echo "basic test that read updates offset but pread does not"

start_share

echo -n "Create a 12byte file ... "
dd if=/dev/urandom of="${TESTDIR}/file" bs=1 count=12 2>/dev/null || failure
success

echo -n "Verify how offset is updated "
./prog_read_update_pos "${TESTURL}/file" >/dev/null || failure
success

stop_share

exit 0
