#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} NFSv4.2-only calls are refused on NFSv4.1."

if [ "${VERS}" != "4.1" ]; then
    echo "Skipping, this checks NFSv4.1 only."
    exit 0
fi

start_share

dd if=/dev/zero of="${TESTDIR}/testfile" count=1 bs=65536 2>/dev/null

echo -n "fallocate and SEEK_HOLE/SEEK_DATA fail with ENOTSUP ... "
./prog_nfs41_notsup "${TESTURL}/?version=${VERS}" "." /testfile > "${TESTDIR}/output" || failure
success

echo -n "the mount reports NFS_V4_1 ... "
grep "nfs_get_version() is NFS_V4_1" "${TESTDIR}/output" >/dev/null || failure
success

stop_share

exit 0
