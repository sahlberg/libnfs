#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} nfs4_stat64() tests."

if [ "${VERS}" = "3" ]; then
    echo "Not applicable to NFSv3. Skipping test"
    exit 0
fi

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null
chmod 644 "${TESTDIR}/testfile"

echo -n "test nfs4_stat64() ... "
./prog_nfs4_stat "${TESTURL}/?version=${VERS}" "." /testfile > "${TESTDIR}/output" || failure
success

for OP in stat lstat fstat; do
    echo -n "test ${OP} uid/gid ... "
    grep "${OP}_uid:$UID" "${TESTDIR}/output" >/dev/null || failure
    grep "${OP}_gid:$GID" "${TESTDIR}/output" >/dev/null || failure
    success

    echo -n "test ${OP} utf8 user/group ... "
    grep "${OP}_user:" "${TESTDIR}/output" | grep -v "${OP}_user:$" >/dev/null || failure
    grep "${OP}_group:" "${TESTDIR}/output" | grep -v "${OP}_group:$" >/dev/null || failure
    success
done

echo -n "test nfs4_stat64() size ... "
grep "stat_size:32768" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test nfs4_stat64() on a missing file ... "
./prog_nfs4_stat "${TESTURL}/?version=${VERS}" "." /no-such-file >/dev/null 2>&1 && failure
success

stop_share

exit 0
