#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} nfs_stat64() through absolute symlinks."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"
dd if=/dev/zero of="${TESTDIR}/subdir/testfile" count=1 bs=32768 2>/dev/null
ln -s "${TESTDIR}/subdir/testfile" "${TESTDIR}/subdir2/abslink"
ln -s "${TESTDIR}/subdir" "${TESTDIR}/subdir2/absdir"
ln -s / "${TESTDIR}/subdir2/outside"
INO=`stat --printf="%i" "${TESTDIR}/subdir/testfile"`

echo -n "test an absolute link to a file (1) ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." /subdir2/abslink > "${TESTDIR}/output" || failure
grep "nfs_ino:$INO$" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test an absolute link from another cwd (2) ... "
./prog_stat "${TESTURL}/?version=${VERS}" "/subdir" ../subdir2/abslink > "${TESTDIR}/output" || failure
grep "nfs_ino:$INO$" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test a file through an absolute link to a directory (3) ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." /subdir2/absdir/testfile > "${TESTDIR}/output" || failure
grep "nfs_ino:$INO$" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test an absolute link is not resolved from the link's directory (4) ... "
mkdir -p "${TESTDIR}/subdir2${TESTDIR}/subdir"
dd if=/dev/zero of="${TESTDIR}/subdir2${TESTDIR}/subdir/testfile" count=1 bs=512 2>/dev/null
./prog_stat "${TESTURL}/?version=${VERS}" "." /subdir2/abslink > "${TESTDIR}/output" || failure
grep "nfs_size:32768$" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "test an absolute link outside the share (5) ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." /subdir2/outside >/dev/null 2>&1 && failure
success

stop_share

exit 0
