#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} nfs_truncate() path tests."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "test nfs_truncate() for a root file (abs) (1)... "
touch "${TESTDIR}/trunc1"
./prog_truncate "${TESTURL}/?version=${VERS}" "." /trunc1 2027 >/dev/null || failure
success

echo -n "test nfs_truncate() for a root file (rel) (2)... "
./prog_truncate "${TESTURL}/?version=${VERS}" "." trunc1 2028 >/dev/null || failure
success

echo -n "test nfs_truncate() for a subdir file (abs) (3)... "
touch "${TESTDIR}/subdir/trunc3"
./prog_truncate "${TESTURL}/?version=${VERS}" "." /subdir/trunc3 2029 >/dev/null || failure
success

echo -n "test nfs_truncate() for a subdir file (rel) (4)... "
./prog_truncate "${TESTURL}/?version=${VERS}" "." subdir/trunc3 2030 >/dev/null || failure
success

echo -n "test nfs_truncate() from a different cwd (rel) (5)... "
./prog_truncate "${TESTURL}/?version=${VERS}" "subdir2" ../subdir/trunc3 2031 >/dev/null || failure
success

echo -n "test nfs_truncate() outside the share (rel) (6)... "
./prog_truncate "${TESTURL}/?version=${VERS}" "subdir2" ../../subdir/trunc3 2032 >/dev/null 2>&1 && failure
success

echo -n "test nfs_truncate() when target is a symlink (7)... "
touch "${TESTDIR}/trunc7"
ln -s trunc7 "${TESTDIR}/symlink7"
./prog_truncate "${TESTURL}/?version=${VERS}" "." symlink7 2033 || failure
success

stop_share

exit 0
