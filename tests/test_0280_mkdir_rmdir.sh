#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic mkdir/rmdir tests."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "test nfs_mkdir2() for a root directory (abs) (1) ... "
./prog_mkdir "${TESTURL}/?version=${VERS}" "." /testdir || failure
success

echo -n "Stat the new directory ... "
./prog_stat "${TESTURL}/?version=${VERS}" "." testdir > "${TESTDIR}/output" || failure
success

echo -n "Verifying it is a directory ... "
grep "nfs_mode:40" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Remove a root directory (abs) (2) ... "
./prog_rmdir "${TESTURL}/" "." /testdir 2>/dev/null || failure
success

echo -n "test nfs_mkdir2() for a root directory (rel) (3) ... "
./prog_mkdir "${TESTURL}/?version=${VERS}" "." testdir 2>/dev/null || failure
success

echo -n "Remove a root directory (rel) (4) ... "
./prog_rmdir "${TESTURL}/" "." testdir 2>/dev/null || failure
success

echo -n "test nfs_mkdir2() in a subdirectory (abs) (5) ... "
./prog_mkdir "${TESTURL}/?version=${VERS}" "." /subdir/testdir 2>/dev/null || failure
success

echo -n "Remove a directory from a subdirectory (abs) (6) ... "
./prog_rmdir "${TESTURL}/" "." /subdir/testdir 2>/dev/null || failure
success

echo -n "test nfs_mkdir2() in a subdirectory (rel) (7) ... "
./prog_mkdir "${TESTURL}/?version=${VERS}" "." subdir/testdir 2>/dev/null || failure
success

echo -n "Remove a directory from a subdirectory (rel) (8) ... "
./prog_rmdir "${TESTURL}/" "." subdir/testdir 2>/dev/null || failure
success

echo -n "test nfs_mkdir2() from a different cwd (rel) (9) ... "
./prog_mkdir "${TESTURL}/?version=${VERS}" "subdir" ../subdir2/testdir 2>/dev/null || failure
success

echo -n "Remove a directory from a subdirectory (rel) (10) ... "
./prog_rmdir "${TESTURL}/" "." subdir2/testdir 2>/dev/null || failure
success

echo -n "test nfs_mkdir2() outside of the share (rel) (11) ... "
./prog_mkdir "${TESTURL}/?version=${VERS}" "subdir" ../subdir2/../../testdir 2>/dev/null && failure
success

echo -n "Remove a directory outside of the share (rel) (12) ... "
./prog_rmdir "${TESTURL}/" "subdir" ../subdir2/../../testdir 2>/dev/null && failure
success

echo -n "test nfs_mkdir2() on an existing dir (rel) (13) ... "
./prog_mkdir "${TESTURL}/?version=${VERS}" "subdir" 2>/dev/null ../subdir2 && failure
success

echo -n "Remove a directory that does not exist (rel) (14) ... "
./prog_rmdir "${TESTURL}/" "subdir" ../subdir3 2>/dev/null && failure
success

stop_share

exit 0

