#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic symlink test."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Create a symlink in root (abs) (1) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "." kangabanga /symlink1 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/symlink1" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink in root (rel) (2) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "." kangabanga symlink2 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/symlink2" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink from a subdir (abs) (3) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "." kangabanga /subdir/symlink3 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/subdir/symlink3" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink from a subdir (rel) (4) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "." kangabanga subdir/symlink4 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/subdir/symlink4" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink from a subdir (rel) (5) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "/subdir" kangabanga symlink5 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/subdir/symlink5" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink in a parent directory (rel) (6) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "/subdir" kangabanga ../symlink6 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/symlink6" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink from different cwd (rel) (7) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "/subdir" kangabanga ../subdir2/symlink7 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/subdir2/symlink7" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink outside the share (rel) (8) ... "
./prog_symlink "${TESTURL}/?version=${VERS}" "/subdir" kangabanga ../../symlink8 2>/dev/null && failure
success

stop_share

exit 0
