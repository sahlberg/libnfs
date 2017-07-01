#!/bin/sh

. ./functions.sh

echo "basic symlink test"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Create a symlink from a root path (absolute) ... "
./prog_symlink "${TESTURL}/" "." kangabanga /abslink || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/abslink" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink from a root path (relative) ... "
./prog_symlink "${TESTURL}/" "." kangabanga rellink || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/rellink" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink from a nested path (absolute) ... "
./prog_symlink "${TESTURL}/" "." kangabanga /subdir/abslink || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/subdir/abslink" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink from a nested path (relative) ... "
./prog_symlink "${TESTURL}/" "." kangabanga subdir/rellink || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/subdir/rellink" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink from a nested path (relative) ... "
./prog_symlink "${TESTURL}/" "/subdir" kangabanga locallink || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/subdir/locallink" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink in a parent directory (relative) ... "
./prog_symlink "${TESTURL}/" "/subdir" kangabanga ../link3 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/link3" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink in a different directory (relative) ... "
./prog_symlink "${TESTURL}/" "/subdir" kangabanga ../subdir2/link4 || failure
success

echo -n "Verify the link ... "
ls -l "${TESTDIR}/subdir2/link4" | egrep "\-> kangabanga$" >/dev/null || failure
success

echo -n "Create a symlink outside the share (relative) ... "
./prog_symlink "${TESTURL}/" "/subdir" kangabanga ../../link5 2>/dev/null && failure
success

stop_share

exit 0
