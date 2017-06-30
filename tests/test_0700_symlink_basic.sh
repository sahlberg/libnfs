#!/bin/sh

. ./functions.sh

echo "basic symlink test"

start_share

echo -n "Create a symlink from a root path (absolute) ... "
./prog_symlink "${TESTURL}/" kangabanga /symlink || failure
success

echo -n "Create a symlink from a nested path (absolute) ... "
mkdir "${TESTDIR}/subdir"
./prog_symlink "${TESTURL}/" kangabanga /subdir/symlink || failure
success

stop_share

exit 0
