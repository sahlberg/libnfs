#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic mount path test."

start_share

echo -n "test nfs_mount() normal share ... "
./prog_mount "${TESTURL}/?version=${VERS}" || failure
success

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir/subdir2"
ln -s subdir "${TESTDIR}/symlink1"

echo -n "test nfs_mount() following a link ... "
./prog_mount "${TESTURL}/symlink1/subdir2/?version=${VERS}" || failure
success

stop_share

exit 0
