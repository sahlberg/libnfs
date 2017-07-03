#!/bin/sh

. ./functions.sh

echo "basic link test"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"
echo "kangabanga" > "${TESTDIR}/testfile"

echo -n "Link a root path (abs -> abs) (1) ... "
./prog_link "${TESTURL}/" "." /testfile /link1 || failure
success

echo -n "Link a root path (abs -> rel) (2) ... "
./prog_link "${TESTURL}/" "." /testfile link2 || failure
success

echo -n "Link a root path (rel -> abs) (3) ... "
./prog_link "${TESTURL}/" "." testfile /link3 || failure
success

echo -n "Link a root path (rel -> rel) (4) ... "
./prog_link "${TESTURL}/" "." testfile link4 || failure
success

echo -n "Link a subdir path (abs -> abs) (5) ... "
./prog_link "${TESTURL}/" "." /testfile /subdir/link5 || failure
success

echo -n "Link a subdir path (abs -> rel) (6) ... "
./prog_link "${TESTURL}/" "." /subdir/link5 subdir2/link6 || failure
success

echo -n "Link a subdir path (rel -> abs) (7) ... "
./prog_link "${TESTURL}/" "." subdir/link5 /subdir2/link7 || failure
success

echo -n "Link a subdir path (rel -> rel) (8) ... "
./prog_link "${TESTURL}/" "." subdir2/link7 subdir/link8 || failure
success

echo -n "Link from a different cwd (rel -> rel) (9) ... "
./prog_link "${TESTURL}/" "subdir2" link7 ../subdir/link9 || failure
success

echo -n "Link from outside the share (rel -> rel) (10) ... "
./prog_link "${TESTURL}/" "subdir2" ../../link7 ../subdir/link10 2>/dev/null && failure
success

echo -n "Link to outside the share (rel -> rel) (11) ... "
./prog_link "${TESTURL}/" "subdir2" link7 ../../subdir/link11 2>/dev/null && failure
success


stop_share

exit 0

