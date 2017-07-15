#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic rename test."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Rename a root path (abs -> abs) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." /testfile /renamed1 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/renamed1" >/dev/null || failure
success

echo -n "Rename a root path (rel -> abs) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." testfile /renamed2 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/renamed2" >/dev/null || failure
success

echo -n "Rename a root path (rel -> rel) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." testfile renamed3 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/renamed3" >/dev/null || failure
success

echo -n "Rename a root path (abs -> rel) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." /testfile renamed4 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/renamed4" >/dev/null || failure
success



echo -n "Rename a subdir path (abs -> abs) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." /subdir/testfile /subdir/renamed5 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/subdir/renamed5" >/dev/null || failure
success

echo -n "Rename a subdir path (rel -> abs) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." subdir/testfile /subdir/renamed6 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/subdir/renamed6" >/dev/null || failure
success

echo -n "Rename a subdir path (rel -> rel) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." subdir/testfile subdir/renamed7 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/subdir/renamed7" >/dev/null || failure
success

echo -n "Rename a subdir path (abs -> rel) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." /subdir/testfile subdir/renamed8 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/subdir/renamed8" >/dev/null || failure
success

echo -n "Rename a subdir path to a different dir (rel -> rel) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "." /subdir/testfile subdir2/renamed9 || failure
success

echo -n "Verify the new path ... "
grep kangabanga "${TESTDIR}/subdir2/renamed9" >/dev/null || failure
success

echo -n "Rename from different cwd ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "subdir" ./testfile ../subdir2/renamed10 || failure
success

echo -n "Rename from outside share ... "
./prog_rename "${TESTURL}/?version=${VERS}" "subdir" ../../testfile ../subdir2/renamed11 2>/dev/null && failure
success

echo -n "Rename to outside share ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
./prog_rename "${TESTURL}/?version=${VERS}" "subdir" ./testfile ../../subdir2/renamed12 2>/dev/null && failure
success


stop_share

exit 0
