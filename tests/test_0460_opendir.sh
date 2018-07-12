#!/bin/sh
#
# NFS servers generally want us to be root in order to create device nodes.
# We can lie and impersonate root by setting uid=0 in the URL.

. ./functions.sh

echo "NFSv${VERS} Basic opendir test."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir/subdir2"
touch "${TESTDIR}/subdir/subdir2/file"

echo -n "Open '.' in the root directory (1)... "
./prog_opendir "${TESTURL}/?uid=0&version=${VERS}" "." "." > "${TESTDIR}/output" || failure
success

echo -n "Check the directory listing ... "
grep "^subdir$" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Open a subdir in the root directory (2)... "
./prog_opendir "${TESTURL}/?uid=0&version=${VERS}" "." "subdir" > "${TESTDIR}/output" || failure
success

echo -n "Check the directory listing ... "
grep "^subdir2$" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Open '.' in a subdir (3)... "
./prog_opendir "${TESTURL}/?uid=0&version=${VERS}" "subdir" "." > "${TESTDIR}/output" || failure
success

echo -n "Check the directory listing ... "
grep "^subdir2$" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Open 'subdir2' in a subdir (4)... "
./prog_opendir "${TESTURL}/?uid=0&version=${VERS}" "subdir" "subdir2" > "${TESTDIR}/output" || failure
success

echo -n "Check the directory listing ... "
grep "^file$" "${TESTDIR}/output" >/dev/null || failure
success

echo -n "Open '..' in a subdir (5)... "
./prog_opendir "${TESTURL}/?uid=0&version=${VERS}" "subdir/subdir2" ".." > "${TESTDIR}/output" || failure
success

echo -n "Check the directory listing ... "
grep "^subdir2$" "${TESTDIR}/output" >/dev/null || failure
success

stop_share

exit 0
