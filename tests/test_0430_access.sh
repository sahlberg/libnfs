#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic access tests."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null
# Not root: with no_root_squash the server lets root read and write anything.
# Use the owner of the build tree, who can reach the share.
USR=$(stat -c %u .)
GRP=$(stat -c %g .)
sudo chown "${USR}:${GRP}" "${TESTDIR}/testfile"

echo -n "test access(R_OK) on a readable file ... "
chmod 400 "${TESTDIR}/testfile"
./prog_access "${TESTURL}/?uid=${USR}&gid=${GRP}&version=${VERS}" "." /testfile R_OK || failure
success

echo -n "test access(W_OK) on a writeable file ... "
chmod 200 "${TESTDIR}/testfile"
./prog_access "${TESTURL}/?uid=${USR}&gid=${GRP}&version=${VERS}" "." /testfile W_OK || failure
success

echo -n "test access(X_OK) on an executable file ... "
chmod 100 "${TESTDIR}/testfile"
./prog_access "${TESTURL}/?uid=${USR}&gid=${GRP}&version=${VERS}" "." /testfile X_OK || failure
success

echo -n "test access(R_OK) on a non-readable file ... "
chmod 300 "${TESTDIR}/testfile"
./prog_access "${TESTURL}/?uid=${USR}&gid=${GRP}&version=${VERS}" "." /testfile R_OK 2>/dev/null && failure
success

echo -n "test access(W_OK) on a non-writeable file ... "
chmod 500 "${TESTDIR}/testfile"
./prog_access "${TESTURL}/?uid=${USR}&gid=${GRP}&version=${VERS}" "." /testfile W_OK 2>/dev/null && failure
success

echo -n "test access(X_OK) on a non-executable file ... "
chmod 600 "${TESTDIR}/testfile"
./prog_access "${TESTURL}/?uid=${USR}&gid=${GRP}&version=${VERS}" "." /testfile X_OK 2>/dev/null && failure
success


stop_share

exit 0
