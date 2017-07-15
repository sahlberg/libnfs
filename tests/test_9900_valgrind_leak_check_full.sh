#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind leak check."

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"


echo -n "Create 100 1M files ... "
for IDX in `seq 1 100`; do
    dd if=/dev/zero of="${TESTDIR}/file.$IDX" bs=1M count=10 2>/dev/null || failure
done
success

echo -n "Testing server discovery for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/nfs-ls -D nfs:// > "${TESTDIR}/output?version=${VERS}" 2>/dev/null || failure
success

echo -n "Testing share enumeration for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/nfs-ls -D nfs://127.0.0.1 > "${TESTDIR}/output?version=${VERS}" 2>/dev/null || failure
success

echo -n "test nfs-ls for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/nfs-ls "${TESTURL}?version=${VERS}" >/dev/null 2>&1 || failure
success

echo -n "test nfs-cp for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/nfs-cp "${TESTURL}/file.99?version=${VERS}" "${TESTURL}/copy-of-file.99" >/dev/null 2>&1 || failure
success

echo -n "test nfs_truncate() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../examples/nfs-io trunc "${TESTURL}/copy-of-file.99?version=${VERS}" >/dev/null 2>&1 || failure
success

echo -n "test nfs_unlink() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../examples/nfs-io unlink "${TESTURL}/copy-of-file.99?version=${VERS}" >/dev/null 2>&1 || failure
success

echo -n "test nfs_mkdir() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../examples/nfs-io mkdir "${TESTURL}/testdir?version=${VERS}" >/dev/null 2>&1 || failure
success

echo -n "test nfs_rmdir() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../examples/nfs-io rmdir "${TESTURL}/testdir?version=${VERS}" >/dev/null 2>&1 || failure
success

echo -n "test nfs_stat64() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_stat "${TESTURL}/?version=${VERS}" "." file.99 >/dev/null 2>&1 || failure
success

echo -n "test nfs_fstat64() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_fstat "${TESTURL}/?version=${VERS}" "." file.99 >/dev/null 2>&1 || failure
success


stop_share

exit 0
