#!/bin/sh

. ./functions.sh

echo "basic valgrind leak check"

start_share

mkdir "${TESTDIR}/subdir"
mkdir "${TESTDIR}/subdir2"

echo -n "Create 100 1M files ... "
for IDX in `seq 1 100`; do
    dd if=/dev/zero of="${TESTDIR}/file.$IDX" bs=1M count=10 2>/dev/null || failure
done
success

echo -n "Testing server discovery for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/nfs-ls -D nfs:// > "${TESTDIR}/output" 2>/dev/null || failure
success

echo -n "Testing share enumeration for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/nfs-ls -D nfs://127.0.0.1 > "${TESTDIR}/output" 2>/dev/null || failure
success

echo -n "test nfs-ls for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/nfs-ls "${TESTURL}" >/dev/null 2>&1 || failure
success

echo -n "test nfs-cp for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/nfs-cp "${TESTURL}/file.99" "${TESTURL}/copy-of-file.99" >/dev/null 2>&1 || failure
success

echo -n "test nfs_truncate() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../examples/nfs-io trunc "${TESTURL}/copy-of-file.99" >/dev/null 2>&1 || failure
success

echo -n "test nfs_unlink() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../examples/nfs-io unlink "${TESTURL}/copy-of-file.99" >/dev/null 2>&1 || failure
success

echo -n "test nfs_mkdir() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../examples/nfs-io mkdir "${TESTURL}/testdir" >/dev/null 2>&1 || failure
success

echo -n "test nfs_rmdir() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../examples/nfs-io rmdir "${TESTURL}/testdir" >/dev/null 2>&1 || failure
success

echo -n "test nfs_stat64() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_stat "${TESTURL}/file.99" >/dev/null 2>&1 || failure
success

echo -n "test nfs_fstat64() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_fstat "${TESTURL}/file.99" >/dev/null 2>&1 || failure
success

echo -n "test nfs_symlink()/nfs_readlink() for memory leaks ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_symlink "${TESTURL}/" "." kangabanga /symlink >/dev/null 2>&1 || failure
success

echo -n "test nfs_symlink()/nfs_readlink() for memory leaks (2) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_symlink "${TESTURL}/" "." kangabanga /subdir/symlink >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (1) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." /testfile /renamed1 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (2) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." testfile /renamed2 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (3) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." testfile renamed3 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (4) ... "
echo "kangabanga" > "${TESTDIR}/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." /testfile renamed4 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (5) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." /subdir/testfile /subdir/renamed5 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (6) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." subdir/testfile /subdir/renamed6 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (7) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." subdir/testfile subdir/renamed7 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (8) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." /subdir/testfile subdir/renamed8 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (9) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "." /subdir/testfile subdir2/renamed9 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (10) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_rename "${TESTURL}/" "subdir" ./testfile ../subdir2/renamed10 >/dev/null 2>&1 || failure
success

echo -n "test nfs_rename() for memory leaks (11) ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rename "${TESTURL}/" "subdir" ../../testfile ../subdir2/renamed11 >/dev/null 2>&1 || expr $? != 99 >/dev/null || failure
success

echo -n "test nfs_rename() for memory leaks (12) ... "
echo "kangabanga" > "${TESTDIR}/subdir/testfile"
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ./prog_rename "${TESTURL}/" "subdir" ./testfile ../../subdir2/renamed12 >/dev/null 2>&1 || expr $? != 99 >/dev/null || failure
success

stop_share

exit 0
