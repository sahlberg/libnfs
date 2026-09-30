#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} nfs-stat utility tests."

start_share

dd if=/dev/zero of=testdata/testfile count=1 bs=32768 2>/dev/null
chmod 644 "${TESTDIR}/testfile"

echo -n "test nfs-stat with an unknown option fails ... "
../utils/nfs-stat --no-such-option "${TESTURL}/testfile?version=${VERS}" >/dev/null 2>&1 && failure
success

echo -n "test nfs-stat ... "
../utils/nfs-stat "${TESTURL}/testfile?version=${VERS}" > "${TESTDIR}/output" || failure
grep "Size: 32768 " "${TESTDIR}/output" >/dev/null || failure
grep "Access: (0644/-rw-r--r--)" "${TESTDIR}/output" >/dev/null || failure
success

if [ "${VERS}" = "3" ]; then
    echo -n "test nfs-stat uid/gid ... "
    grep -F "Uid: ( `stat -c %u "${TESTDIR}/testfile"`/" "${TESTDIR}/output" >/dev/null || failure
    grep -F "Gid: ( `stat -c %g "${TESTDIR}/testfile"`/" "${TESTDIR}/output" >/dev/null || failure
    success

    echo -n "test nfs-stat --utf8-ids is refused for NFSv3 ... "
    ../utils/nfs-stat --utf8-ids "${TESTURL}/testfile?version=${VERS}" > "${TESTDIR}/output" 2>&1 && failure
    grep "only supported for NFSv4" "${TESTDIR}/output" >/dev/null || failure
    success

    stop_share
    exit 0
fi

# Whether the server sends numeric ids or names depends on its idmap
# configuration, so compare against what nfs4_stat64() itself reports.
./prog_nfs4_stat "${TESTURL}/?version=${VERS}" "." /testfile > "${TESTDIR}/nfs4_stat" || failure
UID4=`sed -n 's/^stat_uid://p' "${TESTDIR}/nfs4_stat"`
GID4=`sed -n 's/^stat_gid://p' "${TESTDIR}/nfs4_stat"`
USER4=`sed -n 's/^stat_user://p' "${TESTDIR}/nfs4_stat"`
GROUP4=`sed -n 's/^stat_group://p' "${TESTDIR}/nfs4_stat"`

echo -n "test nfs-stat uid/gid ... "
grep -F "Uid: ( ${UID4}/" "${TESTDIR}/output" >/dev/null || failure
grep -F "Gid: ( ${GID4}/" "${TESTDIR}/output" >/dev/null || failure
success

for OPT in -u --utf8-ids; do
    echo -n "test nfs-stat ${OPT} ... "
    ../utils/nfs-stat ${OPT} "${TESTURL}/testfile?version=${VERS}" > "${TESTDIR}/output" || failure
    grep "Size: 32768 " "${TESTDIR}/output" >/dev/null || failure
    grep -F "Uid: ( ${UID4}/${USER4})" "${TESTDIR}/output" >/dev/null || failure
    grep -F "Gid: ( ${GID4}/${GROUP4})" "${TESTDIR}/output" >/dev/null || failure
    success
done

echo -n "test nfs-stat --utf8-ids on a missing file ... "
../utils/nfs-stat --utf8-ids "${TESTURL}/no-such-file?version=${VERS}" >/dev/null 2>&1 && failure
success

echo -n "test nfs-stat --utf8-ids valgrind leak check ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=99 ../utils/nfs-stat --utf8-ids "${TESTURL}/testfile?version=${VERS}" >/dev/null 2>&1 || failure
success

stop_share

exit 0
