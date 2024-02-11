#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Basic valgrind check of timeout handling."

start_share

touch "${TESTDIR}/testfile"
for IDX in `seq 1 28`; do
    echo -n "Test memory leaks at socket event ${IDX} ... "
    TIMEOUT_START=${IDX} LD_PRELOAD=./ld_timeout.so libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_timeout "${TESTURL}/testfile?version=${VERS}" >/dev/null 2>&1 || failure
    success
done

stop_share

exit 0
