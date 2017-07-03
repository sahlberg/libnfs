#!/bin/sh

. ./functions.sh

echo "basic timeout test"

start_share

touch "${TESTDIR}/testfile"
for IDX in `seq 1 28`; do
    echo -n "Test timeout at socket event ${IDX} ... "
    TIMEOUT_START=${IDX} LD_PRELOAD=./ld_timeout.so ./prog_stat "${TESTURL}/" "." testfile >/dev/null 2>&1 && failure
    success
done

stop_share

exit 0
