#!/bin/sh

. ./functions.sh

echo "discover shares test"

start_share

echo -n "Testing nfs-ls to discover shares on a server ... "
../utils/nfs-ls -D nfs://127.0.0.1 > "${TESTDIR}/output" || failure
grep "${TESTURL}" "${TESTDIR}/output" > /dev/null || failure
success

stop_share

exit 0
