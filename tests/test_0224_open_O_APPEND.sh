#!/bin/sh

. ./functions.sh

echo "NFSv${VERS} Open(O_APPEND) test."

start_share

mkdir "${TESTDIR}/subdir"

echo -n "test open(O_APPEND) (1) ... "
echo -n "GOAT:" > "${TESTDIR}/open1"
./prog_open_write "${TESTURL}/?version=${VERS}" "." /open1 O_WRONLY,O_APPEND "NieR" >/dev/null || failure
./prog_open_write "${TESTURL}/?version=${VERS}" "." /open1 O_WRONLY,O_APPEND "Automata" >/dev/null || failure
success

echo -n "verify it got appended ... "
grep "GOAT:NieRAutomata" "${TESTDIR}/open1" >/dev/null || failure
success

stop_share

exit 0
