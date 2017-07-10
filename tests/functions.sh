TESTDIR=`pwd`/testdata
TESTSHARE="127.0.0.1:${TESTDIR}"
TESTURL="nfs://127.0.0.1${TESTDIR}"

# Which version of NFS to test for
VERS=${VERSION:-3}

start_share() {
    rm -rf "${TESTDIR}" 2>/dev/null
    mkdir "${TESTDIR}" 2>/dev/null
    sudo exportfs -o rw,insecure,no_root_squash "${TESTSHARE}"
}

stop_share() {
    sudo exportfs -u "${TESTSHARE}"
    rm -rf "${TESTDIR}"
}

success() {
    echo "[OK]"
}

failure() {
    echo "[FAILED]"
    exit 1
}

