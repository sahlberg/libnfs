#!/bin/sh

. ./functions.sh

echo "test we can build libnfs as an rpm"

[ -f "/etc/redhat-release" ] || {
    echo "SKIPPED. This is not a red-hat based system"
}

echo -n "try building rpm packages ... "
../packaging/RPM/makerpms.sh >/dev/null 2>&1 || failure

success

exit 0
