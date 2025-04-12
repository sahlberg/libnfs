#!/bin/sh

. ./functions.sh

echo "URL Parsing valgrind leak check."

echo -n "Testing parse_url_full for memory leaks ..."
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_parse_url_full "nfs://user@127.0.0.1/dir/file" "127.0.0.1" "0" "/dir" "/file" || failure
success
