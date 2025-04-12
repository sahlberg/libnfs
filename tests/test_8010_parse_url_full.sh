#!/bin/sh

. ./functions.sh

echo "URL Parsing tests."

echo -n "Parsing a url with a username ..."
./prog_parse_url_full "nfs://user@127.0.0.1/dir/file" "127.0.0.1" "0" "/dir" "/file" || failure
success
