#!/bin/sh

. ./functions.sh

echo "URL Parsing tests."

echo -n "Parsing a url with a username ..."
./prog_parse_url_full "nfs://user@127.0.0.1/dir/file" "127.0.0.1" "0" "/dir" "/file" || failure
success

echo -n "Parsing a url with a port number ..."
./prog_parse_url_full "nfs://user@127.0.0.1:8000/dir/file" "127.0.0.1" "8000" "/dir" "/file" || failure
success

echo -n "Parsing a url with invalid port numbers ..."
./prog_parse_url_full "nfs://user@127.0.0.1:-1/dir/file" "127.0.0.1" "-1" "/dir" "/file"  && failure || success
./prog_parse_url_full "nfs://user@127.0.0.1:65536/dir/file" "127.0.0.1" "65536" "/dir" "/file"  && failure || success
./prog_parse_url_full "nfs://user@127.0.0.1:invalid/dir/file" "127.0.0.1" "0" "/dir" "/file"  && failure || success
