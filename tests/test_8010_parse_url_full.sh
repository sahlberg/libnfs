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

echo -n "Parsing a url with a ':' in the path ..."
./prog_parse_url_full "nfs://127.0.0.1/dir/a:1.txt" "127.0.0.1" "0" "/dir" "/a:1.txt" || failure
success

echo -n "Parsing a url with escaped delimiters ..."
./prog_parse_url_full "nfs://127.0.0.1/d%20ir/a%3Fport%3D1%26b" "127.0.0.1" "0" "/d ir" "/a?port=1&b" || failure
success

echo -n "Parsing a url with an escaped NUL ..."
./prog_parse_url_full "nfs://127.0.0.1/dir/a%00b" "127.0.0.1" "0" "/dir" "/a" >/dev/null 2>&1 && failure || success
