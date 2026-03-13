#!/bin/sh
csvfile=`mktemp` || exit 1
nikto.pl -nointeractive -Format csv -o "$csvfile" "$@" 1>&2
cat "$csvfile" | /usr/bin/g3i "$@"
rm "$csvfile"
exit 0