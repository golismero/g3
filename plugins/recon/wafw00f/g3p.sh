#!/bin/sh
jsonfile=`mktemp --suffix=.json` || exit 1
wafw00f -a -o "$jsonfile" "$1" 1>&2
cat "$jsonfile" | /usr/bin/g3i
rm "$jsonfile"
exit 0