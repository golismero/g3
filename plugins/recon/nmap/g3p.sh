#!/bin/sh
jsonfile=`cat` || exit 1
xmlfile=`mktemp` || exit 1
nmap -oX "$xmlfile" "$@" 1>&2
cat "$xmlfile" | /usr/bin/g3i "$jsonfile"
rm "$xmlfile"
exit 0