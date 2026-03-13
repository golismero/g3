#!/bin/sh
textfile=`mktemp` || exit 1
"$@" > "$textfile"
cat "$textfile" 1>&2
cat "$textfile" | /usr/bin/g3i
rm "$textfile"
exit 0