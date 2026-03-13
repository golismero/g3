#!/bin/sh
#cat /root/.config/subfinder/config.yaml 1>&2
#cat /root/.config/subfinder/provider-config.yaml 1>&2
jsonfile=`mktemp` || exit 1
subfinder -v -oJ -o "$jsonfile" -d "$1" 1>&2
cat "$jsonfile" | /usr/bin/g3i
rm "$jsonfile"
exit 0