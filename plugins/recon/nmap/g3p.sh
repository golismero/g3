#!/bin/sh
set -e
jsonfile=`cat`
nmap -oX /artifacts/nmap.xml "$@" | tee /artifacts/nmap.txt 1>&2
cat /artifacts/nmap.xml | /usr/bin/g3i "$jsonfile"
exit 0