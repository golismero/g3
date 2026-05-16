#!/bin/sh
set -e
"$@" > /artifacts/dig.txt
cat /artifacts/dig.txt 1>&2
cat /artifacts/dig.txt | /usr/bin/g3i r
exit 0