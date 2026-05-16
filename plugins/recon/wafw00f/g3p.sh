#!/bin/sh
set -e
wafw00f -a -o /artifacts/wafw00f.json "$1" | tee /artifacts/wafw00f.txt 1>&2
cat /artifacts/wafw00f.json | python3 /usr/bin/g3i r
exit 0