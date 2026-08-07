#!/bin/sh
set -e
g3="[`cat`]"
set -o pipefail
rc=0
shcheck.py -A -d -r -j -o /artifacts/shcheck.json "$@" | tee /artifacts/shcheck.txt 1>&2 || rc=$?
echo $g3
exit $rc
