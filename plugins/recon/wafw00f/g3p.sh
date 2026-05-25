#!/bin/sh
set -e
# Recover wafw00f's real exit status through the tee pipe. wafw00f exits 0
# whether or not a WAF is detected; exit 1 is a real error (bad input, etc).
set -o pipefail
rc=0
wafw00f -a -o /artifacts/wafw00f.json "$1" | tee /artifacts/wafw00f.txt 1>&2 || rc=$?
cat /artifacts/wafw00f.json | python3 /usr/bin/g3i r
exit $rc
