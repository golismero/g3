#!/bin/sh
set -e
# untangle exits 0 on success; a non-zero status is a real error. It reads
# behavior_repository.out from its current working directory, so run from there.
set -o pipefail
cd /opt/untangle
rc=0
python3 untangle.py -t "$1" | tee /artifacts/untangle.txt 1>&2 || rc=$?
# Pass the target host to the importer so it can reconstruct the url object;
# untangle's own output does not contain the hostname.
cat /artifacts/untangle.txt | python3 /usr/bin/g3i r "$1"
exit $rc
