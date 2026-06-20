#!/bin/sh
set -e
# dig exits 0 on a successful query (including NXDOMAIN); a non-zero status is a
# genuine error (no reply from server, usage/internal error). Capture it through
# the tee pipe without aborting so the importer still runs on partial output,
# then report dig's real exit code so the worker can classify WARNING/ERROR.
set -o pipefail
rc=0
"$@" | tee /artifacts/dig.txt 1>&2 || rc=$?
/usr/bin/g3i r
exit $rc
