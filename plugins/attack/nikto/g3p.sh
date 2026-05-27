#!/bin/sh
set -e
set -o pipefail
# Nikto 2.6.0 treats -o as a base name and appends ".<format>", so
# "-o /artifacts/nikto" produces /artifacts/nikto.csv (older Nikto wrote the -o
# path literally — hence the previous /artifacts/nikto.csv.csv mismatch).
# Capture nikto's real exit status without aborting: it exits 0 on a completed
# scan even with request errors, so a non-zero status is a genuine failure.
# tee the console output to /artifacts/nikto.txt (artifact) and stderr (logs).
# The importer still runs on any partial output; a missing CSV makes the cat
# pipeline fail (pipefail) so the failure reaches the worker instead of being
# silently reported as an empty scan.
rc=0
nikto.pl -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36" -nointeractive -Display V -Save /artifacts -Format csv -o /artifacts/nikto "$@" | tee /artifacts/nikto.txt 1>&2 || rc=$?
cat /artifacts/nikto.csv | /usr/bin/g3i "$@"
exit $rc
