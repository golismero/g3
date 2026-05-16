#!/bin/sh
set -e
nikto.pl -nointeractive -Format csv -o /artifacts/nikto.csv "$@" 1>&2
cat /artifacts/nikto.csv | /usr/bin/g3i "$@"
exit 0