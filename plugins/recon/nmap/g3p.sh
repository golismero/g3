#!/bin/sh
set -e
jsonfile=`cat`
# Recover nmap's real exit status through the tee pipe (pipefail) without
# aborting — the importer must still run so any partial results reach the
# scanner. nmap exits 0 even when the host is down / no ports are open, so a
# non-zero status here is a genuine nmap failure, not "found nothing".
set -o pipefail
rc=0
nmap -oX /artifacts/nmap.xml "$@" | tee /artifacts/nmap.txt 1>&2 || rc=$?
cat /artifacts/nmap.xml | /usr/bin/g3i "$jsonfile"
exit $rc
