#!/bin/sh
set -e
#cat /root/.config/subfinder/config.yaml 1>&2
#cat /root/.config/subfinder/provider-config.yaml 1>&2
# Recover subfinder's real exit status through the tee pipe. subfinder exits 0
# even when zero subdomains are found, so a non-zero status here is a real error.
set -o pipefail
rc=0
subfinder -v -oJ -o /artifacts/subfinder.json -d "$1" | tee /artifacts/subfinder.txt 1>&2 || rc=$?
cat /artifacts/subfinder.json | /usr/bin/g3i r
exit $rc
