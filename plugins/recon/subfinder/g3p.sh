#!/bin/sh
set -e
#cat /root/.config/subfinder/config.yaml 1>&2
#cat /root/.config/subfinder/provider-config.yaml 1>&2
subfinder -v -oJ -o /artifacts/subfinder.json -d "$1" | tee /artifacts/subfinder.txt 1>&2 
cat /artifacts/subfinder.json | /usr/bin/g3i r
exit 0