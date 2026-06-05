#!/bin/sh
set -e
set -o pipefail
# Nikto 2.6.0 treats -o as a base name and appends ".<format>", so
# "-o /artifacts/nikto" produces /artifacts/nikto.csv (older Nikto wrote the -o
# path literally — hence the previous /artifacts/nikto.csv.csv mismatch).
# Capture nikto's real exit status without aborting: it exits 0 on a completed
# scan even with request errors, so a non-zero status is a genuine failure.
# tee the console output to /artifacts/nikto.txt (artifact) and stderr (logs).
# Nikto is now purely an artifact generator: it emits no issues, only the two
# files it produced (the .txt console log and the .csv findings report). We
# declare them with a single nil-typed G3Data carrying an _artifacts claim
# (returns: "nil" in the .g3p — nikto adds no pipeline fuel). The worker
# unmarshals stdout into []g3lib.G3Data, so the output MUST be a JSON array,
# even for this single object — a bare object fails to parse.
rc=0
nikto.pl -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36" -nointeractive -Display V -Save /artifacts -Format csv -o /artifacts/nikto "$@" | tee /artifacts/nikto.txt 1>&2 || rc=$?
echo '[{"_artifacts":["nikto.txt", "nikto.csv"]}]'
exit $rc
