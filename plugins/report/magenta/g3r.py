#!/usr/bin/env python3
"""g3r — golismero3 reporter entrypoint for magenta.

Contract (see docs/superpowers/specs/2026-05-16-reporter-plugins-design.md):
  stdin   : JSONL stream. Line 1 is the G3ScanMetadata object
            (src/g3lib/redis.go: G3ScanMetadata). Its optional `config`
            sub-object mirrors magenta's metadata schema *exactly* (title,
            language, min_severity, severity_colors, project_info, ...), so we
            extract it verbatim and hand it to magenta via `-m`. The remaining
            lines (issues + other G3Data) are NOT read here — magenta walks
            /input on disk through its own parsers — so once line 1 is read we
            repoint stdin to /dev/null. That EPIPEs the worker's pipe writer and
            stops it streaming MongoDB results we would never consume.
  /input  : ro — full scan tree. magenta's process_files() does os.walk(/input)
            and matches each file by tool prefix (nmap.*, testssl.*, etc.).
            Our tool plugins already write artifacts under that convention.
  /output : rw — this reporter task's slot. We drop report.md here; g3api
            enumerates the slot and serves the result (paired with the
            manifest.json the worker writes after we exit).
  exit 0  : success.
  exit !0 : failure — worker marks task ERROR, slot kept for diagnostics.
"""

import json
import os
import sys
import tempfile

INPUT_DIR = "/input"
OUTPUT_FILE = "/output/report.md"
MAGENTA = "/app/magenta/magenta.py"


def read_metadata():
    """Read line 1 of stdin — the G3ScanMetadata header — and return it parsed.

    The worker always streams this object first, so a missing or malformed
    header is a contract violation: we surface it (non-zero exit) rather than
    silently fall through to a config-less report that looks fine but isn't.
    A header that simply omits `config` is legitimate, not an error.
    """
    line = sys.stdin.readline()
    if not line.strip():
        sys.exit("g3r: expected G3ScanMetadata on stdin line 1, got empty stream")
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        sys.exit("g3r: malformed G3ScanMetadata header on stdin: %s" % exc)


def main():
    metadata = read_metadata()

    # Repoint stdin to /dev/null so the worker's pipe writer hits EPIPE on its
    # next encode and stops streaming results magenta never reads from stdin.
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)

    argv = ["python3", MAGENTA, "report", INPUT_DIR, "-o", OUTPUT_FILE]

    # G3ScanMetadata.config (optional) is, by construction, exactly magenta's
    # -m/--metadata schema. When present, materialize it to a temp file and pass
    # it through; absent config means magenta uses its built-in DEFAULT_METADATA.
    config = metadata.get("config")
    if config is not None:
        fd, path = tempfile.mkstemp(suffix=".json", prefix="g3r-metadata-")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        argv += ["-m", path]

    # Hand off to magenta; exec replaces this process so magenta's exit code
    # becomes the task's exit code directly (exit !0 -> worker marks ERROR).
    os.execvp("python3", argv)


if __name__ == "__main__":
    main()
