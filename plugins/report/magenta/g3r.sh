#!/bin/sh
# /usr/bin/g3r — golismero3 reporter entrypoint for magenta.
#
# Contract (see docs/superpowers/specs/2026-05-16-reporter-plugins-design.md):
#   stdin   : JSONL stream (G3Report header + deduped issues + remaining data).
#             Currently unused — magenta walks /input on disk via its own parsers.
#             The worker still streams it but our closed stdin makes the writer
#             EPIPE quickly and stop.
#   /input  : ro — full scan tree. magenta's process_files() does os.walk(/input)
#             and matches each file by tool prefix (nmap.*, testssl.*, etc.).
#             Our tool plugins already write artifacts under that convention, so
#             no path manipulation is needed.
#   /output : rw — this reporter task's slot. We drop report.md here; g3api
#             enumerates the slot and serves the result (paired with the
#             manifest.json the worker writes after we exit, so the bundle ends
#             up as a small zip of {manifest.json, report.md}).
#   exit 0  : success.
#   exit !0 : failure — worker marks task ERROR, slot kept for diagnostics.
#
# First-draft scope (matches the in-process MarkdownReporter behavior):
# language, title, and other report metadata are not surfaced from the request
# yet. magenta's defaults (English, built-in templates) are used. Wire those
# through once the G3Report struct grows the corresponding fields.
set -e

# Close stdin so the worker's pipe writer hits EPIPE on its next encode and
# stops streaming MongoDB results we'll never read. Saves the work even
# though the spec allows lazy consumption.
exec </dev/null

exec python3 /app/magenta/magenta.py report /input -o /output/report.md
