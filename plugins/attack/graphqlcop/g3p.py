#!/usr/bin/python3
"""Golismero3 entrypoint wrapper for graphql-cop.

graphql-cop's ``-o json`` prints the JSON report to stdout, but it also prints
human status lines ("...does not seem to be running GraphQL", "Running a forced
scan...") to the SAME stdout stream, unconditionally — there is no quiet flag and
``-o`` cannot target a file. So we run graphql-cop as a subprocess and split its
stdout by content into two artifacts:

  * /artifacts/graphqlcop.json — the pure JSON array (``[]`` when nothing found)
  * /artifacts/graphqlcop.txt  — the human status/error lines

The status lines and graphql-cop's own stderr are echoed to our stderr so
Golismero captures them as log lines. The worker unmarshals our stdout into
[]g3lib.G3Data, so we emit the artifact claim there as a JSON array. graphql-cop's
own exit code is preserved: 0 means it ran to completion (even with no findings or
a non-GraphQL target), non-zero is a genuine failure.
"""

import json
import os
import subprocess
import sys

ARTIFACTS_DIR = "/artifacts"
JSON_ARTIFACT = "graphqlcop.json"
TXT_ARTIFACT = "graphqlcop.txt"


def split_output(stdout):
    """Split graphql-cop stdout into (json_array, status_lines).

    The JSON report is the first line that starts with '[' and parses as a JSON
    list; every other line is treated as human status text. Content-based, not
    positional: on a crash graphql-cop never prints the JSON line, so a "last
    line" heuristic would mislabel status text as JSON.
    """
    data = None
    status_lines = []
    for line in stdout.splitlines():
        if data is None and line.startswith("["):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                data = parsed
                continue
        status_lines.append(line)
    if data is None:
        data = []
    return data, status_lines


def main():
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    # Always emit JSON; per-target args (-t <url>) arrive via the .g3p command.
    # cwd=/app because graphql-cop.py imports config/version/lib relative to it.
    proc = subprocess.run(
        ["python3", "/app/graphql-cop.py", "-o", "json", *sys.argv[1:]],
        cwd="/app",
        capture_output=True,
        text=True,
    )

    data, status_lines = split_output(proc.stdout)

    with open(os.path.join(ARTIFACTS_DIR, JSON_ARTIFACT), "w") as f:
        json.dump(data, f)

    with open(os.path.join(ARTIFACTS_DIR, TXT_ARTIFACT), "w") as f:
        for line in status_lines:
            f.write(line + "\n")

    # Surface status lines and the tool's stderr as Golismero log lines.
    for line in status_lines:
        print(line, file=sys.stderr)
    if proc.stderr:
        sys.stderr.write(proc.stderr)

    # The worker reads stdout as a JSON array of G3Data; declare the artifacts.
    json.dump([{"_artifacts": [JSON_ARTIFACT, TXT_ARTIFACT]}], sys.stdout)
    sys.stdout.write("\n")

    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
