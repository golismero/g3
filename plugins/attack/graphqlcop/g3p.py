#!/usr/local/bin/python3
"""Golismero3 entrypoint wrapper for graphql-cop.

graphql-cop's ``-o json`` prints the JSON report to stdout, but it also prints
human status lines ("...does not seem to be running GraphQL", "Running a forced
scan...") to the SAME stdout stream, unconditionally — there is no quiet flag and
``-o`` cannot target a file. So we run graphql-cop as a subprocess and split its
stdout by content into two artifacts:

  * /artifacts/graphqlcop.json — the pure JSON array (``[]`` when nothing found)
  * /artifacts/graphqlcop.txt  — the human status/error lines

The status lines and graphql-cop's own stderr are echoed to our stderr so
Golismero captures them as log lines. We stream both child streams line-by-line
as they arrive, rather than buffering the whole run, so the status lines surface
as log lines in real time instead of all at once on completion. graphql-cop emits
those lines progressively during its path loop but never flushes and prints the
JSON report only at the very end, so the child is run with ``-u`` (unbuffered):
without it, Python block-buffers the pipe and the lines would be stuck until exit
regardless of how eagerly we read. The worker unmarshals our stdout into
[]g3lib.G3Data, so we emit the artifact claim there as a JSON array. graphql-cop's
own exit code is preserved: 0 means it ran to completion (even with no findings or
a non-GraphQL target), non-zero is a genuine failure.
"""

import json
import os
import subprocess
import sys
import threading

ARTIFACTS_DIR = "/artifacts"
JSON_ARTIFACT = "graphqlcop.json"
TXT_ARTIFACT = "graphqlcop.txt"


def main():
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    # Always emit JSON; per-target args (-t <url>) arrive via the .g3p command.
    # cwd=/app because graphql-cop.py imports config/version/lib relative to it.
    # -u forces the child's stdout/stderr unbuffered so its status lines reach us
    # as they are printed instead of sitting in a pipe buffer until exit.
    proc = subprocess.Popen(
        ["python3", "-u", "/app/graphql-cop.py", "-o", "json", *sys.argv[1:]],
        cwd="/app",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered on our read side
    )

    # The JSON report is the first stdout line that starts with '[' and parses as a
    # JSON list; every other stdout line is human status text. Content-based, not
    # positional: on a crash graphql-cop never prints the JSON line, so a "last
    # line" heuristic would mislabel status text as JSON.
    captured = {"data": None}
    status_lines = []
    # Serialize writes to our stderr so the stdout and stderr reader threads don't
    # interleave partial lines.
    echo_lock = threading.Lock()

    def echo(line):
        with echo_lock:
            print(line, file=sys.stderr, flush=True)

    def read_stdout():
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if captured["data"] is None and line.startswith("["):
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, list):
                    captured["data"] = parsed
                    continue  # the report itself is not a log line
            status_lines.append(line)
            echo(line)

    def read_stderr():
        for raw in proc.stderr:
            echo(raw.rstrip("\n"))

    # Drain both streams concurrently: reading one to EOF before the other would
    # deadlock if the child fills the unread pipe's buffer.
    t_out = threading.Thread(target=read_stdout)
    t_err = threading.Thread(target=read_stderr)
    t_out.start()
    t_err.start()
    t_out.join()
    t_err.join()
    returncode = proc.wait()

    data = captured["data"] if captured["data"] is not None else []

    with open(os.path.join(ARTIFACTS_DIR, JSON_ARTIFACT), "w") as f:
        json.dump(data, f)

    with open(os.path.join(ARTIFACTS_DIR, TXT_ARTIFACT), "w") as f:
        for line in status_lines:
            f.write(line + "\n")

    # The worker reads stdout as a JSON array of g3model.Data; declare the artifacts.
    json.dump([{"_artifacts": [JSON_ARTIFACT, TXT_ARTIFACT]}], sys.stdout)
    sys.stdout.write("\n")

    return returncode


if __name__ == "__main__":
    sys.exit(main())
