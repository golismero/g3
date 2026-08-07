#!/usr/bin/env python3
"""Golismero3 importer entrypoint for magenta."""

import json
import os
import shutil
import sys
import tempfile

from libmagenta.engine import MagentaReporter


def main():
    m = MagentaReporter()
    tool = sys.argv[1]

    # Two invocation modes:
    #   g3i <tool> <file>  Live run: the artifact already exists on disk, so we
    #                      hand its path straight to the parser.
    #   g3i <tool>         Importer: the input arrives on stdin. Spool it to a
    #                      temp file so the parser -- and the engine's SHA-1
    #                      fingerprint, which re-reads the file afterwards --
    #                      can both open it. Streamed in chunks to avoid
    #                      buffering large inputs in memory.
    if len(sys.argv) > 2:
        issues = m.run_parser(tool, sys.argv[2])
    else:
        fd, path = tempfile.mkstemp(prefix="g3i-stdin-")
        try:
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(sys.stdin.buffer, out)
            issues = m.run_parser(tool, path)
        finally:
            os.unlink(path)

    issues = m.merge_duplicated_issues(issues)
    json.dump(issues, sys.stdout)


if __name__ == "__main__":
    main()
