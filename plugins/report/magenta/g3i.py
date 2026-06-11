#!/usr/bin/env python3
"""g3r — golismero3 importer entrypoint for magenta.
"""

import sys
import json

from libmagenta.engine import MagentaReporter

def main():
    m = MagentaReporter()
    issues = m.run_parser(sys.argv[1], 0)
    issues = m.merge_duplicated_issues(issues)
    json.dump(issues, sys.stdout)

if __name__ == "__main__":
    main()
