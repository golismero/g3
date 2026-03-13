#!/usr/bin/env python3

import re
import sys
import json
import shlex
import datetime

# Here's wishing there's a better format in the future:
# https://github.com/vanhauser-thc/thc-hydra/issues/865
"""
# Hydra v9.2 run at 2023-06-30 10:33:37 on localhost ftp (hydra -l username -p password -o private/test.hydra ftp://localhost)
[21][ftp] host: localhost   login: username   password: password
"""
re_start = re.compile(r"^# Hydra v[0-9]+\.[0-9]+ run at ([^ ]+ [^ ]+) on ([^ ]+) ([^ ]+) \(([^\)]+)\)$")
re_result = re.compile(r"^\[([0-9]+)\]\[([^\]]+)\] host: ([^ ]+) +login: ([^ ]+) +password: (.+)$")
fmt_timestamp = "%Y-%m-%d %H:%M:%S"

# Importer function.
def import_hydra_textfile(fd, is_internal):
    did_warn_0 = False
    did_warn_1 = False
    did_warn_2 = False
    did_warn_3 = False
    did_warn_4 = False
    output = []
    current = None
    now = int(datetime.datetime.now().timestamp())
    credentials = set()
    seen = set()
    for line in fd:
        line = line.strip()

        # Start of a new scan.
        m = re_start.match(line)
        if m:
            if current is not None:
                if is_internal and not did_warn_0:
                    sys.stderr.write("WARNING: parser found multiple Hydra run results in the same file, this should not happen\n")
                    did_warn_0 = True
                _finish_issue(current, credentials)
                output.append(current)
            start_time_str, hostname, service, cmdline = m.groups()
            start_time = int(datetime.datetime.strptime(start_time_str, fmt_timestamp).timestamp())
            cmdline = shlex.split(cmdline)
            if "-o" in cmdline:
                i = cmdline.index("-o")
                cmdline = cmdline[:i-1] + cmdline[i+1:]
            current = {
                "_type": "issue",
                "_tool": "hydra",
                "_cmd": cmdline,
                "_fp": ["hydra " + hostname],
                "_start": start_time,
                "_end": now if is_internal else 0,
            }
            credentials = set()
            continue

        # Result of a scan.
        m = re_result.match(line)
        if m:
            if line.count("password: ") != 1 and not did_warn_2:
                sys.stderr.write("WARNING: parser found line(s) it could not parse, results may be missing or wrong\n")
                did_warn_2 = True
            port, service, hostname, login, password = m.groups()
            t = (hostname, port, service, login, password)
            if t in seen:
                if not did_warn_3:
                    sys.stderr.write("WARNING: parser found duplicated entries, results may be missing or wrong\n")
                    did_warn_3 = True
                continue
            seen.add(t)
            credentials.add(t)

        # Error while parsing.
        if not did_warn_1:
            sys.stderr.write("WARNING: parser found line(s) it could not parse, results may be missing or wrong\n")
            did_warn_1 = True

    # Return the output array.
    if current is not None and current not in output:
        _finish_issue(current, credentials)
        output.append(current)
    return output

# Helper function.
def _finish_issue(current, credentials):
    if not credentials:
        current["_type"] = "nil"
    else:
        affects = set()
        current["credentials"] = []
        for (hostname, port, service, login, password) in sorted(credentials):
            affects.add("%s:%s (%s)" % (hostname, port, service))
            cred = {
                "host": hostname,
                "port": port,
                "service": service,
                "login": login,
                "password": password,
            }
            current["credentials"].append(cred)
        current["severity"] = 3
        current["affects"] = sorted(affects)
        current["taxonomy"] = ["CAPEC-16", "CAPEC-49", "CAPEC-70", "CWE-307", "CWE-1391"]
        current["references"] = ["https://github.com/vanhauser-thc/thc-hydra"]

# Entry point.
if __name__ == "__main__":

    # If we have a filename in the command line, this means the script was invoked internally.
    if len(sys.argv) == 2:
        with open(sys.argv[1], "r") as fd:
            output = import_hydra_textfile(fd, is_internal=True)

    # If we don't, this means the script was invoked as an importer plugin.
    else:
        output = import_hydra_textfile(sys.stdin, is_internal=False)

    # Convert the output array to JSON and send it over stdout.
    json.dump(output, sys.stdout)
