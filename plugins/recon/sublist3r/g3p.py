#!/usr/local/bin/python3

import os
import sys
import json
import shlex
import tempfile
import subprocess

# The domain name is our only argument.
domain = sys.argv[1]

# Create a temporary file for the tool output.
fd, tmp = tempfile.mkstemp()
try:
    with os.fdopen(fd, 'r') as tmpfd:

        # The VirusTotal engine requires an API key.
        # Make sure not to leak it in the _cmd property.
        apikey = os.getenv("VIRUSTOTAL_API_KEY")
        bruteforce = bool(os.getenv("SUBLIST3R_BRUTEFORCE"))
        if apikey:
            if bruteforce:
                args = ["./sublist3r.py", "-b", "-d", domain, "-o", tmp, "-t", "40", "-v", "-vt", apikey]
                cmd = "python3 sublist3r.py -b -d " + shlex.quote(domain) + " -t 40 -v -vt $VIRUSTOTAL_API_KEY"
            else:
                args = ["./sublist3r.py", "-d", domain, "-o", tmp, "-v", "-vt", apikey]
                cmd = "python3 sublist3r.py -d " + shlex.quote(domain) + " -v -vt $VIRUSTOTAL_API_KEY"
        else:
            if bruteforce:
                args = ["./sublist3r.py", "-b", "-d", domain, "-o", tmp, "-t", "40", "-v"]
                cmd = "python3 sublist3r.py -b -d " + shlex.quote(domain) + " -t 40 -v"
            else:
                args = ["./sublist3r.py", "-d", domain, "-o", tmp, "-v"]
                cmd = "python3 sublist3r.py -d " + shlex.quote(domain) + " -v"

        # Run the tool.
        #sys.stderr.write(repr(args) + "\n")
        result = subprocess.run(args, stdout = sys.stderr, stderr = sys.stderr, check=True)

        # Parse the output of the tool and generate G3 objects.
        # The output from Sublist3r is simply a text file with a domain name in each line.
        output = []
        seen = set()
        for domain in tmpfd:
            domain = domain.strip()
            if domain and domain not in seen:
                seen.add(domain)
                output.append({
                    "_cmd": cmd,
                    "domain": domain,
                })

# Delete the temporary file when we're done.
finally:
    os.unlink(tmp)

# Send the JSON output array over stdout.
json.dump(output, sys.stdout)
