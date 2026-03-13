#!/usr/local/bin/python3

import sys
import json

# This will contain the output array.
output = []

# The output from Sublist3r is simply a text file with a domain name in each line.
seen = set()
for domain in sys.stdin:
    domain = domain.strip()
    if domain and domain not in seen:
        seen.add(domain)
        output.append({
            "domain": domain,
        })

# Print out the output data in JSON format.
json.dump(output, sys.stdout)
