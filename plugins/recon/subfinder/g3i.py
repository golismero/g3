#!/usr/bin/python3

import sys
import json
import shlex

# We have four possible output formats: JSON or text, and with or without collecting all sources.
# The -active flag does affect the output contents but not the format.
input = sys.stdin.readlines()
input = [x.strip() for x in input]
input = [x for x in input if x]
if not input:
    sys.stderr.write("Empty input file!\n")
    exit(1)
isJSON = input[0][0] == "{"
isJSONWithSources = False   # will be decided later
isTextWithSources = input[0][-1] == "]"

# Parse the results no matter what the input format is.
# Some formats have more information than others, we make what we can of it.
# We only need the actual subdomains, we can ignore everything else.
results = set()
hostname = None
for line in input:
    if isJSON:
        data = json.loads(line)
        host = data["host"]
        if hostname is None:
            hostname = data["input"]
        if "sources" in data:
            isJSONWithSources = True    # used -cs
    else:
        if isTextWithSources:
            p = line.find(",")
            assert p > 0, line
            assert line[p+1] == "[", line
            host = line[:p]
        else:
            host = line
    results.add(host)
if not results:
    sys.stderr.write("Internal error!\n")
    exit(1)

# The text format doesn't save the hostname that was queried.
# We can reconstruct that by searching for a common suffix.
if not isJSON:
    all_hosts = sorted(set(tuple(host.split(".")) for host in results))
    suffix_len = min(len(host) for host in all_hosts)
    index = -1
    done = False
    while not done:
        suffix = all_hosts[0][index:]
        for host in all_hosts:
            if host[index:] != suffix:
                suffix = suffix[1:]
                done = True
                break
        if done:
            break
        index = index - 1
        done = len(suffix) == suffix_len
    if suffix:
        hostname = ".".join(suffix)

# Now that we have all of the information we can reconstruct the command line.
# Doesn't have to be 100% accurate, just good enough for the report.
cmd = "subfinder -v " + ("-oJ " if isJSON else "") + ("-cs " if isTextWithSources or isJSONWithSources else "") + "-d " + shlex.quote(hostname)

# Generate the fingerprint for the results.
fp = ["subfinder " + hostname]

# Convert the results into G3 format.
output = []
for host in results:
    output.append({
        "_cmd": cmd,
        "_fp": fp,
        "domain": host,
    })

# Print out the output data in JSON format.
json.dump(output, sys.stdout)
