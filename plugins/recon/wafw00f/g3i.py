#!/usr/bin/python3

import sys
import json
import urllib.parse

# We have two possible output formats, JSON or CSV.
# The CSV format is actually broken (no double quotes) so we have to hand parse it.
raw_input = sys.stdin.read()
json_input = []
try:
    json_input = json.loads(raw_input)
    if not isinstance(json_input, list):
        sys.stderr.write("ERROR: unknown file format, ignoring input file.\n")
        sys.exit(1)
    for item in json_input:
        if set(item.keys()) != set(["url", "detected", "firewall", "manufacturer"]):
            sys.stderr.write("ERROR: unknown file format, ignoring input file.\n")
            sys.exit(1)
except Exception:
    lines = raw_input.splitlines()
    if lines.pop(0) != "url,detected,firewall,manufacturer":
        sys.stderr.write("ERROR: unknown file format, ignoring input file.\n")
        sys.exit(1)
    for line in lines:
        url, detected, firewall, manufacturer = line.split(",", 4)
        json_input.append({
            "url": url,
            "detected": bool(detected.lower() == "true"),
            "firewall": firewall,
            "manufacturer": manufacturer,
        })
if not json_input:
    sys.stderr.write("Empty file, ignoring.\n")
    sys.stdout.write("[]")
    sys.stdout.flush()
    sys.exit(0)

# We have no guarantees on the input file since it may come from the user. Therefore,
# there can be more than one URL, depending on how many were passed via command line.
# We solve this by identifying each different URL and returning a new object for each.
# We can also get more than one result per URL - we assume the order is relevant, so
# we preserve it. We'll also ignore non results (when no firewall was detected).
results_per_url = {}
urls = set()
for item in json_input:
    if not item["detected"] or item["firewall"] == "Generic":
        #sys.stderr.write("Skipped nil result: %r\n" % item)
        continue
    url = item["url"]
    if url not in results_per_url:
        results_per_url[url] = []
        urls.add(url)
    results_per_url[url].append({
        "firewall": item["firewall"],
        "manufacturer": item["manufacturer"],
    })

# Generate an output array of G3 data objects.
output = []
for url in sorted(urls):
    results = results_per_url[url]
    if not results:
        continue
    cmd = "wafw00f " + url
    o = urllib.parse.urlparse(url)
    data = {
        "_cmd": cmd,
        "_fp": [cmd],
        "url": url,
        "scheme": o.scheme,
        "host": o.hostname,
        "path": o.path,
        "waf": results,
    }
    if o.username:
        data["username"] = o.username
    if o.password:
        data["password"] = o.password
    output.append(data)

# Print out the output data in JSON format.
json.dump(output, sys.stdout)
