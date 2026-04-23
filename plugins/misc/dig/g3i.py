#!/usr/local/bin/python3

import jc
import sys
import json
import shlex

# This will contain the output array.
output = []

# Parse the input data.
input = jc.parse("dig", sys.stdin.read())
assert input
assert isinstance(input, list)
for response in input:
    if "question" not in response or "answer" not in response:
        continue

    # Get the domain name.
    domain = response["question"]["name"]
    assert domain.endswith(".")
    domain = domain[:-1]
    server = response["server"]
    p = server.find("(")
    q = server.rfind(")")
    assert p >= 0, (p,q)
    assert q >= 0, (p,q)
    assert p < q, (p,q)
    server = "@" + server[p:q]
    cmd = shlex.join(["dig", "-t", response["question"]["type"], domain, server])
    fp = ["dig " + domain]
    output.append({
        "_type": "domain",
        "_cmd": cmd,
        "_fp": fp,
        "domain": domain,
        "records": response["answer"],
    })

    # Get the IP addresses.
    for answer in response["answer"]:
        if answer["type"] == "A":
            output.append({
                "_type": "host",
                "_cmd": cmd,
                "_fp": fp,
                "ipv4": answer["data"],
                "hostnames": [answer["name"][:-1]],
            })
        if answer["type"] == "AAAA":
            output.append({
                "_type": "host",
                "_cmd": cmd,
                "_fp": fp,
                "ipv6": answer["data"],
                "hostnames": [answer["name"][:-1]],
            })

# Print out the output data in JSON format.
json.dump(output, sys.stdout)
