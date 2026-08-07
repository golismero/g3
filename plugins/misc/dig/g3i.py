#!/usr/local/bin/python3

import ipaddress
import json
import shlex
import sys
from pprint import pprint

import jc


def arpa_to_ipv6(arpa):
    arpa = arpa.lower().rstrip(".").removesuffix(".ip6.arpa")
    nibbles = arpa.split(".")[::-1]  # arpa stores nibbles least-significant-first
    return str(ipaddress.IPv6Address(int("".join(nibbles), 16)))


def arpa_to_ipv4(arpa):
    arpa = arpa.lower().rstrip(".").removesuffix(".in-addr.arpa")
    octets = arpa.split(".")[::-1]  # arpa stores octets least-significant-first
    return str(ipaddress.IPv4Address(".".join(octets)))


# This will contain the output array.
output = []

# Flag that indicates this is the result of a run, not an import.
if len(sys.argv) == 2 and sys.argv[1] == "r":
    SOURCE = json.load(sys.stdin)
    ARTIFACTS = ["dig.txt"]
    INPUT = open("/artifacts/dig.txt", "r").read()
    pprint(SOURCE, sys.stderr)
else:
    SOURCE = None
    ARTIFACTS = []
    INPUT = sys.stdin.read()

# Parse the input data.
input = jc.parse("dig", INPUT)
pprint(input, sys.stderr)
assert input
assert isinstance(input, list)
for response in input:
    if "question" not in response or "answer" not in response:
        continue

    # Get the augmented "domain" object.
    domain = response["question"]["name"]
    assert domain.endswith(".")
    domain = domain[:-1]
    server = response["server"]
    p = server.find("(") + 1
    q = server.find(")", p)
    assert p >= 0, (p, q)
    assert q >= 0, (p, q)
    assert p < q, (p, q)
    server = "@" + server[p:q]
    cmd = shlex.join(["dig", "-t", response["question"]["type"], domain, server])
    if not domain.endswith(".in-addr.arpa") and not domain.endswith(".ip6.arpa"):
        obj = {
            "_type": "domain",
            "_cmd": cmd,
            "_artifacts": ARTIFACTS,
            "domain": domain,
            "records": response["answer"],
        }
        if "authority" in response:
            obj["authority"] = response["authority"]
        output.append(obj)

    # Get the derived objects.
    for answer in response["answer"]:
        if answer["type"] == "A":
            output.append(
                {
                    "_type": "host",
                    "_cmd": cmd,
                    "_artifacts": ARTIFACTS,
                    "ipv4": answer["data"][:-1],
                    "hostnames": sorted({answer["name"][:-1], domain}),
                }
            )
        elif answer["type"] == "AAAA":
            output.append(
                {
                    "_type": "host",
                    "_cmd": cmd,
                    "_artifacts": ARTIFACTS,
                    "ipv6": answer["data"],
                    "hostnames": sorted({answer["name"][:-1], domain}),
                }
            )
        elif answer["type"] == "PTR":
            if domain.endswith(".in-addr.arpa"):
                output.append(
                    {
                        "_type": "host",
                        "_cmd": cmd,
                        "_artifacts": ARTIFACTS,
                        "ipv4": arpa_to_ipv4(answer["name"]),
                        "hostnames": [answer["data"][:-1]],
                    }
                )
                output.append(
                    {
                        "_type": "domain",
                        "_cmd": cmd,
                        "_artifacts": ARTIFACTS,
                        "domain": answer["data"][:-1],
                    }
                )
            elif domain.endswith(".ip6.arpa"):
                output.append(
                    {
                        "_type": "host",
                        "_cmd": cmd,
                        "_artifacts": ARTIFACTS,
                        "ipv6": arpa_to_ipv6(answer["name"]),
                        "hostnames": [answer["data"][:-1]],
                    }
                )
                output.append(
                    {
                        "_type": "domain",
                        "_cmd": cmd,
                        "_artifacts": ARTIFACTS,
                        "domain": answer["data"][:-1],
                    }
                )
            else:
                assert False, domain

# This needs to be replaced for more nuanced logic if we want dig to be selectively reentrant.
# Now I can see why past me made the dig plugin so limited, to prevent this kind of reentry.
# This isn't so terrible (pipelines have a fixed length) but will bite me in the ass quickly
# if I try to add a fully recursive mode at some point.
""" # Block input domain objects (we're creating a newer version).
# Do not block other objects (for example URLs).
if SOURCE is not None and SOURCE["_type"] not in ("domain", "host"):
    output.append(SOURCE)
 """

# Print out the output data in JSON format.
pprint(output, sys.stderr)
json.dump(output, sys.stdout)
