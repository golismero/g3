#!/usr/bin/python3

import re
import sys
import json

# Untangle's known server names. Anything not in this set — the sentinels
# untangle emits ("unknown", "too_long", "exception", "empty", "200") and the
# tool's stray debug prints ("something wrong", tracebacks, ...) — is dropped.
KNOWN_SERVERS = {
    "cloudfront", "cloudflare", "fastly", "akamai", "nginx", "varnish",
    "haproxy", "apache", "caddy", "envoy", "ats", "squid", "tomcat",
}

# Matches ordered layer lines, e.g. "Layer 1: cloudflare".
LAYER_RE = re.compile(r"^Layer\s+\d+:\s*(\S+)\s*$")


def parse_layers(text):
    """Parse untangle stdout into an ordered list of known server names.

    Ordered layers appear as "Layer N: <server>" lines. The unordered case is
    an "Unordered Layers:" header followed by bare server names. In both cases
    we keep only names in KNOWN_SERVERS, preserving order, which discards
    sentinels and debug noise.
    """
    layers = []
    in_unordered = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = LAYER_RE.match(line)
        if m:
            in_unordered = False
            name = m.group(1).lower()
            if name in KNOWN_SERVERS:
                layers.append(name)
            continue
        if line == "Unordered Layers:":
            in_unordered = True
            continue
        if in_unordered:
            name = line.lower()
            if name in KNOWN_SERVERS:
                layers.append(name)
    return layers


def main():
    # Run mode: invoked by g3p.sh as "g3i r <host>" right after a tool run.
    # Import mode: no args (raw file import) — untangle output has no host, so
    # we cannot reconstruct a url and must emit nothing.
    if len(sys.argv) >= 2 and sys.argv[1] == "r":
        artifacts = ["untangle.txt"]
        host = sys.argv[2] if len(sys.argv) >= 3 else ""
    else:
        artifacts = []
        host = ""

    layers = parse_layers(sys.stdin.read())

    if not layers or not host:
        if layers and not host:
            sys.stderr.write(
                "untangle importer: no host argument; cannot build url, dropping result.\n"
            )
        json.dump([], sys.stdout)
        return

    # untangle only ever probes "/", so the fingerprint is the canonical
    # https://<host>/ form (no per-path component). This matches untangle.g3p's
    # command fingerprints ("untangle https://<host>/") exactly, so every url on
    # a host and the bare domain dedup to a single run (scanner dedups by exact
    # _fp string match).
    url = "https://%s/" % host
    cmd = "untangle " + url
    data = {
        "_cmd": cmd,
        "_fp": [cmd],
        "_artifacts": artifacts,
        "url": url,
        "scheme": "https",
        "host": host,
        "path": "/",
        "layers": layers,
    }
    json.dump([data], sys.stdout)


if __name__ == "__main__":
    main()
