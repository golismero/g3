# Untangle Recon Plugin — Design Spec

**Date:** 2026-06-18 (rev. 2026-06-18: synced to implementation — slashed dedup fingerprints, no importer block, host passed to importer via argv)
**Status:** Implemented — importer 10/10 pytest green, `untangle.g3p` parses/validates in g3config; Docker image build + container smoke test + full registration deferred to push/CI.
**Plugin:** `plugins/recon/untangle/`

## Problem

We want a simple recon plugin wrapping [untangle](https://github.com/cemtopcuoglu/untangle),
a multi-layer web server fingerprinting tool (NDSS 2024). Untangle identifies the *ordered
stack* of servers/CDNs/proxies in front of an HTTPS site (e.g. `cloudflare → varnish →
nginx`), which complements the closely related WAF-detection plugin `wafw00f`. The new
plugin should mirror the wafw00f plugin's structure as closely as the tool allows.

## Tool characteristics (as observed)

- **Invocation:** `python3 untangle.py -t <hostname>`. Takes a bare **hostname** only.
- **HTTPS-only / port 443 hardcoded.** It opens a TLS socket to port 443 with the hostname
  as SNI. There is no port or scheme option.
- **Raw IPs don't work:** `-t 1.1.1.1` returns `Layer 1: too_long`. Unreachable hosts
  return `Layer 1: exception` (and stray debug prints).
- **Output is plain text on stdout**, no JSON / file artifact:
  - Ordered layers: lines like `Layer 1: cloudflare`, `Layer 2: varnish`, `Layer 3: nginx`.
  - Unordered case: an `Unordered Layers:` header followed by bare server names, one per line.
  - Sentinel (non-server) values appear as the layer value: `unknown`, `too_long`,
    `exception`, `empty`, `200`.
  - stdout is **noisy**: the tool has stray `print(exception)` / `print("here1 up", ...)` /
    `print("something wrong")` debug lines that must not be mistaken for results.
- **Runtime dependency:** reads `behavior_repository.out` (a ~290 KB pickle) from its
  **current working directory**. The tool must run with CWD set to its install dir.
- **Not on PyPI:** distributed as a git repo. Python deps: `configargparse`, `simphile`.
- **Upstream pin:** commit `ab877e54aee8d584a9477cc215d7a4e7c57df850` (2024-05-14).

## Decisions

Mirror the wafw00f plugin. Four files plus a `Makefile`:
`untangle.g3p`, `Dockerfile`, `g3p.sh`, `g3i.py`, `Makefile`.

### Target scope
Run on **domain objects** and **default-port HTTPS url objects** only. Raw IPs, non-https
URLs, and explicit non-443 ports are excluded (the tool can't use them).

### Output shape
Normalize every result to a `url` G3Data object (`https://<host>/`) — same approach as
wafw00f — and attach an ordered **`layers`** array of server names. The `commands` declare
`returns: "url"`.

```jsonnet
{
    url: "https://github.com/cemtopcuoglu/untangle",
    description: "Untangle is a multi-layer web server fingerprinting tool that identifies the ordered stack of servers/CDNs/proxies (e.g. cloudflare -> varnish -> nginx) in front of an HTTPS site.",

    commands: [
        {   // domain objects
            condition: "{{if .domain}} true {{else}} false {{end}}",
            fingerprint: ["untangle https://{{.domain}}/"],
            command: ["{{.domain}}"],
            returns: "url",
        },
        {   // https url objects on the default port only
            condition: "{{if and .url (eq .scheme \"https\") (not (contains .host \":\"))}} true {{else}} false {{end}}",
            fingerprint: ["untangle https://{{.host}}/"],
            command: ["{{.host}}"],
            returns: "url",
        },
    ],
}
```

The port gate uses `contains .host ":"` (both `contains` and `not` are registered template
funcs — see `src/g3lib/template.go`). A canonical default-port https url has its port
stripped, so `.host` is a bare hostname; any `:` means a non-default port and is skipped.

**No `importer` block.** Every other plugin's standalone importer assumes the target is
recoverable from the tool's output file; untangle's output (`Layer N: ...`) contains no
hostname, so a file-only import genuinely cannot reconstruct a `url`. Declaring an importer
that always returns `[]` would be misleading, so the block is omitted (matching nmap, nikto,
hydra, testssl, which also have none). Run-mode parsing still happens — `g3p.sh` pipes the
output to `g3i` directly — and the worker types the result from the command's `returns: "url"`.

**Fingerprints carry the canonical `/` path on purpose.** untangle only ever probes `/`, so
fingerprinting `untangle https://<host>/` makes every url on a host — and the bare domain —
collapse to a single fingerprint, deduping repeated runs across many URLs of the same host.
The importer must emit the identical slashed `_fp` (the scanner dedups by exact `_fp` string
match — `GetFingerprintMatchesIDs` in `src/g3lib/datastore.go`, queried against the command
fingerprint in `src/g3scanner/g3scanner.go`).

### Entrypoint (`g3p.sh`)
Mirror wafw00f, but `cd` into the install dir first so `behavior_repository.out` resolves,
and tee the (only) stdout output to the artifact:

```sh
#!/bin/sh
set -e
set -o pipefail
cd /opt/untangle
rc=0
python3 untangle.py -t "$1" | tee /artifacts/untangle.txt 1>&2 || rc=$?
# Pass the target host to the importer; untangle's output has no hostname.
cat /artifacts/untangle.txt | python3 /usr/bin/g3i r "$1"
exit $rc
```

Artifact: `untangle.txt` (raw output).

### Importer (`g3i.py`)
Parse defensively against noisy stdout:
- Match `^Layer \d+:\s*(\S+)` → ordered server names.
- After an `Unordered Layers:` header → treat following bare tokens as (unordered) servers.
- **Filter every captured name against untangle's known-server allowlist**
  (`cloudfront, cloudflare, fastly, akamai, nginx, varnish, haproxy, apache, caddy, envoy,
  ats, squid, tomcat`). This drops sentinels (`unknown`/`too_long`/`exception`/`empty`/
  `200`) and debug spew in one step.
- If **zero** real layers remain → emit `[]` (drop non-detections, like wafw00f).
- The target host arrives as an argument (`g3i r <host>`), since untangle's output has no
  hostname. In standalone import mode (no host argument) a `url` can't be reconstructed, so
  the importer emits `[]`.
- Otherwise emit one `url` object with the standard url fields reconstructed from the
  hostname (`https://<host>/`), plus the flat `layers` array. `_cmd`/`_fp` use the same
  slashed `untangle https://<host>/` form as the command fingerprints (see dedup note above):

```json
{
  "_cmd": "untangle https://reversi.nexus/",
  "_fp": ["untangle https://reversi.nexus/"],
  "_artifacts": ["untangle.txt"],
  "url": "https://reversi.nexus/",
  "scheme": "https",
  "host": "reversi.nexus",
  "path": "/",
  "layers": ["cloudflare", "varnish", "nginx"]
}
```

Ordered and unordered layers both land in `layers` in listed order; the ordered/unordered
distinction is **not** preserved (accepted simplification of the flat-array shape).
Follow the wafw00f importer's `ARTIFACTS = ["untangle.txt"]` when `argv[1] == "r"` convention.

### Dockerfile
Untangle isn't on PyPI, so clone-and-pin at build. Use `python:3-slim` (Debian) rather than
wafw00f's `python:3-alpine`, because `simphile` is more likely to install from prebuilt
wheels on Debian and avoid a source build:

```dockerfile
FROM python:3-slim
ENV PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/cemtopcuoglu/untangle.git /opt/untangle \
    && cd /opt/untangle \
    && git checkout ab877e54aee8d584a9477cc215d7a4e7c57df850
RUN pip3 install --no-cache-dir -r /opt/untangle/requirements.txt
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i
WORKDIR /opt/untangle
ENTRYPOINT ["/usr/bin/g3p"]
```

`Makefile` builds/pulls `ghcr.io/golismero/untangle` (framework default image name), matching
the wafw00f `Makefile`.

## Known limitation — future upstream patch

Untangle hardcodes port 443, so HTTPS URLs on non-standard ports can't be fingerprinted; the
url command is gated to default-port only to avoid feeding the tool a `host:port` it would
mishandle. The intended fix is a PR to upstream untangle adding a port option; if accepted,
we revisit this plugin to widen the url condition. Tracked in
`docs/notes/untangle-port-patch.md`.

## Out of scope (YAGNI)

- No `g3m.py` merger (mergers are being phased out and only apply to issue-producing plugins;
  untangle produces no issues).
- No IPv4/IPv6/host-object support (the tool can't use them).
- No preservation of the ordered/unordered nuance.
