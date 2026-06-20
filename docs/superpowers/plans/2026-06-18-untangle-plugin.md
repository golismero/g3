# Untangle Recon Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `plugins/recon/untangle/` plugin that wraps the [untangle](https://github.com/cemtopcuoglu/untangle) multi-layer web server fingerprinting tool, mirroring the sibling `wafw00f` plugin.

**Architecture:** A `.g3p` definition triggers on domain objects and default-port HTTPS url objects, passing a bare hostname to a containerized untangle. A shell entrypoint (`g3p.sh`) runs untangle from its install dir (where its `behavior_repository.out` pickle lives), tees the plain-text output to an artifact, and pipes it — along with the target host — to a Python importer (`g3i.py`). The importer parses untangle's noisy `Layer N: <server>` stdout against a known-server allowlist and emits one `url` G3Data object carrying an ordered `layers` array. Non-detections are dropped.

**Tech Stack:** Jsonnet plugin definition, POSIX shell, Python 3 (importer), Docker (`python:3-slim`, git-clone-and-pin of untangle). Tests: pytest driving `g3i.py` via subprocess.

**Spec:** `docs/superpowers/specs/2026-06-18-untangle-plugin-design.md`

> **GIT NOTE:** The repo owner runs **all** git commands for this repo. This plan contains **no** `git` steps. Where the skill would normally commit, you'll find a **Commit checkpoint** marker instead — pause and let the owner commit. Do not run `git add`/`git commit`/`git push`.

---

## File Structure

- `plugins/recon/untangle/g3i.py` — importer: parse untangle stdout → G3Data JSON (the only logic-bearing file; gets unit tests).
- `plugins/recon/untangle/test_g3i.py` — pytest suite driving `g3i.py` via subprocess. Not copied into the image.
- `plugins/recon/untangle/untangle.g3p` — Jsonnet plugin definition (commands, conditions, importer).
- `plugins/recon/untangle/g3p.sh` — container entrypoint: run untangle, tee artifact, pipe to importer.
- `plugins/recon/untangle/Dockerfile` — clone-and-pin untangle on `python:3-slim`, install deps, add wrappers.
- `plugins/recon/untangle/Makefile` — build/pull `ghcr.io/golismero/untangle`.

---

## Task 1: Importer (`g3i.py`) — TDD

The importer is invoked two ways:
- **Run mode** (`g3i r <host>`): right after a tool run; `<host>` is the target. Artifacts include `untangle.txt`.
- **Import mode** (no args): a user feeds a raw untangle output file. Untangle's output contains **no** host, so a url cannot be reconstructed — the importer emits `[]`. (Documented limitation.)

**Files:**
- Create: `plugins/recon/untangle/g3i.py`
- Test: `plugins/recon/untangle/test_g3i.py`

- [ ] **Step 1: Write the failing tests**

Create `plugins/recon/untangle/test_g3i.py`:

```python
import json
import os
import subprocess
import sys

G3I = os.path.join(os.path.dirname(__file__), "g3i.py")


def run_importer(stdin_text, *args):
    proc = subprocess.run(
        [sys.executable, G3I, *args],
        input=stdin_text,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_ordered_three_layers():
    out = run_importer(
        "Layer 1: cloudflare\nLayer 2: varnish\nLayer 3: nginx\n",
        "r", "reversi.nexus",
    )
    assert out == [{
        "_cmd": "untangle https://reversi.nexus/",
        "_fp": ["untangle https://reversi.nexus/"],
        "_artifacts": ["untangle.txt"],
        "url": "https://reversi.nexus/",
        "scheme": "https",
        "host": "reversi.nexus",
        "path": "/",
        "layers": ["cloudflare", "varnish", "nginx"],
    }]


def test_two_layers():
    out = run_importer(
        "Layer 1: nginx\nLayer 2: apache\n",
        "r", "nextcloud.cacharreo.duckdns.org",
    )
    assert out[0]["layers"] == ["nginx", "apache"]


def test_trailing_unknown_is_dropped():
    out = run_importer(
        "Layer 1: cloudflare\nLayer 2: varnish\nLayer 3: unknown\n",
        "r", "www.example.net",
    )
    assert out[0]["layers"] == ["cloudflare", "varnish"]


def test_too_long_yields_empty():
    out = run_importer("Layer 1: too_long\n", "r", "1.1.1.1")
    assert out == []


def test_exception_with_debug_noise_yields_empty():
    # untangle prints stray debug lines; none must be mistaken for a result.
    out = run_importer(
        "[Errno 61] Connection refused\nLayer 1: exception\n",
        "r", "host.invalid",
    )
    assert out == []


def test_unordered_layers_are_collected():
    out = run_importer(
        "Unordered Layers:\nnginx\napache\n",
        "r", "example.org",
    )
    assert out[0]["layers"] == ["nginx", "apache"]


def test_debug_noise_after_unordered_header_is_filtered():
    out = run_importer(
        "Unordered Layers:\nnginx\nsomething wrong\napache\n",
        "r", "example.org",
    )
    assert out[0]["layers"] == ["nginx", "apache"]


def test_import_mode_without_host_yields_empty():
    # Standalone import of a raw file: no host arg, so no url can be built.
    out = run_importer("Layer 1: nginx\n")
    assert out == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest plugins/recon/untangle/test_g3i.py -v`
Expected: FAIL — all tests error because `plugins/recon/untangle/g3i.py` does not exist yet (`can't open file ... g3i.py`).

- [ ] **Step 3: Write the importer**

Create `plugins/recon/untangle/g3i.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest plugins/recon/untangle/test_g3i.py -v`
Expected: PASS — all 8 tests green.

- [ ] **Step 5: Commit checkpoint**

Stop and let the repo owner commit `plugins/recon/untangle/g3i.py` and `plugins/recon/untangle/test_g3i.py`. (Do not run git yourself.)

---

## Task 2: Plugin definition (`untangle.g3p`)

**Files:**
- Create: `plugins/recon/untangle/untangle.g3p`

- [ ] **Step 1: Write the definition**

Create `plugins/recon/untangle/untangle.g3p`:

```jsonnet
{
    url: "https://github.com/cemtopcuoglu/untangle",
    description: "Untangle is a multi-layer web server fingerprinting tool that identifies the ordered stack of servers/CDNs/proxies (e.g. cloudflare -> varnish -> nginx) in front of an HTTPS site.",

    commands: [

        // Domain objects: fingerprint the domain over HTTPS.
        {
            condition: "{{if .domain}} true {{else}} false {{end}}",
            fingerprint: ["untangle https://{{.domain}}"],
            command: ["{{.domain}}"],
            returns: "url",
        },

        // HTTPS url objects on the default port only. untangle hardcodes port
        // 443, so a url whose .host carries an explicit port (contains ":") is
        // skipped. See docs/notes/untangle-port-patch.md.
        {
            condition: "{{if and .url (eq .scheme \"https\") (not (contains .host \":\"))}} true {{else}} false {{end}}",
            fingerprint: ["untangle {{.url}}"],
            command: ["{{.host}}"],
            returns: "url",
        },
    ],

    importer: {
        returns: "url",
    },
}
```

- [ ] **Step 2: Validate Jsonnet parses**

`.g3p` files are Jsonnet, so the authoritative parse check is `g3config` itself
(it evaluates the Jsonnet and validates the resulting struct). Run Task 4's
`g3config` step and confirm it reports the plugin without error. There is no
standalone pre-check — Python's `json5` cannot parse Jsonnet (`|||` text blocks,
in particular), so it would give false negatives.

- [ ] **Step 3: Commit checkpoint**

Stop and let the repo owner commit `plugins/recon/untangle/untangle.g3p`.

---

## Task 3: Container glue (`g3p.sh`, `Dockerfile`, `Makefile`)

**Files:**
- Create: `plugins/recon/untangle/g3p.sh`
- Create: `plugins/recon/untangle/Dockerfile`
- Create: `plugins/recon/untangle/Makefile`

- [ ] **Step 1: Write the entrypoint**

Create `plugins/recon/untangle/g3p.sh`:

```sh
#!/bin/sh
set -e
# untangle exits 0 on success; a non-zero status is a real error. It reads
# behavior_repository.out from its current working directory, so run from there.
set -o pipefail
cd /opt/untangle
rc=0
python3 untangle.py -t "$1" | tee /artifacts/untangle.txt 1>&2 || rc=$?
# Pass the target host to the importer so it can reconstruct the url object;
# untangle's own output does not contain the hostname.
cat /artifacts/untangle.txt | python3 /usr/bin/g3i r "$1"
exit $rc
```

- [ ] **Step 2: Write the Dockerfile**

Create `plugins/recon/untangle/Dockerfile`:

```dockerfile
# untangle is not on PyPI; clone and pin to a known-good commit.
# Debian (slim) rather than alpine so simphile installs from wheels.
FROM python:3-slim

ENV PYTHONUNBUFFERED=1

# git is needed to fetch untangle at build time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Fetch and pin untangle (includes behavior_repository.out).
RUN git clone https://github.com/cemtopcuoglu/untangle.git /opt/untangle \
    && cd /opt/untangle \
    && git checkout ab877e54aee8d584a9477cc215d7a4e7c57df850

# Install untangle's Python dependencies (configargparse, simphile).
RUN pip3 install --no-cache-dir -r /opt/untangle/requirements.txt

# Add the Golismero3 wrapper and importer.
COPY --chmod=0755 g3p.sh /usr/bin/g3p
COPY --chmod=0755 g3i.py /usr/bin/g3i

# untangle reads behavior_repository.out from the CWD.
WORKDIR /opt/untangle

ENTRYPOINT ["/usr/bin/g3p"]
```

- [ ] **Step 3: Write the Makefile**

Create `plugins/recon/untangle/Makefile` (matches `plugins/recon/wafw00f/Makefile`):

```makefile
.PHONY: all pull
all:
	docker build -t ghcr.io/golismero/untangle .
pull:
	docker pull ghcr.io/golismero/untangle
```

- [ ] **Step 4: Commit checkpoint**

Stop and let the repo owner commit `g3p.sh`, `Dockerfile`, and `Makefile`.

---

## Task 4: Build, register, and live smoke test

This task validates the whole plugin end-to-end. It requires Docker and network access. Use the targets the owner already exercised by hand.

- [ ] **Step 1: Build the image**

Run: `make -C plugins/recon/untangle`
Expected: image `ghcr.io/golismero/untangle` builds successfully; the final lines show a successful tag. If `simphile` fails to build, that's the one risk flagged in the spec — capture the error for the owner.

- [ ] **Step 2: Smoke test a multi-layer target**

Run:
```bash
mkdir -p /tmp/untangle-art
docker run --rm -v /tmp/untangle-art:/artifacts ghcr.io/golismero/untangle reversi.nexus
```
Expected: stdout is a JSON array with one object whose `host` is `reversi.nexus`, `url` is `https://reversi.nexus/`, and `layers` is a non-empty ordered list of known server names (e.g. `["cloudflare","varnish","nginx"]`). The raw tool output is in `/tmp/untangle-art/untangle.txt`.

- [ ] **Step 3: Smoke test the drop-non-detection path**

Run:
```bash
docker run --rm -v /tmp/untangle-art:/artifacts ghcr.io/golismero/untangle 1.1.1.1
```
Expected: stdout is `[]` (untangle returns `too_long` for the bare IP, which the importer drops).

- [ ] **Step 4: Register the plugin with g3config**

Build and run g3config against the repo so the new `.g3p` is parsed and registered. From the repo root:
```bash
cd src && make ../bin/g3config && cd ..
G3HOME="$(pwd)" ./bin/g3config
```
Expected: g3config completes without error and reports the untangle plugin among those registered; a corresponding entry appears under `config/`. A parse error in `untangle.g3p` (including a malformed template condition) would surface here.

- [ ] **Step 5: Verify against the spec**

Confirm: domain + default-port-https url trigger the plugin; raw IP / non-https / explicit-port url do not; output is a `url` object with a `layers` array; non-detections produce `[]`. All match `docs/superpowers/specs/2026-06-18-untangle-plugin-design.md`.

- [ ] **Step 6: Final commit checkpoint**

Stop and let the repo owner commit any generated `config/` changes and finalize.

---

## Self-Review Notes

- **Spec coverage:** target scope (Task 2 conditions), output shape (Task 1 importer), drop non-detections (Task 1 tests + Task 4 Step 3), known-server allowlist (Task 1), `cd` for behavior_repository.out (Task 3 g3p.sh), clone-and-pin on python:3-slim (Task 3 Dockerfile), default-port gate (Task 2 condition), Makefile/image name (Task 3). The port-patch limitation note already exists at `docs/notes/untangle-port-patch.md`.
- **Refinement beyond the spec text:** the importer receives the target host as `g3i r <host>` because untangle's stdout contains no hostname — required to reconstruct the `url` object. Consistent with the spec's stated intent ("reconstructs the canonical https://<host>/ url").
- **Type/name consistency:** `parse_layers`, `KNOWN_SERVERS`, `LAYER_RE`, the `layers` field, and the `untangle.txt` artifact name are used identically across the importer, its tests, and g3p.sh.
