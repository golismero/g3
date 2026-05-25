# Tier 4 — Wrapper Exit-Code Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the tool wrappers emit a meaningful exit code so the worker's WARNING/ERROR derivation (already shipped in Tiers 1–3) actually fires: `0` = nothing to flag, non-zero = a soft signal. The worker turns `(exit code, did actionable data survive)` into DONE / WARNING / ERROR — wrappers never pick the state.

**Architecture:** Per-wrapper edits only; no Go changes. Piped shell wrappers (`nmap`, `subfinder`, `wafw00f`) currently mask the tool's exit code behind `tee` — recover it via `pipefail` and propagate. Python wrappers (`testssl`, `hydra`) currently force `exit 0` — capture each invocation's `returncode` and fold the per-target loop into one exit (`any non-zero → non-zero`). Both tools already return 0 on clean runs (testssl even when a sub-test like CAA-DNS fails; hydra whether or not creds were found), so no per-code special-casing is needed. `dig` is already correct; the debug plugins are already correct; **`nikto` is excluded** (needs a separate Dockerfile-source-install + importer-compat plan — see the spec's Future-work section).

**Tech Stack:** POSIX/busybox `sh` (`set -o pipefail`), Python 3 `subprocess`, Docker (plugin image rebuilds).

**Spec:** [docs/superpowers/specs/2026-05-21-task-warning-state-design.md](../specs/2026-05-21-task-warning-state-design.md) (Tier 4 section)

---

## Notes for executors

Same project-level overrides as every prior tier:

- **Tests are user-owned.** Do not write tests, do not run tests.
- **Git is user-owned.** No mutating git commands; the user commits at the end of the tier.
- **No per-task STOP.** Run through end-to-end.
- **Verification an agent can do:** `sh -n <file>` (and `shellcheck` if present — see caveat) for shell wrappers; `python3 -m py_compile <file>` for Python wrappers. **Image rebuild and runtime smoke tests are user-owned** (they need Docker + live targets, which agents don't run here).
- **`shellcheck` caveat:** `set -o pipefail` is not POSIX, so shellcheck under `-s sh` will warn. That's expected — the target `/bin/sh` is busybox ash, which supports it. Do not "fix" the warning by removing pipefail.

The model these wrappers feed (for reference, do not re-implement): worker computes `softSignal = (exit != 0) || droppedObjects`, `actionable = non-nil valid objects`, then `softSignal && !actionable → ERROR`, `softSignal && actionable → WARNING`, else DONE ([g3worker.go:792-805](../../../src/g3worker/g3worker.go#L792)).

---

## Task 1: `nmap` — recover exit status through the tee pipe

**Files:**
- Modify: `plugins/recon/nmap/g3p.sh`

- [ ] **Step 1: Replace the wrapper body**

Current:

```sh
#!/bin/sh
set -e
jsonfile=`cat`
nmap -oX /artifacts/nmap.xml "$@" | tee /artifacts/nmap.txt 1>&2
cat /artifacts/nmap.xml | /usr/bin/g3i "$jsonfile"
exit 0
```

Replace with:

```sh
#!/bin/sh
set -e
jsonfile=`cat`
# Recover nmap's real exit status through the tee pipe (pipefail) without
# aborting — the importer must still run so any partial results reach the
# scanner. nmap exits 0 even when the host is down / no ports are open, so a
# non-zero status here is a genuine nmap failure, not "found nothing".
set -o pipefail
rc=0
nmap -oX /artifacts/nmap.xml "$@" | tee /artifacts/nmap.txt 1>&2 || rc=$?
cat /artifacts/nmap.xml | /usr/bin/g3i "$jsonfile"
exit $rc
```

- [ ] **Step 2: Syntax-check**

Run: `sh -n plugins/recon/nmap/g3p.sh`
Expected: no output (valid).

---

## Task 2: `subfinder` — recover exit status through the tee pipe

**Files:**
- Modify: `plugins/recon/subfinder/g3p.sh`

- [ ] **Step 1: Replace the wrapper body**

Current (note the trailing whitespace on the subfinder line — drop it):

```sh
#!/bin/sh
set -e
#cat /root/.config/subfinder/config.yaml 1>&2
#cat /root/.config/subfinder/provider-config.yaml 1>&2
subfinder -v -oJ -o /artifacts/subfinder.json -d "$1" | tee /artifacts/subfinder.txt 1>&2 
cat /artifacts/subfinder.json | /usr/bin/g3i r
exit 0
```

Replace with:

```sh
#!/bin/sh
set -e
#cat /root/.config/subfinder/config.yaml 1>&2
#cat /root/.config/subfinder/provider-config.yaml 1>&2
# Recover subfinder's real exit status through the tee pipe. subfinder exits 0
# even when zero subdomains are found, so a non-zero status here is a real error.
set -o pipefail
rc=0
subfinder -v -oJ -o /artifacts/subfinder.json -d "$1" | tee /artifacts/subfinder.txt 1>&2 || rc=$?
cat /artifacts/subfinder.json | /usr/bin/g3i r
exit $rc
```

- [ ] **Step 2: Verify the base shell supports `pipefail`**

The base image is `projectdiscovery/subfinder:latest` (Alpine-based). Confirm its `/bin/sh` accepts `set -o pipefail`:
Run: `docker run --rm --entrypoint sh projectdiscovery/subfinder:latest -c 'set -o pipefail && echo ok'`
Expected: `ok`. **If this errors** (shell lacks pipefail), use the portable fallback instead — capture to a file, then tee to the log:

```sh
#!/bin/sh
set -e
rc=0
subfinder -v -oJ -o /artifacts/subfinder.json -d "$1" > /artifacts/subfinder.txt 2>&1 || rc=$?
cat /artifacts/subfinder.txt 1>&2
cat /artifacts/subfinder.json | /usr/bin/g3i r
exit $rc
```

(This fallback loses live log streaming — output appears after subfinder finishes. Only use it if pipefail is unavailable.)

- [ ] **Step 3: Syntax-check**

Run: `sh -n plugins/recon/subfinder/g3p.sh`
Expected: no output.

---

## Task 3: `wafw00f` — recover exit status through the tee pipe

**Files:**
- Modify: `plugins/recon/wafw00f/g3p.sh`

- [ ] **Step 1: Replace the wrapper body**

Current:

```sh
#!/bin/sh
set -e
wafw00f -a -o /artifacts/wafw00f.json "$1" | tee /artifacts/wafw00f.txt 1>&2
cat /artifacts/wafw00f.json | python3 /usr/bin/g3i r
exit 0
```

Replace with:

```sh
#!/bin/sh
set -e
# Recover wafw00f's real exit status through the tee pipe. wafw00f exits 0
# whether or not a WAF is detected; exit 1 is a real error (bad input, etc).
set -o pipefail
rc=0
wafw00f -a -o /artifacts/wafw00f.json "$1" | tee /artifacts/wafw00f.txt 1>&2 || rc=$?
cat /artifacts/wafw00f.json | python3 /usr/bin/g3i r
exit $rc
```

- [ ] **Step 2: Syntax-check**

Run: `sh -n plugins/recon/wafw00f/g3p.sh`
Expected: no output. (Base image `python:3-alpine` → busybox ash supports pipefail.)

---

## Task 4: `testssl` — propagate the real exit code, folded across the per-target loop

**Files:**
- Modify: `plugins/recon/testssl/g3p.py`

testssl's exit code is already well-behaved: `0` on a normal run (including when individual sub-tests like the CAA-DNS probe fail), non-zero only on a genuine failure (connect/DNS/tool error). So just stop forcing `exit 0` and propagate. The wrapper has two mutually-exclusive branches (URL test, host loop) — capture in both, fold to one exit.

- [ ] **Step 1: Add a fold accumulator next to `output_data`**

Find:

```python
# Here we will have the output data.
output_data = []
```

Replace with:

```python
# Here we will have the output data.
output_data = []

# Worst exit code seen across all testssl invocations (URL branch or the
# per-target host loop). testssl exits 0 on a normal run even when sub-tests
# fail; a non-zero code is a genuine failure. Fold: any non-zero → non-zero.
worst_rc = 0
```

- [ ] **Step 2: Capture the return code in the URL branch**

Find (in the `if "url" in input_data:` branch):

```python
            with open("/artifacts/testssl.txt", "wb") as logfile:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in proc.stdout:
                    sys.stderr.buffer.write(line)
                    sys.stderr.buffer.flush()
                    logfile.write(line)
                proc.wait()
```

Replace with:

```python
            with open("/artifacts/testssl.txt", "wb") as logfile:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in proc.stdout:
                    sys.stderr.buffer.write(line)
                    sys.stderr.buffer.flush()
                    logfile.write(line)
                proc.wait()
            if proc.returncode and not worst_rc:
                worst_rc = proc.returncode
```

- [ ] **Step 3: Capture the return code in the host loop**

Find (in the `else:` host branch, inside the per-service loop):

```python
            with open(txt_path, "wb") as logfile:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in proc.stdout:
                    sys.stderr.buffer.write(line)
                    sys.stderr.buffer.flush()
                    logfile.write(line)
                proc.wait()
```

Replace with:

```python
            with open(txt_path, "wb") as logfile:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in proc.stdout:
                    sys.stderr.buffer.write(line)
                    sys.stderr.buffer.flush()
                    logfile.write(line)
                proc.wait()
            if proc.returncode and not worst_rc:
                worst_rc = proc.returncode
```

- [ ] **Step 4: Exit with the folded code**

Find the final line:

```python
# Send the JSON output array over stdout.
json.dump(output_data, sys.stdout)
```

Replace with:

```python
# Send the JSON output array over stdout.
json.dump(output_data, sys.stdout)
sys.stdout.flush()

# Propagate testssl's exit code (folded across all invocations). 0 = clean;
# non-zero = a genuine failure. The worker turns non-zero + data → WARNING,
# non-zero + no data → ERROR.
sys.exit(1 if worst_rc else 0)
```

- [ ] **Step 5: Syntax-check**

Run: `python3 -m py_compile plugins/recon/testssl/g3p.py`
Expected: no output.

---

## Task 5: `hydra` — propagate the real exit code (0 = clean, incl. no creds)

**Files:**
- Modify: `plugins/attack/hydra/g3p.py`

hydra's `main()` returns `0` on a clean completion **whether or not valid credentials were found** — the return depends on error/incomplete-target counts, not on `found` (verified in [hydra.c](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra.c): `if (error || j != 0 || exit_condition < 0) return -1; else return 0;`). Non-zero paths are `return -1` → exit **255** (targets disabled due to too many errors) and `_exit(2)` from the signal handler. So the rule is the simple one — same as nmap: **`0` → benign, any non-zero → real problem.** "No creds found" needs no special-casing; hydra already returns 0 for it.

- [ ] **Step 1: Add a fold accumulator next to `output_data`**

Find:

```python
# Here we will have the output data.
output_data = []
```

Replace with:

```python
# Here we will have the output data.
output_data = []

# Worst exit code seen across all hydra invocations. hydra returns 0 on a
# clean run whether or not creds were found; non-zero (255 = errors/disabled
# targets, 2 = killed by signal) is a real problem. Fold: any non-zero → non-zero.
worst_rc = 0
```

- [ ] **Step 2: Capture the return code from each hydra run**

Find:

```python
        # Run Hydra, piping stdout and stderr directly to our stderr.
        # This will send all of the text output into the G3 logs.
        # On error an exception is raised.
        subprocess.run(args, stdout = sys.stderr, stderr = sys.stderr, check=False)
```

Replace with:

```python
        # Run Hydra, piping stdout and stderr directly to our stderr.
        # This will send all of the text output into the G3 logs.
        result = subprocess.run(args, stdout = sys.stderr, stderr = sys.stderr, check=False)
        # hydra returns 0 on a clean run (creds found OR none); any non-zero
        # (255 = errors, 2 = signal) is a real failure worth flagging.
        if result.returncode and not worst_rc:
            worst_rc = result.returncode
```

- [ ] **Step 3: Exit with the folded code**

Find the final line:

```python
# Send the JSON output array over stdout.
json.dump(output_data, sys.stdout)
```

Replace with:

```python
# Send the JSON output array over stdout.
json.dump(output_data, sys.stdout)
sys.stdout.flush()

# Propagate hydra's exit code (folded across all targets). 0 = clean (creds
# found or legitimately none); non-zero = a real failure. The worker turns
# non-zero + data → WARNING, non-zero + no data → ERROR.
sys.exit(1 if worst_rc else 0)
```

- [ ] **Step 4: Syntax-check**

Run: `python3 -m py_compile plugins/attack/hydra/g3p.py`
Expected: no output.

---

## Task 6: Confirm the no-change wrappers

No edits — this task is a documented confirmation so the executor doesn't "fix" them:

- [ ] **`dig`** ([plugins/misc/dig/g3p.sh](../../../plugins/misc/dig/g3p.sh)) — already correct. `set -e` propagates dig's status, and dig's codes are clean: `0` = answer received (incl. NXDOMAIN), `9` = no reply (real failure), `1/8/10` = other real errors. Leave as-is.
- [ ] **`error`** ([plugins/debug/error/g3p.sh](../../../plugins/debug/error/g3p.sh)) — `exit 1` with no output → ERROR. Correct, leave as-is.
- [ ] **`force-exec` / `passthrough`** — `exit 0`, echo input → DONE. Correct, leave as-is.
- [ ] **`magenta`** (reporter) — out of scope; reporters use the separate `markReportTerminal` path.

---

## Final verification & rollout

- [ ] **Syntax sweep:** `sh -n` on the three changed `.sh` files; `python3 -m py_compile` on the two changed `.py` files. All clean.
- [ ] **Image rebuilds (user-owned):** rebuild the five affected plugin images (`nmap`, `subfinder`, `wafw00f`, `testssl`, `hydra`).
- [ ] **Runtime smoke (user-owned):** for at least one piped wrapper and one Python wrapper, run against (a) a reachable target → expect DONE, and (b) an unreachable target → expect ERROR (non-zero + no data); confirm a partial/degraded run surfaces WARNING amber in the TUI.

## Out of scope (tracked elsewhere)

- **`nikto`** — needs a Dockerfile source-install at the 2.6.0 tag (the version where the exit-1-on-findings regression is fixed) plus importer compatibility with 2.6.0's changed report format. Separate plan; see the spec's Future-work section.
- **Operator-tunable WARNING strictness** — deferred (spec Future-work).
