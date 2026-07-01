# De-Issue Golismero & Externalize Reporting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove Golismero's built-in Markdown reporter and all i18n, stop plugins from producing `_type:"issue"` objects (refactoring them into asset/artifact producers), and route every `report` surface to the Magenta plugin.

**Architecture:** The engine's issue-handling plumbing is *retained* (Magenta will be the future sole issue producer). We delete only the in-process `MarkdownReporter` + i18n, and rewrite the four issue-producing plugins so each emits its **input asset enriched with `_artifacts`** (the existing nmap host pattern) instead of an issue. hydra additionally emits a new `credential` asset type. `report` becomes a dispatch of the already-registered Magenta reporter plugin.

**Tech Stack:** Go 1.25 (multiple binaries under `src/`), Python 3 plugin scripts, Jsonnet `.g3p` definitions, Docker, MQTT/Mongo/Redis/MariaDB. **No test harness exists in this repo** — verification is `make bin` / `go build` for compilation, `g3config` for plugin re-registration, and functional command runs. Each task's verification reflects that.

**Design spec:** [docs/superpowers/specs/2026-06-03-de-issue-and-externalize-reporting-design.md](../specs/2026-06-03-de-issue-and-externalize-reporting-design.md)

**Git:** The repo owner handles all commits — **do not run git**. "Commit" steps are intentionally omitted. Do not pause between phases unless a genuine architectural decision surfaces.

---

## Phase ordering

1. **Phase 1 — Reporter + i18n removal** (Go only; engine issue-handling untouched).
2. **Phase 2 — De-issue the plugins** (Python + `.g3p`; nmap, testssl, nikto).
3. **Phase 3 — `credential` type + hydra**.
4. **Phase 4 — `report` → Magenta rewiring** (server, g3cli, local g3, TUI).

Each phase ends green: all seven binaries build and `g3config` registers cleanly.

---

## File structure (what changes)

**Deleted files:**
- `src/g3lib/report.go`
- `plugins/recon/nmap/g3m.py`, `plugins/recon/nmap/i18n/`
- `plugins/attack/nikto/g3m.py`, `plugins/attack/nikto/i18n/`
- `plugins/recon/testssl/g3m.py`, `plugins/recon/testssl/i18n/`, `plugins/recon/testssl/g3i.py`
- `plugins/attack/hydra/g3m.py`, `plugins/attack/hydra/i18n/`
- `i18n/` (repo-root global strings), `config/g3strings.json`, `config/g3templates.json`

**Modified Go:** `src/g3lib/{common.go,plugin.go,go.mod,go.sum}`, `src/g3config/g3config.go`, `src/g3api/g3api.go`, `src/g3scanner/g3scanner.go`, `src/g3/g3.go`, `src/g3cli/g3cli.go`, `src/g3tui/internal/ui/report.go`, `src/g3tui` client.

**Modified plugins:** `nmap/g3i.py`, `nmap.g3p`, `nmap-fast.g3p`, `nmap-full.g3p`, `testssl/g3p.py`, `testssl.g3p`, `nikto/g3p.sh`, `nikto/g3i.py`, `nikto.g3p`, `nikto-slow.g3p`, `hydra/g3p.py`, `hydra/g3i.py`, `hydra.g3p`.

---

# Phase 1 — Reporter + i18n removal

### Task 1.1: Delete the built-in reporter file and its chart dependency

**Files:**
- Delete: `src/g3lib/report.go`
- Modify: `src/g3lib/go.mod`, `src/g3lib/go.sum`

- [ ] **Step 1: Delete the reporter source**

```bash
rm src/g3lib/report.go
```

- [ ] **Step 2: Remove the go-chart dependency**

Edit `src/g3lib/go.mod`: delete the line requiring `github.com/wcharczuk/go-chart` (the v2 `+incompatible` line, ~line 22). Then tidy:

```bash
cd src/g3lib && go mod tidy
```

`go mod tidy` rewrites `go.sum`, dropping go-chart and its transitive deps (e.g. `golang/freetype`, `image`) if nothing else uses them.

- [ ] **Step 3: Verify g3lib still builds**

Run: `cd src/g3lib && go build ./...`
Expected: build fails *only* with references to now-missing `report.go` symbols (`NewMarkdownReporter`, `MarkdownReporter`, `DefaultConfig`, `ReportConfig`) from other packages — those are fixed in Tasks 1.2–1.4. `g3lib` itself should compile (report.go was self-contained within the package except for callers in other modules).

> Note: if `DefaultConfig`/`ReportConfig` live in `report.go`, their only consumers are the report call sites removed below. Confirm via `grep -rn "DefaultConfig\|NewMarkdownReporter\|MarkdownReporter" src/`.

### Task 1.2: Remove the `/scan/report` endpoint and reporter wiring from g3api

**Files:**
- Modify: `src/g3api/g3api.go`

- [ ] **Step 1: Delete the `POST /scan/report` handler**

In `src/g3api/g3api.go`, remove the `/scan/report` route registration and its handler function (the block around lines 1021–1096 that builds a `NewMarkdownReporter(...)` and returns `{"report":...,"errors":...}`).

- [ ] **Step 2: Delete the reporter startup wiring**

Remove the `g3lib.LoadG3Strings(...)` and `g3lib.LoadPluginTemplates(...)` calls in g3api startup (~lines 295–298) and any variables (`i18nStrings`, `pluginTemplatesCache`) that were captured solely for the `/scan/report` handler closure.

- [ ] **Step 3: Verify**

Run: `cd src/g3api && go build`
Expected: PASS. If it fails on an undefined `LoadG3Strings`/`LoadPluginTemplates`, those are removed in Task 1.5 — sequence Task 1.5 before re-running, or stub-confirm by grep that no other g3api reference remains.

### Task 1.3: Remove the built-in report path from g3scanner

**Files:**
- Modify: `src/g3scanner/g3scanner.go`

- [ ] **Step 1: Delete `runBuiltinReport` and the bare-`report` branch**

Remove the `runBuiltinReport(...)` function (~lines 1284–1406) and, in `ScanRunner`, the branch that calls it for a bare `report` directive with no tool (the `msg.Report.Tool == ""` branch, ~lines 1185–1196). **Keep** the `msg.Report.Tool != ""` branch that dispatches a plugin reporter (~1197–1218) — that is the Magenta path.

> Phase 4 (Task 4.1) re-points the bare-`report` directive to Magenta. For Phase 1, deleting the in-process branch is correct; until 4.1, a bare `report` simply dispatches nothing. That intermediate state is acceptable (no production callers).

- [ ] **Step 2: Delete the i18n loads in g3scanner main**

Remove the `LoadG3Strings`/`LoadPluginTemplates` calls in `g3scanner` main (~lines 113–114) and stop threading `pluginTemplatesCache`/`i18nStrings` into `ScanRunner`'s signature and call sites.

- [ ] **Step 3: Verify**

Run: `cd src/g3scanner && go build`
Expected: PASS (after Task 1.5 removes the i18n functions; otherwise the only errors reference i18n symbols removed there).

### Task 1.4: Gut the in-process `ReportCmd.Run` bodies (CLI placeholders)

**Files:**
- Modify: `src/g3/g3.go`, `src/g3cli/g3cli.go`

- [ ] **Step 1: Replace g3 local `ReportCmd.Run` body with a temporary stub**

In `src/g3/g3.go`, replace the body of `(cmd *ReportCmd) Run()` (~961–1005, the `NewMarkdownReporter(...).Build("en",...)` logic) with a temporary error so the binary still builds. Keep the `ReportCmd` struct registration:

```go
func (cmd *ReportCmd) Run() error {
	return fmt.Errorf("the built-in reporter has been removed; reporting is now handled by the magenta plugin (rewired in Phase 4)")
}
```

- [ ] **Step 2: Replace g3cli `ReportCmd.Run` body with the same temporary stub**

In `src/g3cli/g3cli.go`, replace the body of `(cmd *ReportCmd) Run()` (~1017–1079, the `/scan/report` call) with:

```go
func (cmd *ReportCmd) Run() error {
	return fmt.Errorf("the built-in reporter has been removed; reporting is now handled by the magenta plugin (rewired in Phase 4)")
}
```

> These stubs are replaced with real Magenta dispatch in Phase 4 (Tasks 4.2, 4.3). They exist so Phase 1 leaves every binary buildable.

- [ ] **Step 3: Verify**

Run: `cd src/g3 && go build` and `cd src/g3cli && go build`
Expected: both build. Remove any now-unused imports flagged by the compiler.

### Task 1.5: Remove i18n loading/parsing from g3lib and g3config

**Files:**
- Modify: `src/g3lib/common.go`, `src/g3lib/plugin.go`, `src/g3config/g3config.go`

- [ ] **Step 1: Remove the string/template loaders in g3lib**

- In `src/g3lib/common.go`: delete `LoadG3Strings`, the `G3TranslatedStrings`/`G3TranslatedStringsForLanguage` types, and the `G3STRINGS`/`G3TEMPLATES` constants (~lines 32–36, 170–199).
- In `src/g3lib/plugin.go`: delete `LoadPluginTemplates`, `G3PluginTemplates`, `G3PluginTemplatesCache` (~lines 107–161).

Keep `template.go`'s `ExpandTemplate`/`BuildTemplate`/`ExpandTemplateArray` (used by conditions/commands/fingerprints).

- [ ] **Step 2: Remove the i18n parsers in g3config**

In `src/g3config/g3config.go`: delete `ParseLanguageFiles` and `ParsePluginTemplates` (~lines 27–148), the calls that invoke them and write `config/g3strings.json` / `config/g3templates.json`, and the now-unused imports `golang.org/x/text/language` and `golang.org/x/text/language/display` (~lines 14–15). Remove the per-plugin `i18n/` directory walk.

- [ ] **Step 3: Verify all i18n references are gone**

Run: `grep -rn "LoadG3Strings\|LoadPluginTemplates\|G3TranslatedStrings\|ParseLanguageFiles\|ParsePluginTemplates\|g3strings\|g3templates\|x/text/language" src/`
Expected: no matches.

- [ ] **Step 4: Build the affected binaries**

Run: `cd src && make ../bin/g3config ../bin/g3api ../bin/g3scanner`
Expected: all build.

### Task 1.6: Flatten `G3Plugin.Description` from `map[string]string` to `string`

**Files:**
- Modify: `src/g3lib/plugin.go`, `src/g3config/g3config.go`, `src/g3api/g3api.go`, `src/g3/g3.go`

- [ ] **Step 1: Change the struct field**

In `src/g3lib/plugin.go:79`, change:

```go
	Description map[string]string   `json:"description"`                                    // Description for humans, translated.
```
to:
```go
	Description string              `json:"description"`                                    // Description for humans.
```

- [ ] **Step 2: Update `G3Plugin.String()`**

In `src/g3lib/plugin.go` (~line 92), change `plugin.Description["en"]` to `plugin.Description`.

- [ ] **Step 3: Update the g3config parse + auto-fill**

In `src/g3config/g3config.go`, where the `.g3p` `description` object is parsed into the registry (and the auto-fill at ~line 347), collapse the `{en: "..."}` Jsonnet object to its English string. The `.g3p` files keep `description: { en: "..." }` on disk; g3config reads `description.en` (falling back to empty) and stores a plain string in `config/g3plugins.json`.

```go
// where the raw .g3p description (map[string]string) is read:
desc := ""
if raw, ok := rawDescription["en"]; ok {
	desc = raw
}
plugin.Description = desc
```

- [ ] **Step 4: Update read sites in g3api and g3**

- `src/g3api/g3api.go` (~line 1457, `/plugin/list`): `plugin.Description["en"]` → `plugin.Description`.
- `src/g3/g3.go` (~lines 456, 650, plugin listings): `plugin.Description["en"]` → `plugin.Description`.

- [ ] **Step 5: Verify**

Run: `grep -rn 'Description\["en"\]\|Description\[' src/` → no matches. Then `cd src && make all` (all seven binaries).
Expected: every binary builds.

### Task 1.7: Keep the TUI `<img>` fallback, rewire its fetch later

**Files:**
- Modify: `src/g3tui/internal/ui/report.go` (comment only in Phase 1)

- [ ] **Step 1: Update the comment to reference Magenta**

In `src/g3tui/internal/ui/report.go` (~lines 356–364), update the comment block so it explains that **Magenta** emits the base64 pie-chart `<img>` blocks (not "the server's report template"). **Do not** remove `htmlImgWithPRe`/`htmlImgRe` — they remain needed.

- [ ] **Step 2: Verify the TUI still builds**

Run: `cd src && make ../bin/g3tui`
Expected: PASS. (The `ReportPane.fetchCmd` rewire to dispatch+artifacts is Task 4.4; in Phase 1 it still calls `GetReport`, which still compiles — the endpoint is gone but the client method is rewired in Phase 4.)

> If `GetReport` in the g3tui client referenced the deleted `/scan/report` such that it no longer compiles, leave the client method returning an error stub here and finish the rewire in Task 4.4. Prefer the minimal change that keeps `g3tui` building.

### Task 1.8: Full Phase-1 build gate

- [ ] **Step 1: Build everything**

Run: `cd src && make all`
Expected: all seven binaries (`g3`, `g3api`, `g3cli`, `g3config`, `g3scanner`, `g3tui`, `g3worker`) build with no reporter/i18n references remaining.

- [ ] **Step 2: Confirm no dangling references**

Run: `grep -rn "report.go\|MarkdownReporter\|go-chart\|wcharczuk" src/` → no matches.

---

# Phase 2 — De-issue the plugins (nmap, testssl, nikto)

**Shared convention:** the container entrypoint already receives the input G3Data object (nmap `g3p.sh`: `jsonfile=$(cat)`; testssl `g3p.py`: `json.load(sys.stdin)`). Each tool emits its input asset enriched with `_artifacts`. Per-plugin mergers and `i18n/` are deleted; `merger:` declarations are removed from `.g3p` (mergers are optional — `Merger *G3MergerCommand ... validate:"omitempty"`).

### Task 2.1: nmap — drop the plaintext-ports issue, keep host emission

**Files:**
- Modify: `plugins/recon/nmap/g3i.py`
- Delete: `plugins/recon/nmap/g3m.py`, `plugins/recon/nmap/i18n/`
- Modify: `plugins/recon/nmap/nmap.g3p`, `nmap-fast.g3p`, `nmap-full.g3p`

- [ ] **Step 1: Remove the issue block from the importer**

In `plugins/recon/nmap/g3i.py`, delete lines ~426–489 — the entire "Report all plaintext open ports as a vulnerability" block (the `severity`/`plaintext_ports` computation, the `issue = {...}` with `"_type": "issue"`, `vulns.append(issue)`, the script-vuln TODO, and `output.extend(vulns)`). The host emission above (the `if input_data is not None:` / `else:` blocks ending ~424) is **unchanged**. After this, `main()` ends with:

```python
    # Convert the output array to JSON and send it over stdout.
    json.dump(output, sys.stdout)
```

Also remove the now-unused `vulns = []` initialization (search upward in `main()`), and any helper used *only* by the deleted block (`get_open_plaintext_ports`, `has_http`, `has_https`, `HTTP_DESC`/`HTTP_ALT_DESC` handling) — verify each with `grep -n "<name>" plugins/recon/nmap/g3i.py` and remove only if the issue block was its sole caller.

- [ ] **Step 2: Delete the merger and i18n**

```bash
rm plugins/recon/nmap/g3m.py
rm -r plugins/recon/nmap/i18n
```

- [ ] **Step 3: Update the three `.g3p` files**

In `nmap.g3p`:
- `llm.produces`: `["host", "issue"]` → `["host"]`.
- Delete the entire `merger: { ... }` block (~lines 106–116).
- Keep `importer:` (it still returns `host`).

In `nmap-fast.g3p` and `nmap-full.g3p`:
- `llm.produces`: `["host", "issue"]` → `["host"]`.

- [ ] **Step 4: Re-register plugins**

Run: `./bin/g3config` (or the documented config invocation, e.g. `cd src && ../bin/g3config` against the plugins dir).
Expected: nmap/nmap-fast/nmap-full register with no merger and `produces: ["host"]`; no errors.

- [ ] **Step 5: Functional check (importer parses, emits host only)**

Run the importer against a sample nmap XML (use an existing artifact or generate one):

```bash
cat sample-nmap.xml | python3 plugins/recon/nmap/g3i.py
```
Expected: JSON array of `host` objects, **no** object with `"_type":"issue"`.

### Task 2.2: testssl — entrypoint echoes input enriched; delete importer/merger

**Files:**
- Modify: `plugins/recon/testssl/g3p.py`
- Delete: `plugins/recon/testssl/g3i.py`, `plugins/recon/testssl/g3m.py`, `plugins/recon/testssl/i18n/`
- Modify: `plugins/recon/testssl/testssl.g3p`

- [ ] **Step 1: Rewrite the wrapper to echo the input asset**

In `plugins/recon/testssl/g3p.py`, replace the issue-producing logic (the per-target `/usr/bin/g3i` calls that build `new_data`/`output_data` from SSL findings) with collecting the produced artifact filenames and emitting the **input object** once, enriched.

For the URL branch (replacing ~lines 77–86): drop the `g3i` call; just record the artifacts. For the host branch (replacing ~lines 191–213): drop the `g3i` call; accumulate `artifacts` filenames. After the loops, emit the input enriched:

```python
# Emit the input asset, enriched with the artifacts testssl produced.
# Magenta re-parses these files to generate SSL issues; Golismero only
# links the artifacts to the asset for the data graph.
if collected_artifacts:
    enriched = dict(input_data)
    enriched["_artifacts"] = sorted(set(collected_artifacts))
    # Distinct fingerprint so the enriched node doesn't collide with the
    # input node (same pattern as nmap stamping "nmap <cidr>").
    fp_key = input_data.get("url") or input_data.get("ipv4") or input_data.get("ipv6") or ""
    enriched["_fp"] = ["testssl " + fp_key]
    output_data.append(enriched)
```

Where `collected_artifacts` is a list you append to as each `txt_path`/`json_path` (host branch) or `testssl.txt`/`testssl.json` (url branch) is written. Keep all the testssl-execution and artifact-writing code intact — only the issue-generation via `g3i` is removed.

- [ ] **Step 2: Delete importer, merger, i18n**

```bash
rm plugins/recon/testssl/g3i.py
rm plugins/recon/testssl/g3m.py
rm -r plugins/recon/testssl/i18n
```

- [ ] **Step 3: Update `testssl.g3p`**

- `llm.produces`: `["issue"]` → `["host", "url"]`.
- Each command `returns: "issue"` → remove `returns` (the echoed input already carries its own `_type`) **or** set to the matching input type; simplest is to delete the `returns` line from all three commands.
- Delete the `importer: { returns: "issue" }` block and the `merger: {}` block.

- [ ] **Step 4: Fix the Dockerfile if it installed g3i**

Check `plugins/recon/testssl/Dockerfile` for a line copying `g3i.py` → `/usr/bin/g3i`. Remove it (g3i.py no longer exists). Keep the g3p.py entrypoint install.

```bash
grep -n "g3i\|g3m" plugins/recon/testssl/Dockerfile
```

- [ ] **Step 5: Re-register**

Run: `./bin/g3config`
Expected: testssl registers with `produces: ["host","url"]`, no importer/merger; no errors.

### Task 2.3: nikto — entrypoint captures input; tiny g3i echoes it

**Files:**
- Modify: `plugins/attack/nikto/g3p.sh`, `plugins/attack/nikto/g3i.py`
- Delete: `plugins/attack/nikto/g3m.py`, `plugins/attack/nikto/i18n/`
- Modify: `plugins/attack/nikto/nikto.g3p`, `nikto-slow.g3p`

- [ ] **Step 1: Capture the input object in the entrypoint and pass it to g3i**

In `plugins/attack/nikto/g3p.sh`, capture stdin (the input URL object) and pass it to `g3i`. Replace:

```sh
nikto.pl ... -o /artifacts/nikto "$@" | tee /artifacts/nikto.txt 1>&2 || rc=$?
cat /artifacts/nikto.csv | /usr/bin/g3i "$@"
exit $rc
```
with:
```sh
jsonfile=`cat`
nikto.pl ... -o /artifacts/nikto "$@" | tee /artifacts/nikto.txt 1>&2 || rc=$?
printf '%s' "$jsonfile" | /usr/bin/g3i
exit $rc
```

(Keep the exact `nikto.pl ...` line as-is; only add the `jsonfile=$(cat)` capture at the top and change the final `g3i` invocation to receive the input object on stdin.)

- [ ] **Step 2: Replace g3i.py with a tiny echo importer**

Replace the entire contents of `plugins/attack/nikto/g3i.py`:

```python
#!/usr/bin/env python3
# Nikto no longer produces issues. It runs the scan, writes artifacts
# (nikto.txt, nikto.csv) for Magenta to parse, and echoes its input URL
# asset enriched with _artifacts so the data graph links the artifacts to
# the asset (same pattern as nmap emitting an enriched host).
import sys
import json

ARTIFACTS = ["nikto.txt", "nikto.csv"]


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        json.dump([], sys.stdout)
        return
    obj = json.loads(raw)
    enriched = dict(obj)
    enriched["_artifacts"] = ARTIFACTS
    host = obj.get("host") or obj.get("url") or ""
    enriched["_fp"] = ["nikto " + host]
    json.dump([enriched], sys.stdout)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Delete merger and i18n**

```bash
rm plugins/attack/nikto/g3m.py
rm -r plugins/attack/nikto/i18n
```

- [ ] **Step 4: Update `nikto.g3p` and `nikto-slow.g3p`**

In both files:
- `llm.produces`: `["issue"]` → `["url"]`.
- Each command `returns: "issue"` → delete the `returns` line (echoed input carries its `_type`).
- `importer: { returns: "issue" }` → `importer: {}` (the importer still runs in-container via the entrypoint; it now echoes). Remove `returns`.
- Delete the `merger: {}` block.

- [ ] **Step 5: Re-register + functional check**

Run: `./bin/g3config`. Then:
```bash
echo '{"_type":"url","url":"http://example.com/","host":"example.com","scheme":"http","_fp":["g3 target http://example.com/"]}' | python3 plugins/attack/nikto/g3i.py
```
Expected: a single-element array echoing the url object with `"_artifacts":["nikto.txt","nikto.csv"]` and `"_fp":["nikto example.com"]`; **no** `"_type":"issue"`.

### Task 2.4: Phase-2 build + register gate

- [ ] **Step 1:** `cd src && make all` → all binaries build.
- [ ] **Step 2:** `./bin/g3config` → all plugins register; `grep -rn '"issue"' plugins/*/  plugins/*/*.g3p` shows `issue` only in retained engine-level contexts (none in the refactored `.g3p` files).

---

# Phase 3 — `credential` asset type + hydra

### Task 3.1: Document the `credential` type

**Files:**
- Modify: `src/g3lib/common.go` (doc comment near the `_type` taxonomy / `IsValidData`)

- [ ] **Step 1: Add `credential` to the type taxonomy docs**

`IsValidData` already accepts any `^[a-z]+$` type, so no validation code changes. Add `credential` to the documented taxonomy comment alongside `host`/`url`/`domain`/`cidr`/`issue`/`nil`, noting its conventional fields: `host`, `port`, `service`, `login`, `password`.

- [ ] **Step 2: Verify build**

Run: `cd src/g3lib && go build ./...`
Expected: PASS (comment-only change).

### Task 3.2: hydra — echo input enriched + emit `credential` objects

**Files:**
- Modify: `plugins/attack/hydra/g3p.py`, `plugins/attack/hydra/g3i.py`
- Delete: `plugins/attack/hydra/g3m.py`, `plugins/attack/hydra/i18n/`
- Modify: `plugins/attack/hydra/hydra.g3p`

- [ ] **Step 1: Convert `g3i.py` from issue-producer to credential-producer**

Rewrite `plugins/attack/hydra/g3i.py` so `_finish_issue` becomes credential emission: instead of one `_type:"issue"` object with a `credentials` list, emit one `_type:"credential"` object per found credential. Replace the issue construction (current lines ~57–129) so that, per parsed `(hostname, port, service, login, password)`, it appends:

```python
cred = {
    "_type": "credential",
    "_tool": "hydra",
    "_fp": ["hydra %s:%s" % (hostname, port)],
    "host": hostname,
    "port": port,
    "service": service,
    "login": login,
    "password": password,
}
output.append(cred)
```

Drop `severity`/`affects`/`taxonomy`/`references` and the `_type:"nil"` empty-issue path (an empty run simply yields `[]`). Keep the regex parsing (`re_start`, `re_result`) and the file/stdin entry logic. The script still reads a hydra output file path (argv[1]) as it does today (called per-port by the wrapper).

- [ ] **Step 2: Echo the input asset in the wrapper**

In `plugins/attack/hydra/g3p.py`, the wrapper already reads `input_data` and accumulates `output_data` from per-port `g3i` calls (now credentials). After the loops, also append the enriched input host (so the host node carries the hydra artifacts):

```python
# Emit the input host asset enriched with hydra's artifacts, alongside any
# credential objects parsed by g3i.
artifact_files = sorted(set(
    "hydra.%s.%d.txt" % (ip_slug(ip), int(s["port"]))
    for ip in (input_data.get("ipv4",""), input_data.get("ipv6",""))
    if ip and ip_slug(ip)
    for s in input_data.get("services", []) if "port" in s
))
enriched = dict(input_data)
enriched["_artifacts"] = artifact_files
enriched["_fp"] = ["hydra " + (input_data.get("ipv4") or input_data.get("ipv6") or "")]
output_data.append(enriched)
```

> Implementer note: align `artifact_files` with the exact `output_file` names the wrapper passes to hydra (`/artifacts/hydra.<slug>.<port>.txt`). Only include files actually written (a port hydra skipped writes none) — gate on the same `SUPPORTED_PROTOCOLS` filter, or stat the files before listing. Keep it simple: list the files that exist under `/artifacts/` matching `hydra.*.txt`.

- [ ] **Step 3: Delete merger and i18n**

```bash
rm plugins/attack/hydra/g3m.py
rm -r plugins/attack/hydra/i18n
```

- [ ] **Step 4: Update `hydra.g3p`**

- Add `llm` block if absent, or set `llm.produces: ["host", "credential"]`, `accepts: ["host"]`. (hydra.g3p currently has no `llm` block — add one mirroring the other plugins, or skip if `llm` is optional; it is `validate:"omitempty"`.)
- Each command `returns: "issue"` → delete the `returns` line (objects self-type).
- `importer: { returns: "issue" }` → `importer: { returns: "credential" }` (standalone `g3 import hydra <file>` now yields credentials).
- Delete the `merger: {}` block.

- [ ] **Step 5: Re-register + functional check**

Run: `./bin/g3config`. Then test the credential parser against a sample hydra output file:

```bash
printf '# Hydra v9.2 run at 2023-06-30 10:33:37 on localhost ftp (hydra -l u -p p -o x ftp://localhost)\n[21][ftp] host: localhost   login: username   password: password\n' > /tmp/test.hydra
python3 plugins/attack/hydra/g3i.py /tmp/test.hydra
```
Expected: a JSON array with one `{"_type":"credential", "host":"localhost", "port":"21", "service":"ftp", "login":"username", "password":"password", ...}` object; no `_type:"issue"`.

### Task 3.3: Phase-3 gate

- [ ] **Step 1:** `cd src && make all` → builds. `./bin/g3config` → registers. `grep -rn "credential" plugins/attack/hydra/` confirms emission.

---

# Phase 4 — `report` → Magenta rewiring

Magenta is already a registered reporter plugin (`plugins/report/magenta/`). The server reporter dispatch path (`/scan/task/dispatch` `kind:report`, worker `SubscribeAsReporter`, `/scan/task/artifacts`) already exists. This phase points the user-facing `report` surfaces at it.

### Task 4.1: Bare `report` directive → magenta (server scripts)

**Files:**
- Modify: `src/g3lib/script.go`, `src/g3scanner/g3scanner.go`

- [ ] **Step 1: Make bare `report` resolve to tool "magenta"**

In `src/g3lib/script.go`'s `report` directive parsing (the `ParsedReport` population), when no tool is given, default `Report.Tool = "magenta"`. Keep the existing validation (tool must exist and implement a reporter) so a missing/unbuilt magenta registration yields a clear parse error.

- [ ] **Step 2: Confirm ScanRunner dispatches it**

In `src/g3scanner/g3scanner.go`, the existing `if parsed.Report != nil { dispatchTask(..., "report", parsed.Report.Tool, ...) }` block now fires for bare `report` (tool resolved to magenta in Step 1). No new code if that block survived Task 1.3; verify it did.

- [ ] **Step 3: Verify**

Run: `cd src && make ../bin/g3scanner ../bin/g3config` → build. Parse-check a script containing a bare `report` line resolves `Report.Tool == "magenta"` (add a temporary debug print or rely on the script `String()` output).

### Task 4.2: `g3cli report` → dispatch magenta + download artifact

**Files:**
- Modify: `src/g3cli/g3cli.go`

- [ ] **Step 1: Implement the dispatch→poll→download flow**

Replace the Task-1.4 stub `(cmd *ReportCmd) Run()` with a flow that reuses the existing endpoints (follow the patterns of other `g3cli` commands and `g3lib.MakeApiRequest`):

1. `POST /scan/task/dispatch` with body `{scanid, kind:"report", tool:"magenta"}` → returns a `taskid`.
2. Poll `POST /scan/tasks/status` (or `/scan/task/status`) for `scanid` until the magenta task is terminal (`DONE`/`ERROR`/`CANCELED`).
3. On `DONE`: `POST /scan/task/artifacts {scanid, taskid}` → stream the report bytes to `cmd.Output` (or stdout). Reuse the streaming/zip-slip-safe download already used elsewhere if present.

Keep the `ReportCmd` flags (`ScanID`, `Output`). Match existing error handling and the `{status,data}` envelope conventions used by sibling commands.

- [ ] **Step 2: Verify build**

Run: `cd src/g3cli && go build`
Expected: PASS.

- [ ] **Step 3: Functional (requires a running stack)**

With `docker compose up` and a completed scan, run `g3cli report --scanid <id> -o report.md`.
Expected: dispatches magenta, waits, writes `report.md`. (Defer to integration; note as manual verification.)

### Task 4.3: `g3 report` (local) → Docker-run magenta against a user-supplied artifacts dir

**Files:**
- Modify: `src/g3/g3.go`

- [ ] **Step 1: Add `--artifacts <dir>` and run the reporter plugin locally**

Replace the Task-1.4 stub `(cmd *ReportCmd) Run()` with logic that:
1. Requires an `--artifacts <dir>` flag (the user-populated input tree) and an `-o/--output <dir-or-file>`.
2. Loads the magenta plugin from the registry.
3. Builds the reporter command via the existing `g3lib.BuildReporterCommand(plugin, preset)` and runs it via `g3lib.RunPluginReporter(...)`, mounting `<artifacts dir>` → `/input:ro` and the output dir → `/output:rw`.

Follow how `g3worker`'s `SubscribeAsReporter` handler calls `BuildReporterCommand`/`RunPluginReporter` for the mount/arg conventions. Add the `Artifacts string` field to `ReportCmd` with a Kong tag (e.g. `--artifacts` `type:"existingdir"`).

```go
type ReportCmd struct {
	IOCmd
	Artifacts string `name:"artifacts" type:"existingdir" required:"" help:"Directory of tool artifacts to report on (mounted as /input)."`
	// existing fields...
}
```

- [ ] **Step 2: Verify build**

Run: `cd src/g3 && go build`
Expected: PASS.

- [ ] **Step 3: Functional**

Run: `g3 report --artifacts ./some-artifacts-dir -o ./out`
Expected: Docker-runs magenta, writes the report into `./out`. (Manual verification; requires the magenta image.)

### Task 4.4: TUI report pane → dispatch + artifacts

**Files:**
- Modify: `src/g3tui/internal/ui/report.go`, the g3tui client (`GetReport`)

- [ ] **Step 1: Rewire `ReportPane.fetchCmd`**

Change `fetchCmd` (and the client `GetReport`) from calling the removed `/scan/report` to: dispatch magenta via `/scan/task/dispatch`, poll status, then fetch the report via `/scan/task/artifacts`. Reuse the same client transport the rest of g3tui uses. The `<img>` → `*[Image: …]*` fallback in `renderAndApply` stays (Magenta emits the charts).

- [ ] **Step 2: Verify build**

Run: `cd src && make ../bin/g3tui`
Expected: PASS.

- [ ] **Step 3: Functional**

Manual: open the TUI against a scan, open the report pane, confirm a Magenta report renders (with chart alt-text fallback).

### Task 4.5: Final gate

- [ ] **Step 1:** `cd src && make all` → all seven binaries build.
- [ ] **Step 2:** `./bin/g3config` → all plugins register; no `issue`/`merger`/`i18n` references in the refactored plugins.
- [ ] **Step 3:** `grep -rn "scan/report\b" src/` → only references are the *task* endpoints (`/scan/task/...`), not the removed `/scan/report`.

---

## Self-review notes (spec coverage)

- Spec Component 1 (reporter removal) → Phase 1 Tasks 1.1–1.4, 1.7.
- Spec Component 2 (de-issue plugins) → Phase 2 (nmap/testssl/nikto) + Phase 3 (hydra).
- Spec Component 3 (i18n removal) → Tasks 1.5, 1.6.
- Spec Component 4 (report→Magenta) → Phase 4.
- Retained engine issue-handling (guiding principle) → never touched; verified by the absence of edits to `LoadIssues`/`GetIssueIDs`/`IsValidData`/`BuildMergerCommand`/`G3Report`.
- `credential` type → Task 3.1, 3.2.
- TUI `<img>` kept → Task 1.7.
- Description flatten → Task 1.6.

## Open items (carried from spec)

- **nikto `url` discovery** (.git dirs, backups → chainable `url` assets): investigate during Phase 2; currently nikto echoes only its input url. If pursued, the tiny `g3i.py` (Task 2.3) additionally parses `nikto.csv` for high-value paths and emits `url` objects — a follow-up, not a blocker.
- **Dormant merger machinery**: the engine merger phase remains after all per-plugin mergers are removed; revisit once Magenta owns dedup.
