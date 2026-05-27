# Design: g3 tool integration for knife (managed scans + Python client library)

**Date:** 2026-05-27
**Status:** Approved (brainstorming) — pending implementation plan
**Author:** Mario Vilas (with Claude)

## 1. Goal

Let knife's LLM agents invoke the individual security tools that golismero3 (g3)
orchestrates — running one tool at a time against a target/object, fetching the
resulting `G3Data`, downloading raw artifacts, and uploading files for import —
against a **remote** g3 deployment that runs on separate machines/containers from
knife's core.

We do **not** support launching full scans or generating reports from knife.
Invoking individual tasks is the entire surface.

The deliverable in this repository is two things:

1. **Minimal, additive extensions to `g3api`** so individual tasks can be driven
   against a long-lived, externally-managed scan without the g3 orchestrator
   ever taking ownership of that scan's lifecycle.
2. **A standalone Python client library** (shipped here) that wraps the extended
   `g3api` into a clean, scan-scoped, data-only API plus tool-contract discovery.

The knife team consumes the Python library and wires it into their existing
in-process `@mcp.tool` registry. We do not modify knife.

## 2. Scope

### In scope
- `g3api` server-side changes (Section 5).
- Additive `.g3p` plugin metadata for LLM consumption + a `/plugin/describe`
  endpoint that serves it (Section 5.6).
- A Python client library in this repo (Section 6).

### Out of scope (explicitly deferred — see Section 10)
- A real MCP-protocol server (JSON-RPC over stdio / streamable-HTTP) usable by
  arbitrary MCP clients. Nice future feature; the network-MCP-to-model-provider
  security concern is knife's reason for preferring an in-process wrapper today.
- Folding per-tool presets into a single `.g3p` with `tool:preset` selector
  syntax. This is a **major** g3 refactor (`.g3p` schema, scan-script grammar,
  per-preset fingerprints, log attribution) and gets its own spec/plan. Until
  then, presets remain separate plugins (`nmap`, `nmap-fast`, `nmap-full`, …),
  each surfaced as a distinct tool.
- Free-form / caller-supplied tool arguments. g3's data-only model stands.
- Task-level and log WebSocket streaming. Polling is sufficient for v1.
- Turning file import into a dispatched worker task (the existing in-`g3api`
  synchronous importer is reused as-is; the standing FIXME is unrelated work).
- Knife-side integration code (engagement↔scan mapping, `@mcp.tool`
  registration, LLM tool naming). Owned by the knife team.

## 3. Background: what g3api already provides

Verified against current source:

- **Single-task dispatch already exists and is orchestrator-decoupled.**
  `/scan/task/dispatch` (`kind=tool`, `tool`, `dataid`, `index`) publishes a
  `G3Dispatch`; the scanner's `dispatchHandler` (`src/g3scanner/g3scanner.go`)
  "handles dispatches for any scan, regardless of whether it's actively running
  its script" and does only per-task bookkeeping — it never touches scan-level
  status.
- **Results, artifacts, uploads, plugin list, auth all exist:** `/scan/data`,
  `/scan/datalist`, `/scan/task/artifacts` (tar.gz/zip bundle), `/file/upload`,
  `/plugin/list`, bearer-token auth on every route + WS upgrade.
- **Dedup is pipeline-only.** Fingerprint dedup lives entirely in `ScanRunner`
  (`GetFingerprintMatchesIDs`); neither `dispatchHandler` nor `g3worker` dedups.
  So managed scans (which never run a pipeline) already permit re-running the
  same tool on the same object.

### The real gaps

1. **Scan lifecycle ownership.** The only path that drives a scan to a terminal
   state is the pipeline runner: `/scan/start` always calls `SendNewScan` →
   `ScanRunner`, which emits `FINISHED` for a target-only script or `ERROR` for
   a target-less one. There is no way to hold a scan "open" for ongoing
   on-demand dispatch, and there is intentionally **no** API to set scan status
   directly (status is owned by g3scanner via MQTT). A long-lived,
   externally-driven scan needs a lifecycle the orchestrator never touches.

2. **Getting a `dataid` to dispatch against.** Dispatch requires the Mongo `_id`
   of the object to run the tool on. Targets are created by `/scan/start`'s
   `target X` script via `SaveData`, but the handler returns only the scan ID
   and discards the inserted IDs. knife would otherwise have to list-all +
   fetch + client-side-match to recover them. (`SaveData` already returns the
   inserted IDs — they are simply thrown away today.)

3. **No machine-readable tool contract.** `/plugin/list` returns only
   `{name, url, description}`. An LLM choosing/driving tools needs: what a tool
   is for, what `G3Data` input it consumes, what it produces, and which
   command-index variants exist.

## 4. Architecture

```
  knife/core  (NOT in this repo — knife team owns)
    └─ @mcp.tool registry  ──uses──▶  g3 Python client library (THIS repo)
         engagement_id → scan_id (knife DB)        │
                                                    │ HTTPS + bearer token
                                                    ▼
                              REMOTE g3 deployment (separate host/containers)
                                g3api (extended)
                                  ├─ /scan/create          (NEW: managed scan, no SendNewScan)
                                  ├─ /scan/target/add      (NEW: strings → BuildTargets → ids)
                                  ├─ /scan/data/insert      (NEW: raw G3Data → validate → ids)
                                  ├─ /scan/import           (NEW: uuid+tool → importOne → ids)
                                  ├─ /scan/data            (EXTENDED: optional _taskid filter)
                                  ├─ /plugin/describe       (NEW: tool contract from .g3p llm metadata)
                                  ├─ /scan/task/dispatch   (exists, unchanged)
                                  ├─ /scan/tasks/status    (exists, unchanged)
                                  ├─ /scan/task/artifacts  (exists, unchanged)
                                  ├─ /file/upload          (exists, unchanged)
                                  └─ /scan/delete          (exists, unchanged)
                                g3scanner / g3worker / Mongo / Redis / MariaDB / MQTT  (unchanged)
```

Topology decision (records the rejected alternatives):
- **Chosen:** build on `g3api`. It already implements ~80% of the surface;
  preserves distributed scalability; single bearer-token boundary; no duplicated
  source of truth.
- **Rejected — wrap the `g3` CLI:** loses scalability, needs the Docker socket +
  every plugin image co-located, and would reimplement orchestration g3api
  already owns. (Still fine as an offline single-plugin test harness.)
- **Rejected — connect directly to MQTT/Mongo/Redis/MariaDB/FS:** duplicates
  g3api's logic and widens the security boundary dramatically.

## 5. g3api changes

All new endpoints require the existing bearer token. All new endpoints that
mutate a scan are **gated to managed scans only**: they look up the scan's
status and reject with 409 (or 400) if it is not `MANAGED`.

### 5.1 New scan status: `MANAGED`

Add `STATUS_MANAGED G3SCANSTATUS = "MANAGED"` to the enum and `VALID_STATUS`
in `src/g3lib/task.go`. It is a stable terminal-but-not-finished state that the
scanner never emits and never overwrites. The progress table / TUI display it as
externally-managed.

### 5.2 `/scan/create` — create a managed scan

- Request: `{}` (no targets required).
- Behaviour: generate a UUID, write the progress row directly with
  `status = MANAGED` (via `InsertScanProgress` + an `UpdateScanProgress` to
  MANAGED, or a dedicated insert), `MkdirAll(<artifactsRoot>/<scanid>)`, and
  **do not** publish a `G3Scan`. The scanner is never informed of this scan.
- Response: `{ "status": "success", "data": "<scan-uuid>" }`.
- Rationale: g3api already owns `_uploads`, `<scanid>/imports`, and `<scanid>`
  deletion, so owning `<scanid>` creation for managed scans is consistent and
  low-risk. `MkdirAll` is idempotent and harmonises with g3worker's lazy slot
  creation.

### 5.3 `/scan/target/add` — add targets by string (managed-only)

- Request: `{ "scanid": "<uuid>", "targets": ["https://ex.com", "10.0.0.1", …] }`.
- Behaviour: reuse `BuildTargets` (identical canonicalization/validation to
  `target X` scripts — URL schemes, loopback rejection, `_type`/`_fp`
  synthesis), then `SaveData(scanid, NIL_TASKID, …)`.
- Response: `{ "status": "success", "data": ["<dataid>", …] }` (parallel to
  input order).
- Canonicalization stays authoritative in g3; neither knife nor the library
  needs to understand G3Data shape for the common case.

### 5.4 `/scan/data/insert` — insert raw G3Data (managed-only)

- Request: `{ "scanid": "<uuid>", "data": [ {G3Data}, … ] }`.
- Behaviour: validate each object is well-formed G3Data server-side (reuse the
  `_type`/`_tool`/`_fp` checks in `src/g3lib/common.go`); reject malformed input
  with 400 and a clear message. Then `SaveData`.
- Response: `{ "status": "success", "data": ["<dataid>", …] }`.
- Escape hatch for injecting non-target objects (e.g. a pre-known service/issue).
  Validation stays server-side so a bad object can't corrupt the scan.

### 5.5 `/scan/import` — import an uploaded file (managed-only)

- Precondition: file already uploaded via existing `/file/upload` (returns a
  file UUID).
- Request: `{ "scanid": "<uuid>", "tool": "<plugin>", "fileid": "<uuid>" }`.
- Behaviour: reuse the existing `importOne` logic (relocate
  `_uploads/<uuid>` → `<scanid>/imports/`, run the importer container via
  `RunPluginImporter`, `SaveData`). This is decoupled from `SendNewScan` already.
- Response: `{ "status": "success", "data": ["<dataid>", …] }`.
- Inherits the existing synchronous in-`g3api` Docker behaviour. Making imports
  a dispatched task is out of scope (matches the existing FIXME at
  `g3api.go:495`).

### 5.6 `/scan/data` — optional `_taskid` filter

Extend `ReqLoadData` with an optional `taskid` field. When set, the query
becomes `bson.M{"_taskid": taskid}` (via `LoadDataWithCallback`), returning
exactly the objects a given dispatched task produced. Existing behaviour
(by `_id` list, or all when empty) is unchanged when `taskid` is absent.

This is the "fetch the results of the task I just ran" primitive.

### 5.7 `/plugin/describe` — machine-readable tool contract

Serves, per plugin, the contract an LLM needs. Sourced from new **additive**
`.g3p` metadata (graceful fallback when absent).

New optional `.g3p` block (parsed into a new optional field on `G3Plugin` in
`src/g3lib/plugin.go`; passed through by `g3config`):

```json5
{
  // …existing fields…
  llm: {
    summary:     "Web server vulnerability scanner.",
    accepts:     ["url"],        // G3Data _type(s) this plugin consumes
    produces:    "issue",        // primary G3Data _type produced
    // optional per-command notes, keyed by command index:
    commands: [
      { description: "Scan an HTTP URL." },
      { description: "Scan an HTTPS URL (TLS)." }
    ]
  }
}
```

`/plugin/describe` response per plugin — only the LLM contract, no presentation
metadata:
- `name`: the identifier the caller uses to reference the tool in
  `/scan/task/dispatch`.
- `summary`: the LLM-specific explanation from `llm.summary`. (Falls back to the
  plugin's `description` *text* internally when `llm.summary` is absent, but the
  field is always named `summary` — `description`, `url`, and `image` are **not**
  returned; those are presentation metadata for reports/GUIs, available via the
  existing `/plugin/list`.)
- `accepts`, `produces`: from `llm` (fall back to per-command `Returns` for
  `produces` when `llm` is absent).
- `operations`: one entry per command index — `{ index, description, produces }`
  — because `/scan/task/dispatch` selects a command by `index`. This lets the
  LLM/library pick the right variant (e.g. nikto http vs https) without g3
  evaluating conditions at dispatch time.

Deliberately **no** `when_to_use` / condition guidance. knife already has
agentic orchestration; encoding *when* to run a tool here would be opinionated
and would duplicate decision-making that belongs to the consumer. We describe
*what* a tool is and *what it consumes/produces*, not *when* to use it.

### 5.8 `/config/env` — read-only shared configuration

Returns the deployment's shared `G3_ENV_*` variables, which g3worker injects
into every plugin container and which therefore describe global runtime
capabilities (e.g. whether IPv6 is enabled). These are **global, not
per-plugin**, and g3api already has them in its own environment — the handler
simply collects every `G3_ENV_*` variable from `os.Environ()` and returns them
as a map. No `.g3p` declaration and no derivation from `dockeropt` is needed.

- Request: `{}`.
- Response: `{ "status": "success", "data": { "G3_ENV_IPV6_SUPPORTED": "true", … } }`.

The operator owns the actual values via the deployment environment; this
endpoint just surfaces them so the consumer can reason about capabilities.

## 6. Python client library (this repo)

### 6.1 Placement & packaging
- New top-level directory: `clients/python/` containing an installable package
  (e.g. `g3client/`) with its own `pyproject.toml`. (Final name/layout to be
  fixed in the plan; keep it independent of `misc/requirements.txt`, which is
  for plugin tooling.)
- No dependency on knife. Pure HTTP client (e.g. `httpx`/`requests`) + typing.

### 6.2 Responsibilities
- Own the g3api transport: base URL, bearer token, error mapping, the multipart
  upload, and the artifact download stream.
- Provide scan-scoped, data-only operations and tool-contract discovery.
- Provide a polling helper for task completion (poll `/scan/tasks/status`).
- **Materialise artifacts to disk, not RAM.** Stream the bundle to a
  caller-supplied directory, auto-create a `<task_id>/` subdirectory to prevent
  clobbering, transparently extract zip/tar.gz bundles (and pass a single raw
  file through unchanged), and return the directory path. The LLM already has
  local file search/list/read tools, so the library never holds big blobs in
  memory.
- **Ship a G3Data type primer** as a module-level string constant (see 6.5),
  intended to be fed to the LLM *before* the per-tool contracts so it
  understands the shared data model the tools speak.
- It does **not** persist any client state, and it does **not** know about
  engagements — it deals in scan IDs the caller supplies.

### 6.3 Public API (illustrative)
```python
client = G3Client(base_url="https://g3.internal", token="…")

# lifecycle (knife calls these on engagement create/delete)
scan_id = client.create_managed_scan()
client.delete_scan(scan_id)

# seed data
ids   = client.add_targets(scan_id, ["https://ex.com", "10.0.0.1"])  # -> [dataid]
ids   = client.insert_data(scan_id, [ {...G3Data...} ])              # -> [dataid]
# one call: uploads the local file, then imports it with the given tool
ids   = client.import_file(scan_id, tool="nmap", path="/tmp/scan.xml")  # -> [dataid]

# tool contract + shared config
tools = client.list_tools()                # cached /plugin/describe snapshot
spec  = client.describe_tool("nikto")
env   = client.get_env()                   # /config/env -> {G3_ENV_*: value}

# run one task and collect results
task  = client.run_tool(scan_id, tool="nikto", dataid=ids[0], index=0)  # -> task_id
state = client.task_status(scan_id, task)         # single poll
state = client.wait_for_task(scan_id, task)       # polling helper -> terminal state
data  = client.task_results(scan_id, task)        # /scan/data?taskid -> [G3Data]
# downloads + extracts into <dest_dir>/<task_id>/, returns that path
path  = client.task_artifacts(scan_id, task, dest_dir="/work/artifacts")
```

`import_file` combines the existing `/file/upload` (multipart) and `/scan/import`
endpoints into a single client call — there is no need to expose the two-step
dance to the caller.

### 6.4 G3Data type primer (module constant)
A static string (e.g. `g3client.G3DATA_PRIMER`) describing the shared G3Data
model: the mandatory envelope fields (`_type`, `_tool`, `_fp`, and the optional
`_id`/`_scanid`/`_taskid`/`_cmd`/`_start`/`_end`/`_artifacts`), and the common
`_type` values (`host`, `url`, `domain`, `cidr`, `issue`, `service`, …) with the
fields each typically carries. The consumer feeds this to the LLM once, ahead of
the per-tool `accepts`/`produces` contracts, so the model can reason about what
flows between tools. It is descriptive reference text, not orchestration
guidance.

### 6.5 Knife integration boundary (informational, not built here)
Knife wraps the above into `@mcp.tool` functions, maps `engagement_id → scan_id`
in its own DB, creates a managed scan when an engagement is created, deletes it
when the engagement is deleted, and chooses the LLM-facing tool names. None of
that lives in this repo.

## 7. Runtime sequences

### Run a tool on a target
```
engagement created  ─▶ create_managed_scan()                 → scan_id (stored by knife)
add_targets(scan_id, ["https://ex.com"])  ─▶ /scan/target/add → [dataid]
run_tool(scan_id, "nikto", dataid)         ─▶ /scan/task/dispatch → task_id
wait_for_task(scan_id, task_id)            ─▶ poll /scan/tasks/status → DONE/WARNING/ERROR
task_results(scan_id, task_id)             ─▶ /scan/data?taskid     → [G3Data]
  (optional) task_artifacts(...)           ─▶ /scan/task/artifacts  → bundle
engagement deleted  ─▶ delete_scan(scan_id)                  ─▶ /scan/delete
```

### Import a file then run a tool over the imported data
```
import_file(scan_id, "nmap", "/tmp/scan.xml")  ─▶ /file/upload (multipart) → file uuid
                                                ─▶ /scan/import            → [dataid]
run_tool(scan_id, "<tool>", dataid)             ─▶ /scan/task/dispatch     → task_id
… (status / results as above)
```
(`import_file` performs both HTTP calls; the caller sees one step.)

## 8. Data governance & lifecycle

- One managed scan per knife engagement (1:1), created on engagement creation,
  deleted on engagement deletion. `/scan/delete` already cascades Redis report
  info, Redis task states, SQL logs, the Mongo scan DB, the SQL progress row,
  and the `<artifactsRoot>/<scanid>` tree — so engagement teardown leaves no
  residue.
- Data accumulates within an engagement's scan, which preserves data-feeds-data
  chaining (e.g. nmap output later consumed by hydra) and is bounded by the
  engagement's lifetime.

## 9. Security considerations

- Single bearer-token boundary (existing). The g3 deployment is reachable only
  by knife's backend, never by a model provider.
- Managed-only gating on every new mutating endpoint prevents knife from
  injecting data into, or otherwise disturbing, orchestrator-owned scans.
- Canonicalization (`/scan/target/add`) and G3Data validation
  (`/scan/data/insert`) stay server-side; malformed input is rejected, never
  trusted.
- Data-only invocation: the LLM can choose a tool + a target object, not
  arbitrary command-line flags, so there is no argv-injection surface.

## 10. Deferred / future work

- **Real MCP-protocol server** wrapping the same g3api surface, for use by
  arbitrary MCP clients outside knife. Separate plan.
- **Single-file presets** (`tool:preset` selector): `.g3p` schema change,
  scan-script grammar, preset-aware fingerprints (e.g. `nmap:fast 1.2.3.4`),
  and preset attribution in logs. Major refactor; separate plan. Until then,
  presets are distinct plugins/tools.
- **Task-level / log WebSocket streaming** (e.g. a `taskupdate` subscription)
  to replace polling if latency warrants.
- **Import as a dispatched worker task** (addresses the existing
  `g3api.go:495` FIXME); orthogonal to this work.

## 11. Open questions for the implementation plan

- Final package name/layout under `clients/python/`.
- Whether the managed-only gate returns 409 vs 400 for non-managed scans.

Resolved during design:
- `/scan/create` is a **separate handler** (not a `managed:true` flag on
  `/scan/start`), for clarity.
- Shared config is exposed via a dedicated global `/config/env` endpoint that
  reads `G3_ENV_*` from g3api's own environment — not derived per-plugin.
- The `llm` block carries no `when_to_use`; *when* to run a tool is the
  consumer's (knife's) decision.
- `import_file` is a single client call wrapping `/file/upload` + `/scan/import`.
```