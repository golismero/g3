# Design: g3 tool integration for knife (managed scans + Python client library)

**Originated:** 2026-05-27
**Substantially revised:** 2026-05-31
**Status:** Design locked. v1 server-side and v1 library shipped through Tier 4;
this document supersedes v1 with a redesigned library and tightened server
contracts.
**Author:** Mario Vilas (with Claude)

> **Revision history.** This document was substantially revised on 2026-05-31
> after observing the v1 library in practice against a live g3 deployment.
> Five shifts, in order of impact:
>
> 1. **Plugin contract is strictly opt-in, no derivation.** Only `.g3p` files
>    that declare an `llm:` block appear in `/plugin/describe`, and every field
>    in the response is author-populated (no fallbacks from `description`).
> 2. **The per-operation surface is removed.** The LLM picks between *plugins*
>    (`nmap` vs `nmap-fast` vs `nmap-full` — distinct `.g3p` files); the
>    orchestrator's `condition` templates pick between a plugin's *internal*
>    command variants at dispatch time, where they always belonged. The LLM no
>    longer passes a command `index`.
> 3. **`produces` becomes a list.** A plugin's importer routinely emits more
>    than one `_type` (nmap emits both `host` and `issue`; dig emits both
>    `domain` and `host`). The previous singular `produces: string` was lossy.
> 4. **The Python client is rebuilt around a data-flow primitive.** `Client(key)`
>    is a per-engagement multiton with eager scan creation; `client.run(data,
>    tool) -> RunResult` hides task IDs, polling, multi-task fan-out, artifact
>    download, and state aggregation from the LLM. The operational HTTP-thin
>    methods remain available for knife's lifecycle hooks and debugging.
> 5. **Cache-by-fingerprint is deferred.** See §10.
>
> The original Tier 1–3 server-side work (managed scans, the seed/import
> endpoints, `/config/env`) is unchanged and remains the foundation. The v1
> library (Tier 4) is being rewritten.

## 1. Goal

Let knife's LLM agents invoke the individual security tools that golismero3
(g3) orchestrates — running one tool at a time against a target/object,
fetching the resulting `G3Data`, downloading raw artifacts, and uploading
files for import — against a **remote** g3 deployment that runs on separate
machines/containers from knife's core.

We do **not** support launching full scans or generating reports from knife.
Invoking individual tools is the entire surface.

The deliverables in this repository are two things:

1. **Additive extensions to `g3api`** so individual tasks can be driven against
   a long-lived, externally-managed scan without the g3 orchestrator ever
   taking ownership of that scan's lifecycle.
2. **A standalone Python client library** that wraps the extended `g3api`
   into a per-engagement, data-flow-oriented API hiding scans, tasks, polling,
   and multi-task fan-out from the LLM.

The knife team consumes the Python library and wires it into their existing
in-process `@mcp.tool` registry. We do not modify knife.

## 2. Scope

### In scope
- `g3api` server-side changes (Section 5).
- Additive `.g3p` plugin metadata for LLM consumption + a `/plugin/describe`
  endpoint that serves it (§5.7).
- A Python client library in this repo (Section 6).

### Out of scope (Section 10)
- A real MCP-protocol server (JSON-RPC over stdio / streamable-HTTP) usable by
  arbitrary MCP clients outside knife.
- Folding per-tool presets into a single `.g3p` with `tool:preset` selector
  syntax (presets remain separate plugins).
- Free-form / caller-supplied tool arguments. g3's data-only model stands.
- Task-level and log WebSocket streaming. Polling is sufficient.
- Turning file import into a dispatched worker task.
- Knife-side integration code (engagement↔scan mapping persistence,
  `@mcp.tool` registration, LLM tool naming). Owned by the knife team.
- **Cache-by-fingerprint lookup (run-or-fetch).** Deferred for v1.
- **Async Python client.** Sync-only for v1.

## 3. Background: what g3api provides and what was missing

Verified against current source:

- **Single-task dispatch already existed and was orchestrator-decoupled.**
  `/scan/task/dispatch` publishes a `G3Dispatch`; the scanner's
  `dispatchHandler` (`src/g3scanner/g3scanner.go`) "handles dispatches for any
  scan, regardless of whether it's actively running its script" and does only
  per-task bookkeeping — it never touches scan-level status.
- **Results, artifacts, uploads, plugin list, auth all exist.** `/scan/data`,
  `/scan/datalist`, `/scan/task/artifacts`, `/file/upload`, `/plugin/list`,
  bearer-token auth on every route + WS upgrade.
- **Dedup is pipeline-only.** Fingerprint dedup lives entirely in `ScanRunner`
  (`GetFingerprintMatchesIDs`); neither `dispatchHandler` nor `g3worker`
  dedups. So managed scans (which never run a pipeline) permit re-running the
  same tool on the same object.

### The gaps the design closes

1. **Scan lifecycle ownership.** `/scan/start` always calls `SendNewScan` →
   `ScanRunner`, which emits `FINISHED` for a target-only script or `ERROR`
   for a target-less one. There is no way to hold a scan "open" for ongoing
   on-demand dispatch, and intentionally **no** API to set scan status
   directly (status is owned by g3scanner via MQTT).
2. **Getting a `dataid` to dispatch against.** Dispatch requires the Mongo
   `_id` of the object. `SaveData` returns inserted IDs but `/scan/start`
   discards them.
3. **No machine-readable tool contract.** `/plugin/list` returns only
   `{name, url, description}` — fine for humans, insufficient for an LLM
   choosing which tool to invoke and what shape of object to feed it.
4. **No auto-dispatch on `/scan/task/dispatch`.** v1 required callers to pass
   `index`, bypassing the plugin's own `condition` templates. A caller
   picking the wrong index silently runs the tool with wrong flags rather than
   failing cleanly — observed in practice with the HTTP-vs-HTTPS variant of
   nikto.

## 4. Architecture

```
  knife/core  (NOT in this repo — knife team owns)
    └─ @mcp.tool registry
         │
         │  per-engagement Client(engagement_id) — multiton
         ▼
       g3 Python client library  (THIS repo)
         ├─ data-flow API: add_target(), add_targets(), run() → RunResult
         ├─ persistence API: bind(), unbind(), .scan_id, dispose()
         └─ operational API (debug / power user)
         │
         │  HTTPS + bearer token (env-configured)
         ▼
       REMOTE g3 deployment (separate host/containers)
         g3api (extended)
           ├─ /scan/create          managed scan; no SendNewScan
           ├─ /scan/target/add      strings → BuildTargets → ids
           ├─ /scan/data/insert     raw G3Data → validate → ids
           ├─ /scan/import          uuid+tool → importOne → ids
           ├─ /scan/data            optional _taskid filter
           ├─ /scan/task/dispatch   AUTO-EVALUATES conditions; returns task_ids list
           ├─ /plugin/describe      opt-in tool contracts; no operations[]
           ├─ /config/env           G3_ENV_* map
           ├─ /scan/tasks/status    (existing — polled for terminal state)
           ├─ /scan/task/artifacts  (existing — single file or ZIP)
           ├─ /file/upload          (existing — multipart)
           └─ /scan/delete          (existing — cascades)
         g3scanner / g3worker / Mongo / Redis / MariaDB / MQTT  (unchanged)
```

Topology rationale (rejected alternatives):
- **Chosen:** build on g3api. ~80% of the surface already existed; preserves
  distributed scalability; single bearer-token boundary; no duplicated source
  of truth.
- **Rejected — wrap the `g3` CLI:** loses scalability, needs the Docker socket
  + every plugin image co-located, would reimplement orchestration g3api
  already owns.
- **Rejected — connect directly to MQTT/Mongo/Redis/MariaDB/FS:** duplicates
  g3api's logic and widens the security boundary dramatically.

## 5. g3api changes

All endpoints require the existing bearer token. All mutating endpoints are
gated to managed scans only — they verify `status == MANAGED` via
`GetScanStatus` and reject with **409 Conflict** otherwise.

### 5.1 New scan status: `MANAGED`

`STATUS_MANAGED G3SCANSTATUS = "MANAGED"` in `src/g3lib/task.go`, appended to
`VALID_STATUS`. Stable terminal-but-not-finished state the scanner never emits
and never overwrites. (Shipped in Tier 1.)

### 5.2 `/scan/create` — create a managed scan

- Request: `{}`. Response: `{ "status": "success", "data": "<scan-uuid>" }`.
- Behaviour: `uuid.NewString()`, `InsertScanProgress`, `UpdateScanProgress(...,
  STATUS_MANAGED, ...)`, `MkdirAll(<artifactsRoot>/<scanid>)`. Does **not**
  publish a `G3Scan`. (Shipped in Tier 2.)

### 5.3 `/scan/target/add` — add targets by string (managed-only)

- Request: `{ "scanid": "...", "targets": ["https://ex.com", ...] }`.
- Behaviour: reuse `BuildTargets` (identical to the `target X` script directive
  — URL canonicalization, loopback rejection, `_type`/`_fp` synthesis), then
  `SaveData`. Response: `{ "status": "success", "data": ["<dataid>", ...] }`.
  (Shipped in Tier 2.)

### 5.4 `/scan/data/insert` — insert raw G3Data (managed-only)

- Request: `{ "scanid": "...", "data": [ {G3Data}, ... ] }`.
- Behaviour: validate each object via `IsValidData`; reject malformed input
  with 400. Then `SaveData`. Response: list of dataids. (Shipped in Tier 2.)

### 5.5 `/scan/import` — run an importer on an uploaded file (managed-only)

- Precondition: file uploaded via `/file/upload` (returns a file UUID).
- Request: `{ "scanid": "...", "tool": "...", "fileid": "..." }`.
- Behaviour: reuse the extracted `runImport` helper (relocate
  `_uploads/<uuid>` → `<scanid>/imports/`, run the importer container via
  `RunPluginImporter`, `SaveData`). Response: list of dataids. (Shipped in
  Tier 2.)

### 5.6 `/scan/data` — optional `taskid` filter

`ReqLoadData` gained an optional `taskid` field. When set, the query becomes
`bson.M{"_taskid": taskid}` via `LoadDataByTask`, returning exactly the
objects a given dispatched task produced. Existing behaviour (by `_id` list,
or all when empty) is unchanged when `taskid` is absent. (Shipped in Tier 2.)

### 5.7 `/plugin/describe` — machine-readable tool contract  [REVISED]

**Exposure is strictly opt-in, no derivation, no fallbacks.** A plugin appears
in `/plugin/describe` if and only if its `.g3p` declares an `llm:` block. The
absence of the block is the opt-out signal — a plugin without `llm:` is not
reachable to LLM consumers and is filtered out entirely.

When the `llm:` block is present, **all three of `summary`, `accepts`, and
`produces` must be non-empty**. `g3config` validates this at plugin load time
and fails loud if a plugin opts in but leaves any field empty.

No fallback from `description` / `url` / `image` — those remain presentation
metadata for reports/GUIs, available via the existing `/plugin/list`.

The `.g3p` block (parsed into `G3LLMMetadata` in `src/g3lib/plugin.go`):

```jsonnet
{
  // …existing fields…
  llm: {
    summary: "Web server vulnerability scanner.",
    accepts: ["url"],         // G3Data _type(s) this plugin consumes
    produces: ["issue"],      // G3Data _type(s) this plugin emits
                              // (list because an importer routinely emits
                              //  multiple types — nmap emits both `host`
                              //  and `issue`; dig emits both `domain` and
                              //  `host`)
  }
}
```

`/plugin/describe` response per opted-in plugin (slim, exhaustive):

```json
{
  "name":     "nikto",
  "summary":  "Web server vulnerability scanner.",
  "accepts":  ["url"],
  "produces": ["issue"]
}
```

**No `operations[]`, no `when_to_use`, no per-command exposure.** The LLM
picks between plugins (`nmap` / `nmap-fast` / `nmap-full`); the orchestrator's
`condition` templates pick between a plugin's internal command variants at
dispatch time (§5.9).

`G3LLMCommandNote` and `PluginContractOperation` structs are removed.
`G3LLMMetadata.Commands` is removed. `PluginContract.Operations` is removed.
`G3LLMMetadata.Produces` and `PluginContract.Produces` become `[]string`.

### 5.8 `/config/env` — read-only shared deployment configuration

Returns the deployment's shared `G3_ENV_*` variables, which g3worker injects
into every plugin container and which therefore describe global runtime
capabilities (e.g. whether IPv6 is enabled). Global, not per-plugin. (Shipped
in Tier 3.)

- Request: `{}`. Response: `{ "status": "success", "data": { "G3_ENV_IPV6_SUPPORTED": "true", ... } }`.

### 5.9 `/scan/task/dispatch` — auto-evaluate conditions  [REVISED]

The endpoint no longer accepts (or honours) an `index` field. On each request:

1. Server loads the `dataid`'s G3Data from MongoDB.
2. Iterates `plugin.Commands` in order, evaluating each command's `condition`
   template against the data via `g3lib.EvalToolCondition`.
3. Dispatches a task for **every** matching command (preserves the
   orchestrator's "all-matches" semantics — usually one task because
   conditions are typically mutually exclusive, but never assumed).
4. Returns `{ "status": "success", "data": { "task_ids": ["..."] } }`.
5. Returns **400** with a clear message (`"no command in plugin X matches the
   given data"`) if zero conditions match. The caller can react cleanly
   instead of running a wrongly-targeted task.

Rationale: internal command variants are part of the plugin author's
implementation of the tool — they're how the author says "here are the
command-lines I might run depending on the shape of the data I'm fed." The
orchestrator picks via `condition`. An LLM-facing API should respect that
boundary; exposing `index` re-creates the exact silent-mis-dispatch bug we
observed.

The previous `index`-based behaviour is removed entirely — no escape hatch.
The g3man CLI that would have benefitted from explicit `index` control was
rolled back during this revision and will be re-implemented separately;
backwards compatibility is not a constraint.

## 6. Python client library — REWRITTEN

### 6.1 Placement & packaging

The installable package keeps the name `g3client` (chosen for local
uniqueness — `g3` and `pyg3` are already taken on PyPI and, although we're
not currently publishing, it's worth leaving the door open). The LLM-facing
surface lives under the `g3client.llm` submodule, leaving room for future
companions (`g3client.admin`, `g3client.plugin_sdk`, etc.) without forcing
existing knife imports to change. Symbol names inside `g3client.llm` drop
the redundant `G3` prefix that v1 used (the namespace already encodes the
project and the audience).

```
clients/python/
├── pyproject.toml          # name = "g3client"
└── g3client/
    ├── __init__.py         # package marker (intentionally empty)
    └── llm/
        ├── __init__.py     # public exports
        ├── client.py       # Client class
        ├── errors.py       # ClientError, ApiError, TaskTimeout, TaskCancelled
        ├── primer.py       # DATA_PRIMER constant
        └── types.py        # RunResult, PluginContract, TaskStatus
```

Imports:

```python
from g3client.llm import Client, DATA_PRIMER, RunResult, TaskCancelled
# or
import g3client.llm as g3
client = g3.Client(engagement_id)
```

License GPL-3.0-or-later. Python ≥ 3.10. Sole runtime dep: `requests`.

### 6.2 Configuration via environment (mandatory)

All deployment configuration is read from environment variables. There are no
constructor arguments for connection details — knife sets the env once at
process startup and never threads credentials through the library.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `G3_API_BASEURL` | yes | — | e.g. `https://g3.internal/api` |
| `G3_API_TOKEN`   | yes | — | bearer token |
| `G3_ARTIFACTS_ROOT` | no | `<tempfile.gettempdir()>/g3client` | filesystem root for downloaded artifact trees |

Missing `G3_API_BASEURL` or `G3_API_TOKEN` at module import causes a clear
startup error rather than confusing per-call failures later.

### 6.3 Multiton constructor `Client(key)`

```python
client = Client(engagement_id)
# constructing again with the same engagement_id returns the SAME instance
```

`key` is an opaque caller-chosen string. Knife uses engagement IDs.

Construction semantics:
- If `key` is already in the in-process map: return that instance (no
  HTTP traffic).
- If not: POST `/scan/create`, register the returned scan_id under `key`,
  return the new instance.

Race-safety: `threading.Lock` around the map for sync correctness. Async
safety is future work.

### 6.4 Persistence API — knife rehydrating after restart

The multiton lives in-process. After a knife restart, the map is empty but
the corresponding scans on g3 still exist. Knife persists `(key, scan_id)`
pairs in its own DB and uses these class methods to rebuild the map at
startup:

```python
Client.bind(key: str, scan_id: str) -> None
  # Register an existing scan_id under the given key WITHOUT creating a new
  # scan. No g3-side verification; a stale scan_id surfaces as a clean API
  # error on the first method call.

Client.unbind(key: str) -> None
  # Remove key from the map WITHOUT deleting the scan. Inverse of bind.

Client.keys() -> list[str]
  # All currently mapped keys (introspection / debugging).

client.scan_id -> str   # property
  # Underlying scan_id; knife reads this once on engagement create and
  # persists it.
```

Typical knife flow:

```python
# Engagement create:
client = Client(engagement_id)             # -> /scan/create
knife_db.save(engagement_id, client.scan_id)

# Knife process restart:
for eng_id, scan_id in knife_db.load_all():
    Client.bind(eng_id, scan_id)
client = Client(some_engagement_id)        # returns pre-bound instance

# Engagement teardown:
client = Client(engagement_id)
client.dispose()                             # -> /scan/delete + evict
knife_db.delete(engagement_id)
```

### 6.5 Data-flow API (LLM-facing surface knife wraps as `@mcp.tool`s)

Two methods comprise the entire LLM-facing surface:

```python
# Convert a target string into a canonicalized G3Data object (with _id
# populated by the server's BuildTargets). Two round trips: /scan/target/add
# then /scan/data to fetch the full object.
url_obj  = client.add_target("https://example.com/")
[u1, u2] = client.add_targets(["https://a.test/", "https://b.test/"])

# Run a tool against an object. Returns a self-contained RunResult.
result = client.run(host_obj, "nmap")
```

**The LLM never constructs G3Data objects.** It only ever passes back
objects it received from the framework — from `add_target(s)`, from a
previous `run()`'s `RunResult.data`, or from `import_file` (see §6.8).
This is the entire reason no central schema is needed for the LLM use
case: the LLM works with objects whose shape is owned by the framework
on the way out. If knife later wants to inject pre-known objects from
its own data model (e.g. session restoration), that's a knife-side
adapter calling the underscored `_insert_data` in §6.8, not LLM concern.

`run(data, tool) -> RunResult` semantics:

1. **Insert-if-needed (defensive).** If `data` lacks `_id`: POST
   `/scan/data/insert` to register the object, then **mutate `data["_id"]`
   in place** to embed the new id. In the LLM-only path this branch is
   never taken (all objects in flight already have `_id`); it exists as
   the escape hatch for knife-side adapters. Server-side `IsValidData`
   rejects malformed envelopes before save.
2. **Dispatch.** POST `/scan/task/dispatch` (no `index`) — server auto-evaluates
   conditions and returns a list of `task_ids` (one per matching command).
3. **Wait.** Single polling loop on `/scan/tasks/status` (one request returns
   the state of every task in the scan) until all tracked task_ids reach a
   terminal state.
4. **Cancellation check.** If ANY task ended in CANCELED, raise
   `TaskCancelled` (see §6.7). CANCELED on a managed task can only happen
   via external operator intervention, so we surface it as a tool-call
   exception rather than as data.
5. **Collect results.** Per task: fetch G3Data via `/scan/data?taskid=...`,
   download artifacts via `/scan/task/artifacts` into
   `<G3_ARTIFACTS_ROOT>/<scan_id>/<task_id>/...`.
6. **Aggregate.** State = worst-wins (`ERROR > WARNING > DONE`). Data =
   union of all task results. `error_msg` = `"; "`-joined non-empty
   per-task messages.
7. **Return** the `RunResult`.

### 6.6 `RunResult` dataclass

```python
@dataclass(frozen=True)
class RunResult:
    state: str                          # combined terminal state: ERROR | WARNING | DONE
    data: list[dict]                    # union of G3Data from all spawned tasks
    artifacts_dir: Path                 # <G3_ARTIFACTS_ROOT>/<scan_id>/
    error_msg: str = ""                 # "; "-joined non-empty per-task error messages
    task_ids: tuple[str, ...] = ()      # task_ids spawned by this run
```

Per-task identity is preserved three ways:

- `RunResult.task_ids` — the IDs spawned by this `run()` call.
- Each result G3Data carries `_taskid` (server-side, in `SaveData`) — the LLM
  (or knife) can demultiplex the `data` array.
- The artifacts tree lays out `<artifacts_dir>/<task_id>/...`, mirroring
  g3worker's per-task slot layout so an operator inspecting artifacts on the
  g3 host vs. the knife host sees the same shape.

### 6.7 Exceptions

```python
class ClientError(Exception): ...

class ApiError(ClientError):
    status_code: int            # HTTP status
    message: str                # server-side error envelope

class TaskTimeout(ClientError):
    task_ids: tuple[str, ...]   # tasks still non-terminal when timeout fired
    last_states: dict[str, str] # task_id -> last-observed state

class TaskCancelled(ClientError):
    task_ids: tuple[str, ...]   # CANCELED task ids
```

`TaskCancelled` is raised by `run()` whenever any spawned task is observed
in the CANCELED state during polling. Rationale: with the dispatch API no
longer accepting a cancel primitive from the LLM, CANCELED on a managed
task can only mean external intervention — an operator force-cancelled the
task, or knife stopped the engagement out from under the LLM. Either way,
the right LLM-visible behaviour is "the call failed; the operator stopped
you" rather than "your tool returned partial data." Most agentic frameworks
already surface tool-call exceptions as "tool cancelled by operator," which
matches the intent.

The exception deliberately carries **no** partial-data payload. Sibling
tasks that completed before the cancellation arrived have their results
saved on g3, and an operator who wants forensic access can still fetch
them via the operational API using `client.scan_id` and `client.task_results(...)`.
Adding a `partial_data` field to the exception was considered and rejected:
the LLM doesn't need it (it's meant to stop), and most agentic frameworks
serialise tool exceptions to a terse string that wouldn't surface attributes
anyway.

(Edge case: a g3 service restart while a task is mid-flight can also produce
CANCELED. Documented here as a known-rare case; for v1 we treat it identically
to operator cancel. Re-evaluating during the next iteration of the scanner's
managed-scan handling — see §10.)

### 6.8 Operational / power-user methods

These exist on `Client` for debugging, knife's lifecycle hooks, and direct
control over individual operations. They are **not** the LLM-facing surface,
though there's nothing stopping knife from wrapping any of them if needed.

- `dispose()` — delete the scan + evict from the multiton map.
- `_insert_data(data: list[dict]) -> list[str]` — raw G3Data insertion (no
  canonicalization). Underscored deliberately: the LLM-facing surface does
  not include raw insertion. Knife-side compatibility layers that need to
  inject pre-known objects from knife's own data model can call this; for
  any caller, server-side `IsValidData` still rejects malformed envelopes.
- `import_file(tool: str, path: str) -> list[str]` — upload + import in one
  call.
- `task_status(task_id) -> TaskStatus` — single-poll status.
- `wait_for_task(task_id, *, timeout, poll_interval) -> TaskStatus` — polling
  helper for a specific task.
- `task_results(task_id) -> list[dict]` — fetch G3Data produced by one task.
- `task_artifacts(task_id, dest_dir) -> Path` — download + extract one
  task's bundle to a caller-supplied directory.
- `list_tools() -> tuple[PluginContract, ...]` — cached `/plugin/describe`
  snapshot.
- `describe_tool(name: str) -> PluginContract` — one plugin's contract.
- `refresh_tool_cache() -> None` — drop the cache; next `list_tools` refetches.
- `get_env() -> dict[str, str]` — `/config/env`.

There is intentionally **no** `run_tool(..., index=...)` method. Dispatch
always auto-evaluates.

### 6.9 `DATA_PRIMER` module constant

A static string (`g3client.llm.DATA_PRIMER`) describing the shared G3Data
model: the mandatory envelope fields (`_type`, `_tool`, `_fp`, and optional
`_id` / `_scanid` / `_taskid` / `_cmd` / `_start` / `_end` / `_artifacts`),
and the common `_type` values (`host`, `url`, `domain`, `cidr`, `issue`,
`service`, …) with the fields each typically carries. The consumer feeds
this to the LLM once, ahead of the per-tool contracts returned by
`list_tools()`, so the model can reason about what flows between tools.
Descriptive reference text only, not orchestration guidance.

### 6.10 Knife integration boundary (informational, not built here)

Knife wraps `add_target` / `add_targets` / `run` as `@mcp.tool` functions.
The multiton + persistence pattern means knife doesn't have to thread
engagement IDs as parameters into every tool function — each engagement's
tools can close over its `Client(engagement_id)` instance. The LLM sees a
clean object-in / objects-out surface; scan IDs, task IDs, polling, and
multi-task fan-out are entirely the library's concern.

## 7. Runtime sequences

### Engagement create / use / teardown

```
engagement_id created in knife
  knife: client = Client(engagement_id)        ─▶ POST /scan/create   → scan_id
  knife: persist (engagement_id, scan_id) to its DB

LLM tool call: "run nikto on https://target/"
  knife @mcp.tool: client = Client(engagement_id)     (returns existing instance)
  knife @mcp.tool: url_obj = client.add_target("https://target/")
                   ─▶ POST /scan/target/add            → [dataid]
                   ─▶ POST /scan/data {dataids}        → [G3Data]
  knife @mcp.tool: result = client.run(url_obj, "nikto")
                   ─▶ POST /scan/task/dispatch         → {task_ids: ["..."]}
                   ─▶ POST /scan/tasks/status (polled until terminal)
                   ─▶ POST /scan/data {taskid}         → [G3Data] per task
                   ─▶ POST /scan/task/artifacts        → bundle per task
                   ─▶ RunResult(state=DONE, data=[...], artifacts_dir=Path, ...)
  knife: LLM receives the RunResult (typically just data + state)

LLM tool call: "run testssl on that URL object"
  knife @mcp.tool: client = Client(engagement_id)
  knife @mcp.tool: client.run(url_obj, "testssl")
                   (url_obj already has _id from the previous call; no re-insert)

knife process restart (rehydrate from DB)
  for eng_id, scan_id in knife_db.load_all():
      Client.bind(eng_id, scan_id)
  (subsequent Client(eng_id) calls return the pre-bound instances)

engagement_id deleted in knife
  client = Client(engagement_id)
  client.dispose()                                ─▶ POST /scan/delete
  knife: remove (engagement_id, scan_id) from its DB
```

### Multi-task auto-dispatch (transparent to the LLM)

```
client.run(host_obj, "nmap")
  POST /scan/task/dispatch {scanid, tool: "nmap", dataid: host_obj["_id"]}
    server evaluates nmap's two commands:
      [0] condition matches ipv4 hosts with no discovered services
      [1] condition matches ipv6 hosts with no discovered services + IPv6 enabled
    typically one matches; if both do, both dispatch
  → {task_ids: [tid0]}  or  {task_ids: [tid0, tid1]}

  poll /scan/tasks/status until all terminal
  fetch /scan/data?taskid=tid0  (+ tid1 if applicable)
  download /scan/task/artifacts for each

  artifacts_dir layout:
    <G3_ARTIFACTS_ROOT>/<scan_id>/<tid0>/...
    <G3_ARTIFACTS_ROOT>/<scan_id>/<tid1>/...   (if dispatched)

  RunResult(state=worst({task states}), data=union, ...)
```

### Import-then-run (less common path)

```
client = Client(engagement_id)
dataids = client.import_file(tool="nmap", path="/tmp/scan.xml")
                   ─▶ POST /file/upload (multipart)   → file uuid
                   ─▶ POST /scan/import                → [dataid]
# If the LLM wants the imported objects to drive further runs, knife fetches:
hosts = client.task_results(...)    # or wraps in a helper
client.run(hosts[0], "testssl")
```

## 8. Data governance & lifecycle

- One managed scan per knife engagement (1:1), created on engagement creation,
  deleted on engagement deletion. `/scan/delete` cascades Redis report info,
  Redis task states, SQL logs, the Mongo scan DB, the SQL progress row, and
  the `<artifactsRoot>/<scanid>` tree — engagement teardown leaves no
  residue server-side.
- Data accumulates within an engagement's scan, preserving data-feeds-data
  chaining (e.g. nmap output later consumed by hydra) and is bounded by the
  engagement's lifetime.
- Knife persists `(engagement_id, scan_id)` pairs in its own DB. The
  library's multiton is in-process state only; rehydration on knife restart
  is knife's responsibility (via `Client.bind`).
- Client-side artifact trees under `<G3_ARTIFACTS_ROOT>/<scan_id>/` are not
  garbage-collected by the library. Knife is responsible for cleaning these
  up when it disposes of an engagement, if relevant.

## 9. Security considerations

- Single bearer-token boundary (existing). The g3 deployment is reachable
  only by knife's backend, never directly by a model provider.
- Managed-only gating on every mutating endpoint prevents the library from
  injecting data into, or otherwise disturbing, orchestrator-owned scans.
- Canonicalization (`/scan/target/add`) and G3Data validation
  (`/scan/data/insert`) stay server-side; malformed input is rejected, never
  trusted.
- Data-only invocation: the LLM chooses a tool + an object, not arbitrary
  command-line flags, so there is no argv-injection surface. The removal of
  `index` from `/scan/task/dispatch` further closes the avenue of bypassing
  the plugin's own input checks.
- ZIP bundle extraction (`task_artifacts`) is path-traversal-checked in the
  Python client (`_safe_extract_zip`), defending against zip-slip on the
  Python versions supported (3.10–3.11 don't have `data_filter`).

## 10. Deferred / future work

- **Real MCP-protocol server** wrapping the same g3api surface, for use by
  arbitrary MCP clients outside knife. Separate plan.
- **Single-file presets** (`tool:preset` selector): `.g3p` schema change,
  scan-script grammar, preset-aware fingerprints, log attribution. Major
  refactor; separate plan. Until then, presets are distinct plugins.
- **Task-level / log WebSocket streaming** (e.g. a `taskupdate` subscription)
  to replace polling if latency warrants.
- **Import as a dispatched worker task** (addresses the existing
  `g3api.go:495` FIXME); orthogonal to this work.
- **Cache-by-fingerprint lookup.** Run-or-fetch behaviour (`run(..., cached=True)`),
  a `/scan/data/cached` endpoint that server-side-expands the plugin's
  fingerprint templates and queries `LoadFingerprintMatches`, and a
  has-been-run existence-check variant. Deferred for v1. The existence-check
  variant is a natural companion to the in-flight-fingerprint dedup work
  below and should land together.
- **`g3scanner` handles managed scans.** Auto-dispatch and fingerprint cache
  lookup are both orchestrator logic. v1 puts them in g3api (g3api already
  has the template engine via g3lib), but a cleaner long-term home is
  g3scanner — it already evaluates conditions for pipeline scans and
  tracks in-flight fingerprints. Migration would touch the scanner's
  dispatch subscription model; combine with the cache feature when both
  land.
- **Async Python client.** Sync-only in v1 (knife wraps sync calls in
  `asyncio.to_thread` when called from async contexts; negligible overhead
  vs. multi-second tool calls). If MCP perf signals demand it, switch
  transport to `httpx` and `threading.Lock` → `asyncio.Lock` throughout.
- **g3man CLI** (rolled back during this revision). To be re-implemented;
  with `index` removed from `/scan/task/dispatch`, the future g3man uses
  the same auto-dispatch as the Python client.

## 11. Open questions

- Final package name/layout under `clients/python/` — working name `g3client`.

Resolved during the 2026-05-31 revision:
- Plugin contract: opt-in via `llm:` block, no fallback. All three of
  `summary` / `accepts` / `produces` required when block present.
  Enforced at plugin load time by `g3config`.
- `produces` is `[]string`, not `string`.
- `operations[]` removed entirely from `/plugin/describe`.
- `/scan/task/dispatch` removes `index` and always auto-evaluates conditions,
  returning `{task_ids: [...]}`. 400 on zero matches.
- Managed-only gate returns **409 Conflict** for non-managed scans.
- Python client adopts multiton (`Client(key)`) with env-var config and
  eager scan creation.
- `bind` / `unbind` / `keys` / `scan_id` enable knife persistence across
  process restarts.
- `TaskCancelled` exception (rather than a louder state) when a task is
  CANCELED externally.
- Cache-by-fingerprint and async deferred (§10).
