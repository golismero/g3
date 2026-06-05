# g3client — Python Client Library for g3api (Design)

**Date:** 2026-06-05
**Status:** Approved design; implementation plan to follow.
**Context:** Part of the Knife integration ([docs/future/knife-integration-design.md](../../future/knife-integration-design.md)).
**Related:** REST migration ([docs/future/http-routing-and-rest-migration.md](../../future/http-routing-and-rest-migration.md)).

## 1. Purpose

Provide a clean, layered Python client library for `g3api`, solely concerned with
Golismero (no LLM concerns). It replaces the abandoned reference client at
`private/clients/python` (kept only for code/logic salvage) with a new production
package at the repo-root `clients/python/`.

The library is delivered in three tiers, each a strict layer over the one below:

- **Tier 1 — `g3client.api`**: thin, resource-grouped wrappers over every individual
  `g3api` call. Purely mechanical transport.
- **Tier 2 — `g3client.scanner`**: high-level helper for *orchestrated* scans (the
  g3cli/g3tui path). A `scan()` that launches a scan, waits for completion (with
  optional progress/log callbacks), and returns the report in a requested format.
- **Tier 3 — `g3client.manager`**: high-level helper for *managed* scans (the g3man
  path). A `Manager` that tracks scan/task IDs, launches tools asynchronously, polls,
  downloads artifacts, and offers a synchronous `run()` for a single tool.

**Tiers 2 and 3 use `g3client.api` exclusively — no manual API calls.**

A second, equally important deliverable is a **language-agnostic architecture document**
(`docs/design/g3client-architecture.md`) that documents the client abstractions so that
future ports — notably a Go client for g3cli/g3tui — are cheap and consistent.

## 2. Goals and non-goals

### Goals
- One clean Python method per current `g3api` endpoint, grouped by resource.
- The `api` submodule is modeled on the **future** REST resource shape (see the REST
  migration doc), not the current `POST`-everything shape, so the eventual migration is a
  per-method transport edit with **no change to any caller**.
- High-level helpers that reproduce, in Python, the end-to-end flows that g3cli/g3tui
  (orchestrated) and g3man (managed) perform.
- Explicit, testable construction (credentials as arguments, env as fallback).
- A documented, language-agnostic abstraction layer to seed future clients.

### Non-goals (out of scope for this plan)
- **No LLM functionality.** No `DATA_PRIMER`, no LLM-facing contracts policy, no
  reasoning helpers. The existing `g3client.llm` reference package is not carried over;
  a future `llm` submodule may be rebuilt on top of `api` later, but that is out of scope.
- **No other-language clients yet.** Additional `g3client` libraries are planned —
  notably a **Go client that g3cli and g3tui adopt in place of their hand-rolled API
  calls**, reusing these same abstractions — but this plan delivers only the Python
  library and the architecture doc that makes those ports cheap.
- **No async implementation.** v1 is synchronous; an async-ready seam is built in (§6) so
  an async variant can be added later without reworking the resource layer.
- The library does not construct `G3Data` envelopes on the caller's behalf beyond what the
  server returns (callers receive G3Data from `add_targets`/`results`/`import_file`).

## 3. Key decisions

| Decision | Choice | Rationale |
|---|---|---|
| Location | New repo-root `clients/python/` (the path the REST-migration doc already names). Leave `private/clients/python` as untouched reference. | Promotes the client to a real production home; clean break from the failed version. |
| API shape | **Resource-grouped accessors** over a **Transport core**. | Mirrors the future nested REST resources; migration becomes a per-method transport swap; the same vocabulary seeds other languages. |
| Concurrency | **Sync now, async-ready seam.** | Matches Knife's threaded blocking-poll model and the Go port; async adds contagious calling conventions and harder artifact/zip code for little gain here. |
| Configuration | **Explicit args + env fallback.** `Client(base_url, token, ...)` falling back to `G3_API_BASEURL` / `G3_API_TOKEN` / `G3_ARTIFACTS_ROOT`. | Library-friendly, testable, embeddable; matches the knife doc's stateless `(base_url, token)`. |

## 4. Package layout

```
clients/python/                      # promoted out of private/; new production home
├── pyproject.toml                   # name="g3client", deps: requests; py>=3.10; GPL-3.0-or-later
├── README.md
└── g3client/
    ├── __init__.py                  # version; re-export ApiClient, Scanner, Manager, errors
    ├── _transport.py                # Transport: auth, request(), download(), envelope, retry
    ├── _polling.py                  # poll_until(predicate, fetch, clock, interval, timeout)
    ├── errors.py                    # exception hierarchy (ported from old client)
    ├── types.py                     # frozen value types + terminal-state sets
    ├── api/                         # Tier 1 — resource-grouped thin wrappers
    │   ├── __init__.py              # ApiClient (composition root); links REST-migration doc
    │   ├── scans.py                 # ScansResource + nested Targets/Data/Tasks/Imports/Logs
    │   ├── plugins.py               # PluginsResource
    │   ├── files.py                 # FilesResource
    │   └── config.py                # ConfigResource
    ├── scanner/                     # Tier 2 — orchestrated scans (g3cli/g3tui-like)
    │   └── __init__.py              # Scanner
    └── manager/                     # Tier 3 — managed scans (g3man-like)
        └── __init__.py              # Manager
```

The top-level `g3client` package stays thin; tiers live in their own subpackages so each
can be understood and tested in isolation.

## 5. Shared internals

These underpin all three tiers and are not part of any tier's public surface (prefixed
`_` where internal).

### 5.1 `_transport.py` — `Transport`
The single seam through which **all** network I/O passes. Owns:
- a `requests.Session` with the `Authorization: Bearer <token>` header,
- base-URL joining,
- the `{status, data}` envelope unwrap (raise `ApiError` on `status == "error"` or non-2xx),
- a small retry/backoff for transient transport failures,
- exactly **two** I/O methods:
  - `request(method, path, *, json=None, params=None, files=None) -> Any` — returns the
    unwrapped `data`.
  - `download(method, path, dest, *, json=None) -> Path` — streaming download with
    temp-file atomicity, `Content-Disposition` filename handling, and **zip-slip-safe**
    extraction. Ported verbatim from the old client (`client.py:508-564`, `:637-651`).

**This is the only async swap-point.** An `AsyncTransport` exposing the same two methods is
all a future async variant needs; resource and orchestration code never change.

### 5.2 `_polling.py` — `poll_until(...)`
The one reusable poll-loop, mirroring g3tui's Go `Poll` helper and the old client's
`_wait_for_all`:
- takes an injected `clock`/`sleep` (deterministic tests; async-portable),
- a `fetch` callable and a `predicate`,
- an `interval` (default 2.0s, the repo-wide cadence) and a `timeout` (deadline on a
  monotonic clock),
- fires `fetch` immediately, then on each interval; returns when `predicate` is satisfied;
  raises the builtin `TimeoutError` on deadline.

`poll_until` stays free of task semantics: it raises the generic `TimeoutError`, and the
orchestration tiers (`scanner`/`manager`) catch it and translate to the domain
`TaskTimeout` carrying the pending task ids and last-observed states. Both Tier 2 and
Tier 3 build their waits on this; neither writes its own loop.

### 5.3 `errors.py` — exception hierarchy
Ported from the old client (all have operational value outside LLM use):
- `ClientError` — base.
- `ApiError(status_code, message)` — server error envelope or non-2xx.
- `TaskTimeout(task_ids, last_states)` — polling deadline before terminal state.
- `TaskCancelled(task_ids)` — task reached `CANCELED`.
- `TaskFailed(task_ids, error_msg)` — *new*; clean surfacing of terminal `ERROR`.

### 5.4 `types.py` — value types
`frozen` dataclasses, each retaining a `raw: dict` for forward-compatibility:
- `ScanProgress(scanid, status, progress, message, raw)`
- `TaskStatus(task_id, tool, worker, state, dispatched_at, started_at, completed_at, error_msg, raw)` with `.is_terminal`
- `ScanTasksStatus(scan_status, tasks, raw)` — the batch result of `tasks.status`
- `PluginInfo(name, url, description, raw)` — from `plugin/list`
- `PluginContract(name, summary, accepts, produces, raw)` — from `plugin/describe`
- `RunOutcome(state, data, artifacts_dir, error_msg, task_ids)` — Tier 3 result
- `ScanReport(scanid, status, report_path, report_bytes, task_ids)` — Tier 2 result
- `TASK_TERMINAL_STATES = frozenset({"DONE", "WARNING", "ERROR", "CANCELED"})`
- `SCAN_TERMINAL_STATES = frozenset({"FINISHED", "ERROR", "CANCELED"})`

**Excluded:** `DATA_PRIMER`, the LLM-slim `PluginContract` philosophy, and the old
`RunResult`'s LLM framing (the worst-wins aggregation *logic* is reused in `RunOutcome`).

## 6. Tier 1 — `g3client.api` (resource-grouped thin wrappers)

`ApiClient(base_url=None, token=None, *, artifacts_root=None, timeout=..., session=None)`
constructs one `Transport` and hangs resource accessors off it. **Resources never touch
HTTP directly — only `transport.request` / `transport.download`.** Each method is named for
the future resource model; its implementation targets today's endpoint.

The `api/__init__.py` module docstring links
[docs/future/http-routing-and-rest-migration.md](../../future/http-routing-and-rest-migration.md)
and states the design rule: *names track the future REST shape; bodies track today's
transport; the migration is a per-method edit.*

### 6.1 Surface and migration mapping

| Tier-1 call (future-shaped) | Implemented today against | Refactor target |
|---|---|---|
| `api.scans.create(script, scanid=None)` | `POST /scan/start` | `POST /scans` |
| `api.scans.create_managed()` | `POST /scan/create` | `POST /scans/managed` |
| `api.scans.list()` | `POST /scan/list` | `GET /scans/list` |
| `api.scans.progress()` | `POST /scan/progress` | `GET /scans` |
| `api.scans.get(scanid)` | *client-side filter of `progress()`* | `GET /scans/{id}` |
| `api.scans.stop(scanid)` | `POST /scan/stop` | `POST /scans/{id}/stop` |
| `api.scans.delete(scanid)` | `POST /scan/delete` | `DELETE /scans/{id}` |
| `api.scans.targets.add(scanid, targets)` | `POST /scan/target/add` | `POST /scans/{id}/targets` |
| `api.scans.data.insert(scanid, data)` | `POST /scan/data/insert` | `POST /scans/{id}/data` |
| `api.scans.data.list(scanid)` | `POST /scan/datalist` | `GET /scans/{id}/data/list` |
| `api.scans.data.get(scanid, *, dataids=None, taskid=None)` | `POST /scan/data` | `GET .../data` + `POST .../data/filter` |
| `api.scans.tasks.dispatch(scanid, *, kind, tool, dataid=None, preset=None)` | `POST /scan/task/dispatch` | `POST /scans/{id}/tasks` |
| `api.scans.tasks.status(scanid)` | `POST /scan/tasks/status` | `GET /scans/{id}/tasks` |
| `api.scans.tasks.list(scanid)` | `POST /scan/tasks` | `GET .../tasks/list` |
| `api.scans.tasks.get(scanid, taskid)` | *client-side filter of `status()`* | `GET .../tasks/{tid}` |
| `api.scans.tasks.stop(scanid, taskids)` | `POST /scan/task/cancel` | `POST .../tasks/{tid}/stop` |
| `api.scans.tasks.artifacts(scanid, taskid, dest)` | `POST /scan/task/artifacts` (download) | `GET .../tasks/{tid}/artifacts` |
| `api.scans.imports.create(scanid, tool, fileid)` | `POST /scan/import` | `POST /scans/{id}/import` |
| `api.scans.logs.get(scanid, taskid=None)` | `POST /scan/logs` | `GET /scans/{id}/logs` |
| `api.files.upload(path)` | `POST /file/upload` | `POST /files` |
| `api.plugins.list()` | `POST /plugin/list` | `GET /plugins` |
| `api.plugins.describe()` | `POST /plugin/describe` | `GET /plugins/describe` |
| `api.config.env()` | `POST /config/env` | `GET /config/env` |

### 6.2 Forward-compat handling of API gaps

Some future single-resource GETs do not exist yet. Each is marked with a
`# REST-MIGRATION:` comment pointing at the migration doc:

- **`api.scans.get(scanid)` / `api.scans.tasks.get(scanid, taskid)`** — emulated
  client-side today by filtering the batch `progress()` / `status()` results. When the
  refactor adds `GET /scans/{id}` and `GET .../tasks/{tid}`, the body swaps to a direct
  call; the signature is unchanged.
- **Reports** — there is no `/scan/report` endpoint (verified against `g3api.go`); reports
  today are a dispatched reporter *task* plus an artifact download. Tier 1 therefore
  exposes only the primitives (`tasks.dispatch(kind="report", ...)` + `tasks.artifacts`).
  A `# REST-MIGRATION:` note records that a future `GET /scans/{id}/report` would collapse
  the dance; until then Tier 2 composes the primitives. This keeps Tier 1 honestly 1:1
  with real transport calls.

### 6.3 Why this satisfies the "agnostic / trivial migration" requirement
The endpoint string lives in exactly one place per method (a one-line `transport.request`
call). The REST migration becomes a mechanical per-method edit (`"/scan/start"` → `"/scans"`,
move path fields into the path); no caller of `api.scans.create(...)` ever changes.

## 7. Tier 2 — `g3client.scanner` (orchestrated scans)

`Scanner(api)` — or `Scanner.from_credentials(base_url, token)`, which builds the
`ApiClient`. One headline method, composed **only** from `api`:

```python
report = scanner.scan(
    targets=["https://example.com", "10.0.0.1"],
    pipeline=["nmap", "nikto | testssl"],     # tools or pipe-chains
    mode="parallel",                           # or "sequential"
    imports=[("nessus", "scan.xml")],          # optional (tool, path) pairs
    report="magenta:json",                     # reporter tool[:preset]; or ("magenta","json"); or None
    on_progress=lambda p: ...,                 # optional ScanProgress callback
    on_log=lambda lines: ...,                  # optional incremental log callback
    timeout=1800,
) -> ScanReport
```

Flow (mirrors g3cli/g3tui):
1. Upload each `imports` file via `api.files.upload`, then **build the script DSL**
   (`mode` / `target` / `import` / pipeline lines) from the structured args. A raw
   `script="..."` escape hatch is also accepted (matches `g3 scan`).
2. `scanid = api.scans.create(script)`.
3. `poll_until` on `api.scans.get(scanid)` until the scan status is terminal — firing
   `on_progress` each round; if `on_log` is set, also pull `api.scans.logs.get(scanid)` and
   emit only lines past a tracked high-water timestamp.
4. If `report` requested: dispatch the reporter as a **post-scan task**
   (`api.scans.tasks.dispatch(scanid, kind="report", tool, preset)`), `poll_until`
   task-terminal, then `api.scans.tasks.artifacts(...)` to download. (This is precisely
   `g3 report` / g3tui `GetReport`; there is no `/scan/report` shortcut yet.)
5. Return `ScanReport(scanid, status, report_path, report_bytes, task_ids)`.

**Output format** is just the reporter `tool[:preset]` — no plugin name is hardcoded; the
caller names the reporter, and the framework's report formats *are* reporter presets.

**Decision:** Tier 2 always reports via a **post-scan reporter task**, never via a `report`
line baked into the script, to get a clean downloadable artifact and reuse the same report
machinery for both tiers.

## 8. Tier 3 — `g3client.manager` (managed scans)

`Manager(api)` creates a managed scan (`api.scans.create_managed`) and **owns its
`scan_id`**; `Manager(api, scanid=...)` re-attaches to an existing one (restart /
rehydration). It **tracks scan and task IDs** internally (`scan_id`, plus a `task_id → tool`
map of everything it has launched). Composed **only** from `api`:

```python
mgr = Manager(api)                               # or Manager(api, scanid=...)
objs   = mgr.add_targets(["10.0.0.1"])           # -> [G3Data] (with _id)
ids    = mgr.insert_data([...])                  # raw G3Data insert -> [dataid]
ids    = mgr.import_file("nessus", "scan.xml")   # upload + import -> [dataid]

task_ids = mgr.launch(tool, dataid, preset=None) # ASYNC dispatch, returns immediately
status   = mgr.poll()                            # all tracked tasks' status
done     = mgr.wait(task_ids, on_status=cb)      # poll_until terminal -> {taskid: TaskStatus}
path     = mgr.fetch_artifacts(task_id, dest)    # download bundle
data     = mgr.results(task_id)                  # G3Data produced by a task

outcome  = mgr.run(tool, dataid, preset=None,    # the SYNC headline:
                   on_status=cb, dest=...)        #   launch -> wait -> download -> collect
mgr.dispose()                                    # delete the managed scan
```

`run()` is the Tier-3 equivalent of `g3man run` + `ps` + `fetch`: dispatch one tool, poll
to completion, download artifacts, collect produced data, and return a
`RunOutcome(state, data, artifacts_dir, error_msg, task_ids)`. State is aggregated
**worst-wins** (`ERROR > WARNING > DONE`); `CANCELED` raises `TaskCancelled`; timeout raises
`TaskTimeout` carrying the unfinished IDs — the old client's sound polling core, minus LLM
policy.

## 9. Dependency stack and isolation

```
manager / scanner   (Tier 2/3 — orchestration recipes; no protocol knowledge)
      │
      ▼
   api (Tier 1)      (resource-grouped wrappers; no HTTP)
      │
      ▼
  Transport          (the only code that speaks HTTP; the async seam)
```

Each layer knows only the one below. Tier 2/3 are pure "dispatch, poll, download" recipes
that lean on the same `poll_until` and `Transport`. Tier 2 touches only the orchestrated
subset (`scans.create` + progress + report-task); Tier 3 touches only the managed subset
(`create_managed` + targets/data + per-task dispatch). Neither reimplements the other.

## 10. Cross-language architecture document (deliverable)

`docs/design/g3client-architecture.md` — language-neutral, defining:
- The **three-layer model** (Transport → Resources/`api` → Orchestrators/`scanner`+`manager`)
  and the dependency rule.
- The **resource taxonomy** and its mapping to the future REST shape (§6.1, framed as the
  canonical vocabulary: `scans.create`, `tasks.dispatch`, `tasks.artifacts`, …) — so a Go
  client uses the *same names*.
- The **two orchestration recipes** (orchestrated-scan §7, managed-run §8) as numbered,
  language-independent step sequences.
- The **polling contract**, **value-type fields**, **error taxonomy**, and
  **envelope/auth/download contracts**.
- A short "**what is language-specific**" section (`requests`/`Session`, dataclasses, the
  async seam) cordoned off from the agnostic core.

This doc is explicitly the blueprint the eventual **Go client (for g3cli/g3tui)** and any
other-language client build against.

## 11. Salvage map (from `private/clients/python`)

Reuse (protocol correctness, LLM-free):
- Envelope parsing (`client.py:196-223`).
- Bearer + `Session` setup (`client.py:100-104`).
- Deadline-based multi-task polling (`client.py:463-493`) → `_polling.poll_until`.
- Streaming download + temp atomicity (`client.py:508-564`).
- Zip-slip-safe extraction (`client.py:637-651`).
- Worst-wins state aggregation (`client.py:34-36, 343-360`) → `RunOutcome`.
- Error hierarchy (`errors.py:4-50`).

Drop (policy / LLM): multiton + eager scan creation, `run()`'s LLM framing, `DATA_PRIMER`,
the LLM-slim `PluginContract` philosophy, `RunResult` aggregation policy.

## 12. Testing and verification

Per project convention, tests and binary/live-server runs are user-owned; agent
verification for the implementation is limited to lint + (where applicable) import/build
checks. The design favors testability: the injected clock in `poll_until` and the single
`Transport` seam make the orchestration tiers unit-testable without a live server.

## 13. Open questions / deferred

- **Async variant** — deferred; the `Transport`/`poll_until` seams make it additive.
- **Future `llm` submodule** rebuilt on `api` — out of scope; the namespace leaves room.
- **`GET /scans/{id}/report`** and other single-resource GETs — adopt when the REST
  migration lands; `# REST-MIGRATION:` markers flag every site.
- **Go and other-language clients** — out of scope; seeded by §10.
