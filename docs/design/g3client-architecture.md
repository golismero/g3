# g3client — Cross-Language Architecture Blueprint

**Status:** Living design document for the `g3client` library family.
**Reference implementation:** Python, at [`sdk/python/`](../../sdk/python/).
**Authoritative design spec:** [docs/superpowers/specs/2026-06-05-g3client-python-library-design.md](../superpowers/specs/2026-06-05-g3client-python-library-design.md).
**Future REST shape this is modeled on:** [docs/future/http-routing-and-rest-migration.md](../future/http-routing-and-rest-migration.md).

---

## 1. Overview & intent

`g3client` is a layered client library for `g3api`, concerned solely with Golismero
(scans, tasks, data, plugins, files, config) — no LLM concerns. It gives callers a clean
method per `g3api` operation plus two high-level orchestration helpers that reproduce the
end-to-end flows that g3cli/g3tui (orchestrated scans) and g3man (managed scans) would perform.

**This document is the language-neutral blueprint.** It defines the abstractions,
vocabulary, recipes, and contracts that *every* `g3client` port shares, so that future
clients can be built cheaply and consistently. The Python package under `sdk/python/`
is the reference implementation; the agnostic design is captured here, and the
Python-specific bits are cordoned off in [§9](#9-what-is-language-specific).

The first planned additional port is a **Go client that `g3cli` and `g3tui` will adopt in
place of their current hand-rolled `g3api` calls** — reusing the same three layers, the
same resource/method names, the same two recipes, and the same envelope/auth/download
contracts. Other-language ports should use the **same method names** so call sites stay
recognizable across languages.

A second deliverable-level intent: the resource layer's method *names* track the **future**
REST shape (see [§3](#3-resource-taxonomy--future-rest-mapping)), so when `g3api` migrates
from POST-everything to method+path routing, the change is a per-method transport edit with
**no change to any caller** — in any language.

---

## 2. Three-layer model

The library is three strict layers. **Each layer knows only the one directly below it.**

```
  ┌──────────────────────────────────────────────────────────┐
  │  Orchestrators        scanner  +  manager                 │  Tier 2 / 3
  │  (dispatch / poll / download recipes; NO protocol         │
  │   knowledge — never touch HTTP or Transport)              │
  └───────────────────────────┬──────────────────────────────┘
                              │ uses only the api tier
                              ▼
  ┌──────────────────────────────────────────────────────────┐
  │  Resources            api  (scans, plugins, files, config)│  Tier 1
  │  (resource-grouped thin wrappers; one method per g3api    │
  │   operation; NO HTTP — only transport.request/.download)  │
  └───────────────────────────┬──────────────────────────────┘
                              │ uses only Transport
                              ▼
  ┌──────────────────────────────────────────────────────────┐
  │  Transport            (the ONLY code that speaks HTTP:     │  Core
  │   auth header, URL join, {status,data} envelope, retry,   │
  │   streaming download) — also the async swap-point          │
  └──────────────────────────────────────────────────────────┘
```

The dependency rule is absolute and is the single most important invariant of the design:

- **Transport** is the only component that performs network I/O. It exposes exactly two
  methods (`request`, `download`); everything else above it is protocol-agnostic.
- **Resources (the `api` tier)** never construct URLs, set headers, or parse responses.
  They call `transport.request` / `transport.download` and shape the result into value
  types. Each method maps 1:1 to a real `g3api` call (or, for the handful of not-yet-existing
  endpoints, emulates one client-side — see [§3](#3-resource-taxonomy--future-rest-mapping)).
- **Orchestrators (`scanner`, `manager`)** are pure "dispatch, poll, download, collect"
  recipes. They compose the `api` tier and the shared `poll_until` helper **exclusively**.
  They contain **no** HTTP, no endpoint strings, no Transport reference.

Because the layers are this clean, an async port only needs to swap Transport (see
[§5](#5-the-polling-contract) and [§9](#9-what-is-language-specific)); the resource and
orchestration layers are untouched.

A shared `poll_until` helper sits beside Transport as a small, pure, network-free utility
that both orchestrators depend on (see [§5](#5-the-polling-contract)).

---

## 3. Resource taxonomy → future-REST mapping

The `api` tier groups methods by resource. **The canonical method names below are the
cross-language vocabulary**: a Go (or any other) port should name its accessors identically
(`scans.create`, `scans.tasks.dispatch`, `files.upload`, …), differing only in
language-idiomatic casing.

**Design rule (state it plainly):**
> Method **names** track the **future** REST resource shape.
> Method **bodies** call **today's** POST-everything endpoints.
> Endpoints that don't exist yet are **emulated client-side** and marked for migration.

Every method's endpoint string lives in exactly one place (a single
`transport.request`/`transport.download` call). The REST migration therefore becomes a
mechanical per-method edit (swap the path, move identifying fields from the body into the
path); **no caller ever changes**. In the reference implementation each such site carries a
`# REST-MIGRATION:` comment pointing at the migration doc — a discipline ports should keep.

| Canonical method (future-shaped) | Today's endpoint | Future REST endpoint |
|---|---|---|
| `scans.create(script)` | `POST /scan/start` | `POST /scans` |
| `scans.create_managed()` | `POST /scan/create` | `POST /scans/managed` |
| `scans.list()` | `POST /scan/list` | `GET /scans/list` |
| `scans.progress()` | `POST /scan/progress` | `GET /scans` |
| `scans.get(scanid)` | *client-side filter of `progress()`* | `GET /scans/{scanid}` |
| `scans.stop(scanid)` | `POST /scan/stop` | `POST /scans/{scanid}/stop` |
| `scans.delete(scanid)` | `POST /scan/delete` | `DELETE /scans/{scanid}` |
| `scans.targets.add(scanid, targets)` | `POST /scan/target/add` | `POST /scans/{scanid}/targets` |
| `scans.data.insert(scanid, data)` | `POST /scan/data/insert` | `POST /scans/{scanid}/data` |
| `scans.data.list(scanid)` | `POST /scan/datalist` | `GET /scans/{scanid}/data/list` |
| `scans.data.get(scanid, *, dataids=None, taskid=None)` | `POST /scan/data` | `GET .../data` (+ `POST .../data/filter` for the `dataids` form) |
| `scans.tasks.dispatch(scanid, *, kind, tool, dataid=None, preset=None)` | `POST /scan/task/dispatch` | `POST /scans/{scanid}/tasks` |
| `scans.tasks.status(scanid)` | `POST /scan/tasks/status` | `GET /scans/{scanid}/tasks` |
| `scans.tasks.list(scanid)` | `POST /scan/tasks` | `GET .../tasks/list` |
| `scans.tasks.get(scanid, taskid)` | *client-side filter of `status()`* | `GET .../tasks/{taskid}` |
| `scans.tasks.stop(scanid, taskids)` | `POST /scan/task/cancel` | `POST .../tasks/{taskid}/stop` |
| `scans.tasks.artifacts(scanid, taskid, dest)` | `POST /scan/task/artifacts` (download) | `GET .../tasks/{taskid}/artifacts` |
| `scans.imports.create(scanid, tool, fileid)` | `POST /scan/import` | `POST /scans/{scanid}/import` |
| `scans.logs.get(scanid, taskid=None)` | `POST /scan/logs` | `GET /scans/{scanid}/logs` |
| `files.upload(path)` | `POST /file/upload` | `POST /files` |
| `plugins.list()` | `POST /plugin/list` | `GET /plugins` |
| `plugins.describe()` | `POST /plugin/describe` | `GET /plugins/describe` |
| `config.env()` | `POST /config/env` | `GET /config/env` |

### Handling endpoints that don't exist yet

Three categories of gap exist between the canonical surface and today's transport. Each is
emulated client-side and marked for migration:

- **Single-resource GETs** — `scans.get(scanid)` and `scans.tasks.get(scanid, taskid)`
  have no dedicated endpoint today. They are emulated by fetching the batch
  `progress()` / `status()` result and filtering for the requested id. When `GET /scans/{id}`
  and `GET .../tasks/{tid}` land, each body swaps to a direct call; the signature and every
  caller are unchanged.
- **Bulk-by-ID data lookup** — `scans.data.get(..., dataids=[...])` uses today's
  `POST /scan/data`. In the future shape, the no-ID form becomes `GET .../data` and the
  by-ID form becomes `POST .../data/filter` (the one deliberate "POST-as-search" endpoint).
- **Reports** — there is **no** report endpoint today. A report is produced by dispatching
  a reporter **task** and downloading its artifact. The `api` tier therefore exposes only the
  primitives (`scans.tasks.dispatch(kind="report", ...)` + `scans.tasks.artifacts`); the
  Scanner recipe ([§4](#4-the-two-orchestration-recipes)) composes them. This keeps Tier 1
  honestly 1:1 with real transport calls. A future `GET /scans/{scanid}/report` would collapse
  the dance; until then the primitives stand.

---

## 4. The two orchestration recipes

Both recipes are composed **only** from the `api` tier and `poll_until`. They are presented
here as language-independent step sequences so any port can reproduce them exactly.

### 4.1 Orchestrated scan — the `scanner.scan` flow

This is the g3cli/g3tui path: run a pipeline against targets, wait for the whole scan, then
produce a downloadable report.

1. **Upload imports.** For each `(tool, path)` import pair, call `files.upload(path)` to get
   a `fileid`. (Skipped entirely if the caller supplies a raw `script` string instead.)
2. **Build the script DSL.** Render the g3 script grammar from the structured args: a
   `mode` line, then `target` lines, then `import <tool> "<fileid>"` lines (using the
   uploaded file ids), then the pipeline lines. The grammar is g3's `ParsedScript` — see
   `ParsedScript.String()` in [`src/g3lib/script.go`](../../src/g3lib/script.go); ports
   should match its output. **No `report` line is ever emitted** — reporting is a separate
   post-scan task (see step 5). A raw `script="..."` escape hatch bypasses steps 1–2.
3. **Create the scan.** `scanid = scans.create(script)`.
4. **Poll the scan to a terminal status.** `poll_until` over `scans.get(scanid)` with the
   predicate "progress is non-null and terminal". On each poll round:
   - fire the optional `on_progress(ScanProgress)` callback;
   - if an `on_log` callback is set, fetch `scans.logs.get(scanid)` and emit only entries
     past a tracked high-water mark (incremental logs).
   On a terminal status: `ERROR` raises `TaskFailed`, `CANCELED` raises `TaskCancelled`,
   otherwise continue. If `report` was not requested, return here.
5. **Dispatch a post-scan reporter task.** `scans.tasks.dispatch(scanid, kind="report",
   tool, preset)` where `tool[:preset]` names the reporter (no plugin name is hardcoded —
   report formats *are* reporter presets). Take the returned task id.
6. **Poll the reporter task to terminal**, via `poll_until` over `scans.tasks.get`. `ERROR`
   → `TaskFailed`, `CANCELED` → `TaskCancelled`.
7. **Download the report artifact.** `scans.tasks.artifacts(scanid, report_task_id)`.
8. **Return** a `ScanReport(scanid, status, report_path, report_bytes, task_ids)`.
   `report_bytes` is the file's contents when the artifact is a single file, and `None` when
   it unpacked to a directory.

**Decision:** the Scanner always reports via a post-scan reporter *task*, never via a
`report` line baked into the script — this yields a clean downloadable artifact and reuses
one report machinery across both tiers.

### 4.2 Managed run — the `manager.run` flow

This is the g3man path: an externally-driven scan you feed data into and run individual
tools against, asynchronously. A `Manager` owns one managed `scan_id` and tracks every task
it launches (`task_id → tool`).

1. **Create or attach.** New `Manager` → `scans.create_managed()` and own the returned
   `scan_id`. `Manager(scanid=...)` re-attaches to an existing managed scan (restart /
   rehydration) without creating one.
2. **Seed inputs** (any combination, as needed):
   - `add_targets(targets)` → `scans.targets.add`, then `scans.data.get(dataids=...)` to
     return the inserted G3Data objects;
   - `insert_data(data)` → `scans.data.insert` (returns data ids);
   - `import_file(tool, path)` → `files.upload` then `scans.imports.create` (returns data ids).
3. **Dispatch tool task(s) asynchronously.** `launch(tool, dataid, preset)` →
   `scans.tasks.dispatch(kind="tool", ...)`. This returns immediately. **A single dispatch
   may fan out to several task ids** (one per matched command/condition); all are recorded
   in the tracking map.
4. **Poll all dispatched ids to terminal.** `wait(task_ids)` runs `poll_until` over
   `scans.tasks.status(scan_id)` with the predicate "every wanted id is present and
   terminal", firing an optional `on_status(ScanTasksStatus)` each round. The most recent
   snapshot is retained so a timeout never needs a fresh (possibly-throwing) network call.
   On deadline it raises `TaskTimeout` carrying the unfinished ids and their last states.
5. **Handle cancellation.** If any task reached `CANCELED`, raise `TaskCancelled` with those
   ids.
6. **Aggregate state worst-wins.** Across the fan-out, combine task states by priority
   `ERROR > WARNING > DONE`; the worst state wins and becomes the outcome state. Non-empty
   per-task error messages are joined. (CANCELED is handled in step 5, before aggregation;
   TIMEOUT is raised in step 4.)
7. **Download artifacts per task.** For each dispatched id, `fetch_artifacts(task_id)` →
   `scans.tasks.artifacts`. Each task downloads into **its own slot** under a common parent
   directory (per-task isolation; no cross-task clobber).
8. **Collect produced data.** For each task, `results(task_id)` →
   `scans.data.get(taskid=...)`; concatenate.
9. **Return** a `RunOutcome(state, data, artifacts_dir, error_msg, task_ids)`.

`dispose()` deletes the managed scan via `scans.delete`.

---

## 5. The polling contract

Both orchestrators build every wait on one shared, pure helper — `poll_until` — so no tier
writes its own loop.

**Contract:**

- **Inputs:** a `fetch` callable (returns the latest observation), a `predicate` (true when
  done), an `interval` (default 2.0s — the repo-wide cadence), a `timeout` (a deadline), an
  optional `on_poll` callback invoked with every observation, and **injected `clock` and
  `sleep`**.
- **Fetch-immediately, then interval:** call `fetch` once right away (and run `on_poll`), test
  the predicate, and only then sleep `interval` before the next round. This guarantees fast
  paths return without an initial delay.
- **Predicate-driven:** returns the first observation that satisfies `predicate`.
- **Deadline → timeout signal:** the deadline is computed on a monotonic clock at entry; once
  it is exceeded the helper raises a generic timeout signal (the language's built-in timeout
  error). It does **not** know about task ids or domain semantics.
- **Domain translation:** the *orchestrator* catches the generic timeout and re-raises a
  **domain** timeout carrying the pending ids and their last-observed states — `TaskTimeout`
  (see [§7](#7-error-taxonomy)). The orchestrator retains the last successful snapshot
  precisely so it can build that payload without a fresh, possibly-failing fetch.

**Why injected clock/sleep:** deterministic unit tests (drive the loop with a fake clock, no
real waiting) and **async portability** — an async port supplies an async sleep and the same
loop shape works under cooperative scheduling. This is what makes the polling layer reusable
across the sync reference client and any future async/Go port.

---

## 6. Value-type model

The library returns immutable value types. **Every type retains the raw server object** (a
`raw` field holding the original response dict) for forward-compatibility: new server fields
are reachable without a library change. Ports should keep this convention.

### Server-derived types

| Type | Fields | Source |
|---|---|---|
| `ScanProgress` | `scanid`, `status`, `progress` (nullable int), `message`, `raw`; `.is_terminal` | `scans.progress` / `scans.get` |
| `TaskStatus` | `task_id`, `tool`, `worker`, `state`, `dispatched_at`, `started_at`, `completed_at` (nullable timestamps), `error_msg`, `raw`; `.is_terminal` | per-task status |
| `ScanTasksStatus` | `scan_status`, `tasks` (tuple of `TaskStatus`), `raw` | `scans.tasks.status` |
| `PluginInfo` | `name`, `url`, `description`, `raw` | `plugins.list` |
| `PluginContract` | `name`, `summary`, `accepts` (tuple), `produces` (tuple), `raw` | `plugins.describe` |

### Synthesized result types (built by the orchestrators, not the server)

| Type | Fields | Produced by |
|---|---|---|
| `ScanReport` | `scanid`, `status`, `report_path` (nullable), `report_bytes` (nullable), `task_ids` | `scanner.scan` |
| `RunOutcome` | `state` (worst-wins aggregate), `data` (concatenated produced G3Data), `artifacts_dir`, `error_msg` (joined), `task_ids` | `manager.run` |

### Terminal-state sets

These define when polling stops; ports must use the same sets:

- `TASK_TERMINAL_STATES = {DONE, WARNING, ERROR, CANCELED}`
- `SCAN_TERMINAL_STATES = {FINISHED, ERROR, CANCELED}`

`TaskStatus.is_terminal` and `ScanProgress.is_terminal` are membership tests against these
sets.

---

## 7. Error taxonomy

A single base, with operationally-meaningful subclasses. The column **"raised by"** is part
of the contract — ports should raise the same error from the same layer.

| Error | Carries | Raised by |
|---|---|---|
| `ClientError` | — (base for all client errors) | base class only |
| `ApiError` | `status_code`, `message` | **Transport** — on an `error` envelope, a non-2xx status, a non-JSON response, or an exhausted transient-retry (status code `0`) |
| `TaskTimeout` | `task_ids`, `last_states` | **Orchestrators** — translated from the polling layer's generic timeout, carrying the pending ids and their last-observed states |
| `TaskCancelled` | `task_ids` | **Orchestrators** — when a scan/task reached `CANCELED` |
| `TaskFailed` | `task_ids`, `error_msg` | **Orchestrators** — when a scan/task reached a terminal `ERROR` |

The polling helper itself raises only the language's generic timeout error; it never raises a
domain error. Transport raises only `ApiError`. Everything task/scan-semantic
(`TaskTimeout`/`TaskCancelled`/`TaskFailed`) is raised by the orchestration tier, which is the
only layer that understands states.

---

## 8. Envelope / auth / download contracts

These are wire-level contracts that every port must implement identically (they live in
Transport):

**Response envelope.** `g3api` responses are `{status, data}`. Transport unwraps to `data`.
It raises `ApiError(status_code, message)` when the HTTP status is ≥ 400 **or** `status ==
"error"`; the error message is taken from `data` (if a string) else a `message` field. All
callers above Transport see only the unwrapped `data`, never the envelope.

**Authentication.** Bearer token: an `Authorization: Bearer <token>` header is set once on the
session/transport at construction. Credentials are explicit constructor arguments with env
fallback (`G3_API_BASEURL` / `G3_API_TOKEN` / `G3_ARTIFACTS_ROOT`). Both base URL and token
are required (a missing one is a construction-time `ClientError`).

**Transient retry / backoff.** `request` retries a small number of times on transport-level
failures (connection errors, etc.) with exponential backoff; an exhausted retry surfaces as
`ApiError(0, ...)`. This retry is at the transport layer only — it does not re-interpret
application-level `error` envelopes (those raise immediately).

**Streaming, safe artifact download.** `download` streams the response to a temp file for
atomicity, derives the output filename from the `Content-Disposition` header (basename only —
no path components honored), and writes via a temp-then-rename. If the payload is a zip (by
filename or content type), it is extracted **zip-slip-safely**: every member's resolved path
must stay within the destination directory, or the whole extraction is refused with a
`ClientError`. On any failure the temp file is cleaned up. Each task's artifacts download into
its own destination slot (per-task isolation).

---

## 9. What is language-specific

The agnostic core is everything above. These are the reference-implementation (Python)
choices a port may replace freely:

- **HTTP client.** Python uses `requests` with a shared `Session` carrying the auth header.
  A Go port uses `net/http` with a `*http.Client`; the envelope/auth/retry/download contracts
  in [§8](#8-envelope--auth--download-contracts) are identical regardless.
- **Value types.** Python uses frozen `dataclasses` with `from_raw` constructors and a `raw`
  passthrough. A Go port uses structs with a `Raw map[string]any` (or `json.RawMessage`)
  field; the field set and the keep-the-raw convention are the same.
- **Concurrency model.** v1 is **synchronous with an async-ready seam**: all I/O funnels
  through Transport's two methods, and `poll_until` takes injected clock/sleep. This is the
  *only* swap-point for an async variant — an `AsyncTransport` with the same two-method
  surface, plus an async sleep into `poll_until`, and the resource/orchestration layers are
  untouched. **A Go port maps the same recipes onto goroutines/contexts** (a `context.Context`
  deadline replaces the injected clock; channels/`select` replace the sleep loop) while
  preserving the identical recipe steps, method names, and wire contracts. The concurrency
  *mechanism* differs; the *recipes* do not.
- **Packaging / configuration plumbing.** `pyproject.toml`, the `_`-prefixed internal-module
  convention, env-var fallback wiring — all idiomatic-Python; a Go port uses its own module
  layout and config plumbing.

Everything in [§2](#2-three-layer-model)–[§8](#8-envelope--auth--download-contracts) — the
layering, the method names, the two recipes, the polling contract, the value-type field sets
and terminal-state sets, the error taxonomy, and the envelope/auth/download contracts — is
shared and must be matched.

---

## 10. Migration & extensibility note

**REST migration is a per-method transport edit.** Because each `api` method holds its
endpoint string in exactly one `transport.request`/`download` call, and is already *named*
for the future resource (see [§3](#3-resource-taxonomy--future-rest-mapping)), the migration
from POST-everything to method+path routing is mechanical: change the path string, move
identifying fields from the body into the path, and (for the emulated single-resource GETs)
replace the client-side filter with a direct call. **No caller — in any tier, in any
language — changes.** The reference implementation flags every such site with a
`# REST-MIGRATION:` comment; ports should preserve equivalent markers.

**Additional language clients are planned.** The first is a **Go client that `g3cli` and
`g3tui` adopt** in place of their hand-rolled `g3api` calls — built directly against this
blueprint, reusing the same three layers, the same canonical method names, the same two
recipes, and the same envelope/auth/download contracts, with the concurrency differences
noted in [§9](#9-what-is-language-specific). This document is the contract those ports build
against; keep it and the Python reference in sync as the design evolves.
