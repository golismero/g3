# Reporter Plugins — Tier 2 Design

Brainstormed 2026-05-18.

## Context

Tier 1 of the reporter plugin system ([prior spec](2026-05-16-reporter-plugins-design.md))
shipped a synchronous `POST /scan/reporter` endpoint that blocks until the
reporter task reaches a terminal state, then streams the bundled output back to
the caller. Tier 2 is the asynchronous follow-up: clients can kick off a
reporter task without holding the HTTP connection for the duration of the run,
and clients can download any terminal task's slot via a generic endpoint
(reporter or otherwise).

A third piece — first-class task cancellation via HTTP — was pulled into this
tier alongside the original two. It is mildly orthogonal to reporters
specifically, but it completes the "reporter tasks behave like first-class
tasks" story by giving the API surface a single cancel-by-id endpoint that
works for any task kind.

## Goal

Add three endpoints to g3api:

1. `POST /scan/task/artifacts` — generic, task-scoped artifacts download. Works
   for any terminal task with a non-empty slot. Reuses the `BundleTaskSlot`
   logic introduced in Tier 1.
2. `POST /scan/reporter` with `"async": true` body field — async kickoff that
   returns `202 Accepted` and `{ "task_id": "..." }` immediately. Tier 1's
   sync behavior is the default (`async` omitted or `false`).
3. `POST /scan/task/cancel` — batch cancel by `(scan_id, task_ids)`. Mirrors
   the existing `G3CancelTask` MQTT message shape. Works for any task kind.

## Non-goals

- A new task-status endpoint. Reporter tasks already surface in the existing
  `/scan/tasks/status` (per-scan list); the async client lifecycle uses that
  endpoint as-is.
- A WebSocket subscription channel for task state. The existing WS task
  channel (described in the prior architecture work) handles this — reporter
  tasks flow through the same `SetTaskRunning` / `SetTaskTerminal` plumbing
  and are surfaced identically.
- An `?async=true` query-parameter style. Inconsistent with the rest of g3api,
  which is uniformly POST + JSON body with no query params (per
  `ValidateHttpRequest` in `src/g3lib/api.go`). The async opt-in is a body
  field instead.
- A separate single-task cancel endpoint. The batch shape covers both cases
  (a single-task cancel is a list of length 1).
- Per-file download (e.g. `GET /scan/task/artifacts/<path>`). Out of scope per
  prior brainstorming — opens a whole class of path-injection concerns that
  the bundle-only design avoids. Programmatic per-file consumers can unzip
  client-side.
- Pre-download enumeration of slot contents (e.g. a "list files in the slot"
  JSON endpoint). Possible future work but not in Tier 2 — adds another API
  surface for marginal benefit when the same information lives in
  `manifest.json` inside the bundle itself.

## Design heuristic

Tier 2 is purely additive to Tier 1. No existing endpoint changes its
response shape; the sole modification to a Tier 1 endpoint is adding one
optional bool field (`async`) to the `ReqReporter` request struct. Every
existing Tier 1 client keeps working unchanged.

The three new endpoints share a common URL pattern (`/scan/task/<verb>`) that
groups them as "single-task operations." This pairs neatly with the existing
plural `/scan/tasks/...` endpoints which are "many-task queries." Verb noun
parts: `artifacts` (read), `cancel` (mutate). Future single-task operations
follow the same template.

## Component 1: `POST /scan/task/artifacts`

Generic, task-scoped artifacts download. Returns the bundle from any terminal
task's slot.

### Request

```jsonc
POST /scan/task/artifacts
{
    "scan_id": "<uuid4>",
    "task_id": "<uuid4>"
}
```

### Behavior (updated in Tier 3)

The endpoint is **lifecycle-first**: task state is read from Redis (fast
path) or reconstructed from SQL log markers (durable fallback). The
filesystem participates in the bundling step only, never in the lifecycle
decision. This mirrors how `/scan/tasks/status` already resolves state
across both stores.

Tool name comes from the SQL `[g3:dispatch]` marker (uniform across
task kinds). The endpoint no longer reads `manifest.json` — reporter
tasks don't write one (see Tier 3 design), and tool-task manifests
aren't needed at this layer either.

1. Decode + validate the request.
2. `GetTaskState(rdb, scan_id, task_id)`:
   - DISPATCHED/RUNNING → 425 + "task is still <STATE>" + Retry-After: 2.
   - DONE/ERROR/CANCELED → terminal; fall through to SQL for tool name.
   - "" or error → fall through to SQL.
3. `ReconstructTaskStateFromLogs(sql, scan_id, task_id)`:
   - No record AND Redis was silent → 404 "task not found".
   - WAITING/RUNNING/UNKNOWN → 425 + "task is not yet complete" + Retry-After: 2.
   - DONE/ERROR/CANCELED → terminal; tool name from same lookup.
4. Stat slot dir at <G3_ARTIFACTS_ROOT>/<scan_id>/<task_id>/:
   - Missing → 404 "task produced no output".
   - Present → BundleTaskSlot stream-to-response.

### Response matrix

| Lifecycle lookup | Slot on disk | Status | Body / headers |
| --- | --- | --- | --- |
| Terminal (Redis or SQL) | Has ≥1 file | 200 | bundle per `BundleTaskSlot` rules |
| Terminal (Redis or SQL) | Empty or absent | 404 | `"task produced no output"` |
| DISPATCHED/RUNNING in Redis | n/a | 425 | `"task is still <STATE>"` + `Retry-After: 2` |
| WAITING/RUNNING/UNKNOWN via SQL only | n/a | 425 | `"task is not yet complete"` + `Retry-After: 2` |
| No record in Redis or SQL | n/a | 404 | `"task not found"` |
| Malformed request | n/a | 400 | `"Bad request."` |

### Reused infrastructure

| Helper | Source | Role |
| --- | --- | --- |
| `BundleTaskSlot(slotDir, tool, taskID, w)` | `g3lib/manifest.go` (Tier 1) | Walks slot, returns filename/content-type, streams bundle into `w` |
| `GetTaskState(rdb, scanID, taskID)` | `g3lib/kvstore.go` (Tier 1) | Single-task Redis state lookup — fast-path lifecycle check |
| `ReconstructTaskStateFromLogs(sql, scanID, taskID)` | `g3lib/sql.go` (Tier 3) | Single-task SQL log marker lookup — durable fallback for lifecycle when Redis is silent |
| `G3_ARTIFACTS_ROOT` env (with `G3_ARTIFACTS_ROOT_DEFAULT` fallback) | `g3lib/plugin.go` (artifacts spec) | Slot-path root |

No new helpers needed beyond what Tier 3 introduces. The endpoint is ~80 lines of handler glue (decision tree for Redis → SQL fallback chain, then bundling).

## Component 2: Async opt-in for `POST /scan/reporter`

### Request

```jsonc
POST /scan/reporter
{
    "scan_id": "<uuid4>",
    "tool":    "<plugin-name>",
    "preset":  "<preset-name>",   // OPTIONAL
    "async":   true                // OPTIONAL — defaults to false (sync, Tier 1 behavior)
}
```

### Schema change

`ReqReporter` in `src/g3lib/api.go` gains one field:

```go
type ReqReporter struct {
    ScanID string `json:"scanid" validate:"required,uuid"`
    Tool   string `json:"tool"   validate:"required"`
    Preset string `json:"preset"`
    Async  bool   `json:"async,omitempty"`
}
```

`omitempty` plus a zero-value default means Tier 1 clients (no `async` field)
get sync behavior unchanged. New clients opt in by sending `"async": true`.

### Behavior

The handler in `g3api.go` branches early on `request.Async`:

**Async path** (when `request.Async == true`):

| Step | Action |
|---|---|
| 1 | Decode + validate body. Same plugin/preset validation as the sync path. |
| 2 | Generate `reporterTaskID` (uuid4); `dispatchTS = time.Now().Unix()` |
| 3 | `SetTaskDispatched(rdb, scanID, reporterTaskID, tool, dispatchTS)`; on err → 500 |
| 4 | Set `X-G3-Task-ID: <reporterTaskID>` response header |
| 5 | `SendReportTask(mq, scanID, reporterTaskID, tool, preset)`; on err → `SetTaskTerminal(ERROR)` + 500 |
| 6 | Return `202 Accepted`, body `{ "task_id": "<reporterTaskID>" }` |

No polling loop; no bundle response; the synchronous wait-and-stream code in
Tier 1's handler is skipped entirely.

**Sync path** (when `request.Async` is absent or false): **unchanged from
Tier 1.** Polling loop, `""` → CANCELED handling, bundle response, all stay
exactly as shipped.

### Client lifecycle (no new endpoints needed)

```
POST /scan/reporter  { ..., async: true }   →  202 + { task_id }
                                                ↓
POST /scan/tasks/status  { scan_id }         →  look up task by id, check state
                                                ↓ (when terminal)
POST /scan/task/artifacts  { scan_id, task_id } → download bundle
```

Reporter tasks already surface in `/scan/tasks/status` because Tier 1's
worker uses the same `SetTaskRunning` / `SetTaskTerminal` plumbing as tool
tasks. Component 1 above handles the download.

### Response shape

`202 Accepted`, body:

```json
{ "task_id": "<reporterTaskID>" }
```

The `X-G3-Task-ID` response header is also set (matches Tier 1's
forward-compat rule). Clients have two equivalent ways to learn the task ID:
parse the JSON body, or read the header.

## Component 3: `POST /scan/task/cancel`

Batch task cancellation. Publishes a single `G3CancelTask` MQTT message
covering one or more task IDs.

### Request

```jsonc
POST /scan/task/cancel
{
    "scan_id":  "<uuid4>",
    "task_ids": ["<uuid4>", "<uuid4>", ...]
}
```

### Schema

A new request struct `ReqTaskCancel` in `src/g3lib/api.go`:

```go
type ReqTaskCancel struct {
    ScanID  string   `json:"scanid"   validate:"required,uuid"`
    TaskIDs []string `json:"taskids"  validate:"required,min=1,dive,uuid"`
}
```

The `min=1` validator catches the no-op empty-list case at parse time.
`dive,uuid` validates each element.

### Behavior

| Step | Action |
|---|---|
| 1 | Decode + validate body. |
| 2 | Call `g3lib.SendTaskCancel(mq, request.ScanID, request.TaskIDs)`. |
| 3 | On publish error → 500 `"failed to publish cancel"`. On success → 200 OK with `null` body via the existing `SendApiResponse(w, nil)` pattern. |

That's it. Fire-and-forget by design:
- The worker handler for each affected task receives the cancel via its
  existing MQTT subscription, fires its `context.CancelFunc` (registered with
  `cancelTracker.AddTaskIfNew`), and the task transitions to CANCELED through
  the regular `markTerminal` / `markReportTerminal` path.
- Unknown task IDs are silent no-ops on the worker side — already part of the
  existing cancellation semantics, no extra validation here.
- The API doesn't wait for confirmation. Clients that need to observe the
  cancel's effect poll `/scan/tasks/status` (per-scan task list with state)
  or subscribe to the existing WS task channel.

### Response matrix

| Outcome | Status | Body |
| --- | --- | --- |
| MQTT publish succeeds | 200 | `null` |
| Malformed request / missing field / empty list / non-uuid4 | 400 | `"Bad request."` |
| MQTT publish fails | 500 | `"failed to publish cancel"` |

### Reused infrastructure

| Helper | Source | Role |
| --- | --- | --- |
| `SendTaskCancel(mq, scanid, taskids)` | `g3lib/task.go` (existing) | Publishes G3CancelTask to MQTT cancel topic |

No new MQTT message type or helper. The endpoint is ~30 lines of handler glue.

## Cross-cutting

### Backwards compatibility

- Tier 1 clients posting to `/scan/reporter` without `async` keep working
  exactly as before.
- Every Tier 1 endpoint response shape and status code is unchanged.
- No new MQTT topics, no new message types, no SQL schema changes, no Redis
  key changes.

### Authentication

All three endpoints reuse the existing `requireToken(apiToken, ...)` wrapper
that every other endpoint already uses. No new auth surface.

### Concurrency

- `POST /scan/task/artifacts` is read-only against a per-task slot. Multiple
  concurrent downloads of the same slot are safe (each gets its own
  `bytes.Buffer` and `BundleTaskSlot` walk; the slot files are read-only at
  that point).
- `POST /scan/reporter` async path is structurally identical to the sync
  path's first few steps (validate, dispatch, publish) — concurrent
  invocations create independent reporter tasks with independent IDs. No
  serialization needed.
- `POST /scan/task/cancel` publishes a single MQTT message. Concurrent
  cancels for overlapping task ID sets are idempotent — the worker's
  `context.CancelFunc` is safe to call multiple times.

### Edge cases worth calling out

- **Artifacts download for a terminated scan.** This is the common case
  for any non-trivial deployment: a user runs a scan today, comes back
  next week to grab the report. By then the scan has terminated and
  Redis has reaped all per-task hashes for it. Component 1's disk-first
  design handles this directly: `manifest.json` is on disk (slots live
  until scan deletion), the endpoint serves the bundle without ever
  consulting Redis. This is exactly why the artifacts endpoint cannot
  rely on `GetTaskState` as a precondition — the very common case is
  "Redis says nothing, disk has everything."

- **Scan deleted between status poll and download.** A client polls
  `/scan/tasks/status`, sees a task in DONE, then calls
  `/scan/task/artifacts`. Between those two calls the scan gets deleted
  — both the Redis hash AND the slot dir are wiped. The endpoint stats
  the slot dir, finds it missing, returns 404 `"task not found"`. The
  client correctly observes that the scan no longer exists.

- **Cancel after terminal.** A client cancels a task that already finished
  (DONE/ERROR/CANCELED). The cancel publishes successfully (200), the
  worker's cancel handler sees a task ID it no longer has in its
  `cancelTracker`, and does nothing. Safe no-op.

- **Async kickoff race with immediate cancel.** A client posts
  `{async: true}` and almost immediately posts `/scan/task/cancel` with
  the returned task ID before the worker has picked the task up. The
  cancel message hits the MQTT broker first; when a worker eventually
  subscribes and pulls the task, the existing `cancelTracker.AddTaskIfNew`
  case-1 branch (rejected because it was pre-cancelled) handles it — the
  task transitions to CANCELED without ever running the container.
  Already covered by Tier 1's worker handler; reporter tasks aren't
  special here.

## Configuration and deployment

No new environment variables. No new compose services. No new mounts. The
Tier 1 deployment is sufficient — these are purely g3api-side additions.

## Rollout

Single tier. All three endpoints ship together since they share the same
g3api.go handler-block pattern and depend only on Tier 1 + existing
infrastructure. No phased rollout needed.

The implementation plan is its own document; this spec is approved for
handoff to writing-plans.

## Future work (out of scope for Tier 2)

- **Pre-download slot enumeration.** A `POST /scan/task/files` returning the
  `EnumerateSlot` output (filename, size, modified) would let clients show a
  preview before triggering a download. Cheap to add if a real use case
  shows up.
- **WebSocket subscription helper for a specific task.** Today's WS task
  channel pushes events for every task in a scan; a single-task filter helper
  on the client side suffices, but a server-side filter would be friendlier.
  Not urgent — the current channel is already low-volume.
- **Streaming bundle (no `bytes.Buffer`).** Refactor `BundleTaskSlot` into
  `ClassifyTaskSlot` + `StreamTaskSlot`, so headers can be set from the
  classify pass and the stream pass writes straight to the HTTP response.
  Avoids the in-memory buffering of large reports. Worth doing if real-world
  reports start hitting tens of MB.
- **Per-file artifact download with path-injection guards.** Out of scope per
  prior brainstorming; opens a class of security concerns that the
  bundle-only design avoids.
