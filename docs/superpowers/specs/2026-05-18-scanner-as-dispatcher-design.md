# Scanner as Sole Task Dispatcher — Design

Brainstormed 2026-05-18.

## Context

The previous reporter-plugins work (Tier 1 and Tier 2, see
[2026-05-16-reporter-plugins-design.md](2026-05-16-reporter-plugins-design.md)
and [2026-05-18-reporter-tier2-design.md](2026-05-18-reporter-tier2-design.md))
introduced an architectural shortcut: `g3api` publishes directly to MQTT
worker topics (`report/<plugin>`) when dispatching reporter tasks. This
bypassed the scanner — the historical "orchestrator" role — and worked
fine for the narrow Tier 1 scope of "on-demand reporter request, scan
already complete, no pipeline to orchestrate."

The shortcut surfaced two problems when planning the reporter local-CLI
work (originally Tier 3 of the reporter spec):

1. **Server-side scan scripts with a `report` directive cracked it open.**
   If a script wants to declare a reporter, the scanner — which orchestrates
   the rest of the pipeline — would need reporter-dispatch capability too.
   Otherwise the same script would behave differently in local vs server
   mode.

2. **Agentic integration needs dynamic task dispatch.** An agent deciding
   "now I want to run nmap on this newly discovered IP" needs to ask the
   system to dispatch a tool task on demand. Today's scanner only
   dispatches what the scan script declared at scan-start time; there's no
   "dispatch this task on demand" entry point. Building one is foundational
   for the agentic feature work on the roadmap.

Rather than ship the Tier 3 reporter work on the existing shortcut and
then refactor everything once the agentic feature crystallized, the right
sequencing call is to **first** make the scanner the sole dispatcher of
worker tasks, **then** resume the reporter local-CLI work on a cleaner
foundation.

This spec describes that first piece.

## Goal

Replace the Tier 1 reporter-direct-dispatch path with a generic
on-demand task dispatch mechanism in which **`g3scanner` is the sole
entity that publishes to worker MQTT topics**. Two kinds of tasks are
dispatchable on demand: **tool tasks** (matching the agentic use case)
and **reporter tasks** (replacing Tier 1's `/scan/reporter`).

The HTTP API exposes a single canonical endpoint
`POST /scan/task/dispatch` with a flat discriminated-union request body.
The scanner subscribes to a new `dispatch` MQTT topic and processes
dispatch requests at the scanner-process level (outside any
ScanRunner goroutine). The existing scan-script orchestrator
(`ScanRunner`) refactors to use the same internal dispatch helper, so
script-driven and API-driven dispatches share one canonical code path.

## Non-goals

- **Importer and merger on-demand dispatch.** Both stay out of scope:
  - **Mergers** are scan-wide per-plugin synchronization barriers — they
    must run exactly once per plugin per scan to preserve dedup
    correctness. Running on workers would require the scanner to
    serialize them per plugin anyway, defeating the parallelism benefit.
    They continue to run in-process inside `ScanRunner`. (Future-work
    item below outlines worker-dispatch with the barrier preserved, for
    docker-socket-trust-surface reduction.)
  - **Importers** currently run in-process in g3api. Migrating them to
    worker dispatch is genuinely additive once this spec ships — same
    pattern, new topic family. Out of scope here because (a) it's not
    blocking for agentic readiness, (b) it brings its own design surface
    (file path on shared volume, terminal-state tracking for a task kind
    that doesn't produce artifacts), and (c) deferring keeps this spec
    tight. Documented in future work.

- **Synchronous mode on `/scan/task/dispatch`.** The endpoint is
  async-only. Reasons: response shape would otherwise vary by `kind`
  (tool returns G3Data; report returns a bundle stream), which is the
  sort of inconsistency that bites later. Async-only is uniform across
  kinds and matches the canonical agentic flow. Tier 1's one-shot
  reporter UX is lost at the API layer; a future convenience CLI command
  can wrap dispatch → poll → download for clients that want one-shot.

- **Task-id collision detection.** UUIDv4 collisions are treated as
  effectively impossible. No defensive check. If a collision somehow
  occurred, the new dispatch would overwrite the prior Redis hash and
  produce loud weirdness — easy to spot in practice, not worth
  defensive code.

- **Re-run semantics.** The "I want to redo this task with the same ID"
  pattern is deferred. When the need arises, the recommended approach
  is *not* to reuse the same task_id (state cleanup is messy) but to
  generate a new task_id and decorate the fingerprint with a retry
  marker so the new run coexists with the original. See future work.

- **Multi-scanner HA.** Current design uses a non-shared subscription on
  the `dispatch` topic — single scanner instance per deployment.
  Switching to `$share/g3scanner/dispatch` for true horizontal scaling
  is a one-string change documented in future work.

- **Backward compatibility for `/scan/reporter`.** No consumers exist
  (verified via repo-wide grep — only the handler itself, the request
  struct, and design docs reference it). The endpoint is removed
  outright rather than kept as a wrapper.

## Design heuristic

The architectural rule going forward: **g3scanner is the SOLE entity
that publishes to MQTT worker topics** (`tool/<name>`, `report/<name>`).

Two doors open from there:

1. Both script-driven dispatch (inside `ScanRunner`'s pipeline loop) and
   API-driven dispatch (from `g3api` via the new `dispatch` topic) flow
   through a shared internal helper. One canonical "publish a task to its
   worker" code path. Future task-dispatch features compose naturally
   without architectural rewrites.
2. The dispatch lifecycle record in SQL (`[g3:dispatch]`, `[g3:start]`,
   `[g3:done]` markers via `ReconstructTaskStatesFromLogs`) is uniform
   for all dispatches regardless of source. The existing
   `/scan/tasks/status` and Tier 2 `/scan/task/artifacts` endpoints
   continue to use this durable record for state detection.

`g3api` keeps the HTTP-boundary role (decode, validate, generate
task_id, publish dispatch message). It never publishes to worker topics
directly. It never sets initial Redis dispatch state. It is a thin proxy
from HTTP to MQTT.

## Architecture overview

```
HTTP client                                                        Worker
    │                                                                ▲
    │ POST /scan/task/dispatch                                       │
    ▼                                                                │
  g3api ──MQTT publish G3Dispatch──▶ g3scanner ──MQTT publish G3Task──┘
    │       topic: "dispatch"           │       or G3ReportTask
    │                                   │       to tool/<name> or report/<name>
    │ 202 + {task_id}                   │
    ▼                                   ▼
HTTP client                         [g3:dispatch] SQL marker
                                    SetTaskDispatched Redis
```

`g3api` generates the task_id (UUIDv4), publishes the dispatch message
including the task_id, and returns 202 immediately. No MQTT round-trip
for g3api to learn the task_id — it owns the value as a trivial random
number. Validation against the plugin metadata happens in g3api before
publishing; the scanner re-validates kind-specific fields on receipt.

The scanner gains a new top-level MQTT subscription (`dispatch`),
parallel to its existing `scan` subscription. The new handler runs at
the scanner-process level — outside any per-scan ScanRunner goroutine
— so it can serve dispatches for any scan, including ones that have
already completed and have no active ScanRunner.

Inside the existing `ScanRunner` (the scan-script orchestrator), the
dispatch logic factors into a shared helper `dispatchTask` that both the
script-execution loop and the new dispatch handler call. So a dispatch
from a scan script and a dispatch from an API request go through the
exact same code path.

## Component 1: HTTP API contract

**Endpoint:** `POST /scan/task/dispatch`. Replaces `/scan/reporter`
entirely — no backward-compat wrapper.

### Request body (flat discriminated union)

```jsonc
POST /scan/task/dispatch
{
    "scan_id": "<uuid>",         // REQUIRED
    "kind":    "tool" | "report", // REQUIRED — discriminator
    "tool":    "<plugin-name>",  // REQUIRED — must exist in plugin metadata

    // kind=tool:
    "data_id": "<mongoid>",      // REQUIRED — the G3Data object the tool runs against
    "index":   0,                // REQUIRED — subcommand index (matches G3Task.Index semantics)

    // kind=report:
    "preset":  "executive"       // OPTIONAL — must be a declared preset name if plugin has commands; rejected if plugin has reporter:{} with no commands
}
```

The HTTP body never accepts `task_id` — g3api generates one fresh per
request. Clients receive the generated task_id via the response (header
`X-G3-Task-ID` and body `{ task_id }`).

### Validation (g3api side, before MQTT publish)

| Failure | Status | Body |
| --- | --- | --- |
| Malformed JSON / missing required field | 400 | `"Bad request."` |
| `scan_id` not a valid uuid | 400 | `"Bad request."` |
| `kind` not one of `tool` / `report` | 400 | `"unknown kind: <X>"` |
| `tool` not in plugin metadata | 400 | `"unknown tool: <name>"` |
| kind=tool but plugin has no `commands` phase | 400 | `"tool <name> does not implement the tool phase"` |
| kind=tool but `index` >= `len(plugin.Commands)` | 400 | `"index out of range for tool <name>"` |
| kind=tool but `data_id` not a valid mongo id | 400 | `"Bad request."` |
| kind=report but plugin has no `reporter` phase | 400 | `"tool <name> does not implement a reporter"` |
| kind=report but `preset` set and plugin has no commands | 400 | `"tool <name> declares no reporter presets"` |
| kind=report but `preset` set and not a declared preset name | 400 | `"unknown preset for tool <name>: <X>"` |

### Successful dispatch response

| Status | Headers | Body |
| --- | --- | --- |
| 202 Accepted | `X-G3-Task-ID: <task_id>` | `{ "task_id": "<task_id>" }` (wrapped in the standard `APIResponse` envelope) |

### Internal g3api flow

```
1. Decode + validate request body
2. Look up plugin in metadata; validate kind/fields against plugin shape
3. Generate task_id (uuid.NewString())
4. Publish G3Dispatch to MQTT topic "dispatch" with the task_id
5. Set X-G3-Task-ID header; return 202 + { task_id }
```

g3api does not touch Redis or SQL on the dispatch path. All state is
written by the scanner. If MQTT publish in step 4 fails, g3api returns
a 500 with `"failed to publish dispatch"`. If MQTT publish succeeds, the
client receives 202 — even if the scanner is offline (the message
queues until a scanner comes online).

### Client lifecycle (no new endpoints needed)

```
POST /scan/task/dispatch  { scan_id, kind, tool, ... }  →  202 + { task_id }
                                                            ↓
POST /scan/tasks/status  { scan_id }                     →  poll for state
                                                            ↓ (when terminal)
POST /scan/task/artifacts  { scan_id, task_id }          →  download bundle (kind=report)
   (or query MongoDB for G3Data via existing endpoints if kind=tool)
```

The existing `/scan/tasks/status` (per-scan task list with state) and
the Tier 2 `/scan/task/artifacts` endpoints handle the rest of the
client's lifecycle without change.

## Component 2: MQTT message + g3lib helpers

### New MQTT topic and message type

```go
const G3DISPATCHTOPIC = "dispatch"

const MSG_DISPATCH G3MESSAGETYPE = "dispatch"
```

`MSG_DISPATCH` joins `VALID_MSG`. Topic is `dispatch` — top-level,
parallel to existing `scan` / `stop` / `status` / `cancel`.

### G3Dispatch struct

```go
type G3Dispatch struct {       // MessageType: MSG_DISPATCH
    G3TaskMessage              // embeds ScanID + TaskID; TaskID is required,uuid4
    Kind   string `json:"kind"   validate:"required,oneof=tool report"`
    Tool   string `json:"tool"   validate:"required"`
    // kind=tool fields:
    DataID string `json:"dataid,omitempty" validate:"omitempty,mongodb"`
    Index  int    `json:"index,omitempty"  validate:"gte=0"`
    // kind=report fields:
    Preset string `json:"preset,omitempty"`
}

type DispatchHandler func(MessageQueueClient, G3Dispatch)
```

The flat-union shape mirrors the HTTP body. The struct validator
enforces the truly invariant fields (TaskID format, Kind oneof, Tool
non-empty); kind-specific required fields (DataID + Index for tool;
preset existence for report) are validated by the scanner-side handler
because Go's `validate` tag doesn't natively express
"required-when-kind-is-X" semantics.

### Helpers in src/g3lib/task.go

```go
// SendDispatch publishes a G3Dispatch to the scanner's dispatch topic.
// The caller (g3api) is responsible for generating the TaskID, validating
// the request shape against plugin metadata, and populating kind-specific
// fields. The scanner re-validates kind-specific fields on receipt and
// publishes to the appropriate worker topic.
func SendDispatch(client MessageQueueClient, msg G3Dispatch) error {
    msg.MessageType = MSG_DISPATCH
    msg.SenderID = GetClientID(client)
    if err := validator.New().Struct(msg); err != nil {
        return err
    }
    return SendMQPayload(client, G3DISPATCHTOPIC, msg)
}

// SubscribeAsDispatcher registers the scanner as a dispatch consumer.
// Unlike SubscribeAsScanner (per-scan goroutine spawn), this handler runs
// at the scanner-process level and handles dispatches for any scan.
func SubscribeAsDispatcher(client MessageQueueClient, callback DispatchHandler) string {
    log.Debug("Subscribing to: " + G3DISPATCHTOPIC)
    client.Subscribe(G3DISPATCHTOPIC, MQTT_QOS, func(client mqtt.Client, msg mqtt.Message) {
        var dispatch G3Dispatch
        if err := json.Unmarshal(msg.Payload(), &dispatch); err != nil {
            log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
            return
        }
        if err := validator.New().Struct(dispatch); err != nil || dispatch.MessageType != MSG_DISPATCH {
            log.Error("Malformed dispatch object received")
            return
        }
        callback(client, dispatch)
    })
    return G3DISPATCHTOPIC
}
```

`SubscribeAsDispatcher` uses a regular (non-shared) subscription. If
multiple scanner instances are deployed for HA, switch to
`$share/g3scanner/dispatch`.

### Existing helpers repurposed (not changed)

| Helper | Tier 1 caller | Going forward |
| --- | --- | --- |
| `SendTask(client, scanid, taskid, tool, index, data)` | g3scanner (script-driven) | g3scanner (script-driven + dispatch-driven) — unchanged |
| `SendReportTask(client, scanid, taskid, tool, preset)` | **g3api directly (Tier 1)** | **g3scanner (called from the new dispatch handler)** — the direct g3api call is removed |
| `SubscribeAsWorker` | g3worker | g3worker — unchanged |
| `SubscribeAsReporter` | g3worker | g3worker — unchanged |

`SendReportTask` stays in g3lib; the scanner is the only caller after
this spec ships.

## Component 3: Scanner-side handler + ScanRunner refactor

### Shared canonical helper

Private to the `g3scanner` package (only the scanner should dispatch
tasks — exporting this would defeat the architectural rule):

```go
// dispatchTask is the canonical "publish a task to its worker" function.
// Called by both ScanRunner (script-driven dispatches inside the pipeline
// execution loop) and the on-demand dispatch handler (API-driven dispatches).
// Writes the [g3:dispatch] log marker, sets Redis DISPATCHED state, then
// publishes to the appropriate worker topic.
//
// Callers are responsible for upstream validation (plugin exists, kind/fields
// are valid). This helper assumes well-formed inputs.
func dispatchTask(
    mq  g3lib.MessageQueueClient,
    rdb g3lib.KeyValueStoreClient,
    sql g3lib.SQLDBClient,
    scanID, taskID, kind, tool string,
    dataID string,  // tool kind only
    index  int,     // tool kind only
    preset string,  // report kind only
) error {
    dispatchTS := time.Now().Unix()
    if err := g3lib.SetTaskDispatched(rdb, scanID, taskID, tool, dispatchTS); err != nil {
        log.Error("Redis SetTaskDispatched failed: " + err.Error())
    }
    if err := g3lib.SaveLogLine(sql, scanID, taskID, "[g3:dispatch] task="+taskID+" tool="+tool); err != nil {
        log.Error("SaveLogLine (dispatch) failed: " + err.Error())
    }
    switch kind {
    case "tool":
        return g3lib.SendTask(mq, scanID, taskID, tool, index, dataID)
    case "report":
        return g3lib.SendReportTask(mq, scanID, taskID, tool, preset)
    default:
        return fmt.Errorf("unknown dispatch kind: %s", kind)
    }
}
```

### ScanRunner pipeline loop refactor

The current code at `g3scanner.go:627-641` and `g3scanner.go:909+`
inlines:

```go
dispatchTS := time.Now().Unix()
if err := g3lib.SetTaskDispatched(rdb_client, msg.ScanID, taskid, plugin.Name, dispatchTS); err != nil { ... }
if err := g3lib.SaveLogLine(scan_sql_db, msg.ScanID, taskid, "[g3:dispatch] task="+taskid+" tool="+plugin.Name); err != nil { ... }
// ... (SendTask call follows)
```

Both call sites collapse to a single `dispatchTask(...)` call. The
surrounding pipeline loop logic (data lookup, fingerprint dedup, retry,
etc.) is unchanged.

### dispatchHandler at scanner-process level

The new dispatch handler runs in the scanner main flow, NOT in any
ScanRunner goroutine — it serves any scan, regardless of whether the
scan is actively running its script.

```go
// dispatchHandler is registered via SubscribeAsDispatcher.
//
// Validation: the validator on G3Dispatch already enforced common required
// fields (TaskID format, Kind oneof, Tool non-empty, DataID format if set).
// Kind-specific required fields (DataID + Index in range for tool; preset
// existence for report) are validated here against plugin metadata.
func dispatchHandler(
    mq  g3lib.MessageQueueClient,
    rdb g3lib.KeyValueStoreClient,
    sql g3lib.SQLDBClient,
    plugins g3lib.G3PluginMetadata,
    msg g3lib.G3Dispatch,
) {
    // Always create Redis hash and log marker first via SetTaskDispatched,
    // so SetTaskTerminal on validation failure has a hash to update (it's
    // a no-op if the hash is absent — see kvstore.go).
    dispatchTS := time.Now().Unix()
    if err := g3lib.SetTaskDispatched(rdb, msg.ScanID, msg.TaskID, msg.Tool, dispatchTS); err != nil {
        log.Error("Redis SetTaskDispatched failed: " + err.Error())
    }
    if err := g3lib.SaveLogLine(sql, msg.ScanID, msg.TaskID, "[g3:dispatch] task="+msg.TaskID+" tool="+msg.Tool); err != nil {
        log.Error("SaveLogLine (dispatch) failed: " + err.Error())
    }

    // markErr is the consistent failure path: mark terminal ERROR with a reason.
    markErr := func(reason string) {
        if err := g3lib.SetTaskTerminal(rdb, msg.ScanID, msg.TaskID, "ERROR", time.Now().Unix(), reason); err != nil {
            log.Error("Redis SetTaskTerminal failed: " + err.Error())
        }
        if err := g3lib.SaveLogLine(sql, msg.ScanID, msg.TaskID, "[g3:done] task="+msg.TaskID+" state=ERROR"); err != nil {
            log.Error("SaveLogLine (done/error) failed: " + err.Error())
        }
    }

    plugin, ok := plugins[msg.Tool]
    if !ok {
        markErr("unknown tool: " + msg.Tool)
        return
    }

    switch msg.Kind {
    case "tool":
        if len(plugin.Commands) == 0 {
            markErr("tool " + msg.Tool + " does not implement the tool phase")
            return
        }
        if msg.Index >= len(plugin.Commands) {
            markErr(fmt.Sprintf("index %d out of range for tool %s", msg.Index, msg.Tool))
            return
        }
        if msg.DataID == "" {
            markErr("kind=tool requires dataid")
            return
        }
        if err := g3lib.SendTask(mq, msg.ScanID, msg.TaskID, msg.Tool, msg.Index, msg.DataID); err != nil {
            markErr("MQTT publish failed: " + err.Error())
        }

    case "report":
        if plugin.Reporter == nil {
            markErr("tool " + msg.Tool + " does not implement a reporter")
            return
        }
        if msg.Preset != "" {
            if len(plugin.Reporter.Commands) == 0 {
                markErr("tool " + msg.Tool + " declares no reporter presets")
                return
            }
            found := false
            for _, c := range plugin.Reporter.Commands {
                if c.Name == msg.Preset {
                    found = true
                    break
                }
            }
            if !found {
                markErr("unknown preset for tool " + msg.Tool + ": " + msg.Preset)
                return
            }
        }
        if err := g3lib.SendReportTask(mq, msg.ScanID, msg.TaskID, msg.Tool, msg.Preset); err != nil {
            markErr("MQTT publish failed: " + err.Error())
        }

    default:
        markErr("unknown kind: " + msg.Kind)
    }
}
```

The handler does NOT call `dispatchTask` directly because its validation
needs to come AFTER the bookkeeping writes (so `markErr → SetTaskTerminal`
has a hash to update). Both code paths share the same primitives
(`SendTask`/`SendReportTask`) but with the right shape for their caller:

- **ScanRunner (script-driven)**: validates upstream during script parsing
  → calls `dispatchTask` → done.
- **dispatchHandler (API-driven)**: writes initial state → validates →
  calls `SendTask`/`SendReportTask` directly → `markErr` on any failure.

### Scanner main() integration

```go
// New process-level connections alongside the existing MQTT connection.
rdb_client, err := g3lib.ConnectToRedis()
// ...
sql_db, err := g3lib.ConnectToSQL()
// ...

// Subscribe to dispatch messages. The handler runs at scanner-process level,
// independent of any ScanRunner goroutine.
dispatchTopic := g3lib.SubscribeAsDispatcher(mq_client, func(_ g3lib.MessageQueueClient, msg g3lib.G3Dispatch) {
    dispatchHandler(mq_client, rdb_client, sql_db, plugins, msg)
})
```

The existing `SubscribeAsScanner` call (for `MSG_SCAN` that spawns
`ScanRunner` goroutines) stays. The new `SubscribeAsDispatcher` is
parallel — both run at the scanner-process level. Process-level Redis
and SQL connections are added so the dispatch handler can do its
bookkeeping without spinning up a per-message connection.

The dispatch handler runs synchronously inside the MQTT message callback
because the work is light (one Redis write, one SQL write, one MQTT
publish). If profile evidence ever shows backpressure under high
dispatch load, swap to `go dispatchHandler(...)` — one-line change.

## What gets deleted

| File | Code removed |
| --- | --- |
| `src/g3api/g3api.go` | The entire `/scan/reporter` handler (~120 lines, including the synchronous polling loop, the `bytes.Buffer` bundling path, and the `BundleTaskSlot` call). The endpoint is replaced by `/scan/task/dispatch`. |
| `src/g3lib/api.go` | The `ReqReporter` struct and its `Decode` method. Replaced by `ReqTaskDispatch`. |

The Tier 1 sync-with-bundle-stream UX is **lost at the API layer**.
Clients that want one-shot behavior now do dispatch → poll → download.
A future convenience CLI command can restore the one-shot UX at the
client layer if desired.

The Tier 1 in-process `MarkdownReporter` (`src/g3lib/report.go`) and the
legacy `POST /scan/report` endpoint (the no-tool built-in markdown
reporter) are **untouched**. They remain available as the no-plugin
fallback path. This spec only obsoletes the *plugin* reporter dispatch
endpoint, not the built-in reporter.

The Tier 2 endpoints `/scan/task/artifacts` and `/scan/task/cancel` are
**unaffected** — they're orthogonal to dispatch and continue to work
with the new task-creation flow.

## Edge cases

| Case | Behavior |
| --- | --- |
| No scanner online when g3api publishes | MQTT broker queues the message (QoS=2 + `SetCleanSession(false)`) for delivery once the scanner reconnects, **provided the scanner has connected at least once before** so the broker has a persistent session for it. First-deploy race (g3api accepts traffic before scanner has ever connected) drops messages silently — same pre-existing property as all other MQTT flows in g3 (MSG_SCAN, MSG_TASK, etc.). Operational mitigation: bring subscribers online before publishers on first deploy, or restart g3api after scanner is up. Not specific to this feature. |
| Scanner offline → online | Drains MQTT queue, processes dispatches in arrival order via `dispatchHandler`. |
| Multiple scanner instances (HA) | Non-shared subscription on `dispatch` means MQTT broker's standard delivery semantics apply. For true horizontal scaling, switch to `$share/g3scanner/dispatch` shared subscription. Out of scope here. |
| Scan deleted between dispatch and worker pickup | Worker fails when operating on a non-existent scan (Mongo DB gone); sets task ERROR via the existing terminal-state path. Visible via `/scan/tasks/status`. |
| Plugin metadata differs between g3api and scanner | Shouldn't happen (both load from `<G3HOME>/config/plugins.json`). If mismatch: g3api validates against its view, scanner re-validates against its view, mismatch → scanner's `markErr` writes ERROR. Loud failure, not silent. |
| Worker for `tool/<name>` has no subscribers | MQTT broker queues the message. Task stuck `DISPATCHED` in `/scan/tasks/status` (never transitions to RUNNING). Operator concern, not API concern. |
| On-demand dispatch lands while ScanRunner is finishing its script for the same scan | ScanRunner's `defer DeleteTaskStates(scanID)` wipes the new task's Redis hash as part of normal scan-completion cleanup. The task is still in MQTT-flight to its worker and runs to completion normally, but during its RUNNING phase it's invisible in `/scan/tasks/status` (Redis empty, no `[g3:done]` SQL marker yet). Once the worker writes `[g3:done]`, `ReconstructTaskStatesFromLogs` picks it up from SQL — terminal state is recovered. The invisibility window is bounded by the task's RUNNING duration (seconds to minutes for typical tools). For agentic clients polling task state, this manifests as "task disappears briefly, then reappears as DONE/ERROR via SQL fallback." Mitigation if it becomes a real issue: tag dispatch-origin on the task and have `DeleteTaskStates` skip API-dispatched tasks. Not in scope for this spec. |
| Dispatch validation fails kind-specific checks at scanner | `markErr` writes ERROR + `[g3:done] state=ERROR` log marker. Client sees ERROR via `/scan/tasks/status`. No worker receives the task. |
| Task_id collision (UUIDv4) | Treated as never happening. If somehow it did happen: loud weirdness in artifacts; would be noticed quickly. No defensive check. |
| g3api Redis or SQL outage at dispatch time | g3api doesn't touch Redis or SQL on the dispatch path — only publishes MQTT. The case is moot for g3api. |
| Old g3api with new scanner / vice versa | Mixed-version deployments need both binaries upgraded together: `/scan/reporter` disappears in the new g3api AND the scanner's dispatch handler is new. Document as "upgrade g3api and g3scanner together." No client-facing migration. |

## Configuration and deployment

No new environment variables. No new MongoDB / Redis / MariaDB schema
changes. No Docker image changes. No plugin metadata changes. The
architectural change is purely intra-process within the g3 binaries.

`g3scanner` needs Redis and SQL connection access at startup (it
already has MQTT). If running scanner-only deployments (a future
multi-binary split) the scanner container needs the same connection
env vars as g3api currently does.

## Rollout

Single ship. No phased rollout. All changes land together:

1. New g3lib types and helpers (`G3Dispatch`, `MSG_DISPATCH`,
   `G3DISPATCHTOPIC`, `SendDispatch`, `SubscribeAsDispatcher`).
2. New `ReqTaskDispatch` request struct in `g3lib/api.go`. Remove
   `ReqReporter`.
3. New `dispatchHandler` and `dispatchTask` in `g3scanner`, plus the
   `SubscribeAsDispatcher` call and process-level Redis/SQL connections
   in scanner main.
4. `ScanRunner` pipeline loop refactored to call `dispatchTask`
   (two call sites: g3scanner.go:627 and :909).
5. New `POST /scan/task/dispatch` handler in g3api. Old
   `/scan/reporter` handler removed.
6. Cross-binary build verification.

## Future work (out of scope; documented for the next person)

- **Re-run semantics via fresh task_id + retry-marker on fingerprint.**
  When agentic flows need idempotent retries, generate a new task_id for
  each attempt and decorate the fingerprint with a retry marker (e.g.
  `<original-fp>::retry=N`). Preserves all prior data; coexists with the
  original run. Incremental rollout: failed tasks first, then plan for
  successful tasks (especially ones with children, which raise their
  own design questions about descendant invalidation).

- **Importer migration to worker dispatch.** Currently g3api runs
  importers in-process. Migrating them to the dispatch mechanism (new
  `import/<name>` topic, new `G3ImportTask` message, worker handler that
  reads input file from shared volume) is purely additive once this
  spec ships. Gains observability (task IDs in `/scan/tasks/status`)
  and removes g3api's docker-socket dependency for importers.

- **Migrate mergers to worker dispatch via `merge/<plugin>` topic.**
  Mergers stay scan-wide per-plugin (one merger task per plugin per
  scan, serialized by the scanner to preserve the dedup synchronization
  barrier), but execute on workers instead of in-process. New
  `G3MergeTask` message and `merge/<plugin>` topic family. Choose
  between dedicated merger-worker role vs per-plugin merger on existing
  tool-workers. Once this and the importer migration both land, only
  `g3worker` and the local CLI binary `g3` need docker socket access —
  `g3scanner` and `g3api` become pure orchestration/API processes with
  no container-launching capability, tightening their trust surfaces.

- **HA scanner deployment.** Switch `SubscribeAsDispatcher` to use
  `$share/g3scanner/dispatch` shared subscription. Add coordination for
  split-brain scenarios (probably none needed since dispatches are
  independent).

- **`g3 scan` script `report` directive (the original Tier 3 reporter
  work).** Pick up the deferred local-CLI reporter integration on top
  of this clean dispatch foundation. The script directive becomes a way
  for the local `g3` binary to emit a dispatch in its own pipeline —
  same MQTT message, same handler.

- **Convenience CLI for one-shot reporter UX.** A
  `g3cli report <tool> <scan_id>` command that wraps dispatch → poll
  → download. Restores the Tier 1 one-shot UX at the client layer if
  missed.
