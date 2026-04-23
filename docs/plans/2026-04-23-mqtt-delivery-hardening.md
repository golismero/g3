# MQTT Delivery Hardening — Tiered Plan

Tracking GitHub issue [golismero/g3#5](https://github.com/golismero/g3/issues/5).

## Context

### What the issue says

> currently the code doesn't check at all for errors when sending MQTT messages. This can cause messages to be dropped silently under heavy load.

### What the code actually shows

The MQTT wrapper `SendMQPayload` at `src/g3lib/task.go:358-373` *does* return errors correctly — it waits on the paho token and propagates `token.Error()`. The gap is at **callers**, in two distinct shapes:

1. **Statement-level publishes that drop the return entirely.** These are the calls currently silenced by errcheck exclusions in `.golangci.yml` (lines 32-42). A grep for every call to the six suppressed functions finds **32 unchecked sites**:
   - `src/g3scanner/g3scanner.go` — **30 unchecked calls** (every use of `SendTaskCancel`, `SendScanFailed`, `SendScanProgress`, `SendScanStopped`, `SendScanCompleted` is statement-level with no error assignment)
   - `src/g3worker/g3worker.go:473` — `SendEmptyResponse` on SIGTERM drop path
   - `src/g3worker/g3worker.go:535` — `SendEmptyResponse` on "command index out of range" path
2. **Callers that check the error but only `log.Error(...)` and move on.** Most other worker publishes fit this pattern. The debug log captures the failure; the API, the DB, and the user don't. Scans can appear `RUNNING` forever if `SendScanCompleted` drops.

Configuration worth flagging:
- `MQTT_QOS = 2` — good, exactly-once semantics.
- `MQTT_PERSIST = false` — this is paho's *retained* flag, not broker persistence. Retained is wrong for shared-subscription work queues; leave as-is.
- `MQTT_QUIESCE = 3` — tight for QoS 2 (four-packet handshake) under load; produces false-positive timeouts.
- `CleanSession = false` — correct for work-queue semantics, broker retains queued messages for known subscribers.
- **No LWT** configured on workers or scanner.

### Goal

Close silent-drop holes and make scans self-heal when MQTT drops a message, without over-engineering (no broker swap — the problems are application-layer). Do it in tiers so each piece can be reviewed, merged, and observed before the next starts.

### Why tiered

Issue #5 lists five options, but they aren't alternatives — they're layers. Ordering them smallest-first lets Tier 1 ship today while we watch whether Tier 2+ is still needed. All tiers are outlined here; each tier's details will be fleshed out at its kickoff.

---

## Tier 1 — Close silent drops, unsuppress the lint, give publishes a fair timeout

**Status:** details filled in, ready to execute after approval.

### Changes

#### 1.1 Error-check every call to the six currently-suppressed functions

Target: every statement-level call becomes `err := <Send>(...)` followed by `if err != nil { log.Error("<op> failed: " + err.Error()) }`. No retry, no state change — that's Tier 2/3. Just stop dropping the return.

Call sites to convert (from `grep -rn 'g3lib\.\(SendTaskCancel\|SendScanFailed\|SendScanProgress\|SendScanStopped\|SendScanCompleted\|SendEmptyResponse\)' --include='*.go' src/`):

**`src/g3scanner/g3scanner.go` — 30 sites:**

| Line | Function | Context |
|---|---|---|
| 205 | SendTaskCancel | cancel handler broadcast |
| 230, 237, 246 | SendScanFailed | pre-flight validation errors |
| 294, 307, 331, 338 | SendScanFailed | scan setup errors |
| 324, 346 | SendScanProgress | initial/seed progress |
| 358 | SendScanFailed | unsupported mode (loop) |
| 392, 409, 451, 479 | SendScanStopped | cancellation points in parallel mode |
| 439, 459, 489, 505, 524, 537 | SendScanFailed | parallel-mode errors |
| 582 | SendScanProgress | per-step progress, parallel mode |
| 592 | SendScanFailed | "internal error" fallback |
| 608, 659, 675, 701, 728, 792 | SendScanStopped | cancellation points in sequential mode |
| 688, 709, 738, 752, 761, 774, 798 | SendScanFailed | sequential-mode errors |
| 781 | SendScanProgress | per-step progress, sequential mode |
| 825 | SendScanProgress | final progress |
| 840 | SendScanStopped | wrap-up cancel path |
| 854, 862, 886, 918, 937 | SendScanFailed | merger / report-info errors |
| 942 | SendScanCompleted | terminal success |

**`src/g3worker/g3worker.go` — 2 sites:**

| Line | Function | Context |
|---|---|---|
| 473 | SendEmptyResponse | SIGTERM drop |
| 535 | SendEmptyResponse | command index out of range |

(The other 11 `g3worker.go` calls to these functions already check the error — line 445 and below follow the pattern `err := ...; if err != nil { log.Error(err.Error()) }`.)

#### 1.2 Remove the TODO suppressions in `.golangci.yml`

Delete lines 32-42 (the TODO comment and the six function exclusions). This is the gate: once Tier 1 is done, re-running the linter must pass without these entries. If any call was missed, errcheck will flag it.

Specifically, remove:

```yaml
        # TODO: temporary — these MQTT send functions DO have errors worth
        # handling. A failed send means a lost message that currently goes
        # undetected and unlogged (scan status updates, cancel/stop signals,
        # progress, empty responses from workers). Remove these exclusions
        # once proper error handling is added in a follow-up task.
        - golismero.com/g3lib.SendTaskCancel
        - golismero.com/g3lib.SendScanFailed
        - golismero.com/g3lib.SendScanProgress
        - golismero.com/g3lib.SendScanStopped
        - golismero.com/g3lib.SendScanCompleted
        - golismero.com/g3lib.SendEmptyResponse
```

#### 1.3 Bump `MQTT_QUIESCE` from 3s to 15s

- `src/g3lib/task.go:25`
- QoS 2 requires PUBLISH → PUBREC → PUBREL → PUBCOMP. Over a loaded Docker network or a slow link, 3s is enough to manufacture false timeouts that then get logged as errors even when the publish actually succeeded server-side. 15s is conservative but still catches a genuinely dead broker in a reasonable time.
- Single-constant change. No other call sites depend on the literal.

### Files touched (Tier 1)

| File | Change |
|---|---|
| `src/g3lib/task.go` | Constant: `MQTT_QUIESCE` 3 → 15 |
| `src/g3scanner/g3scanner.go` | 30 call sites converted to check-and-log |
| `src/g3worker/g3worker.go` | 2 call sites (473, 535) converted to check-and-log |
| `.golangci.yml` | Remove 6 errcheck exclusions + TODO comment (lines 32-42) |

### Verification (Tier 1)

Verification is owned by the user — they run the end-to-end tests locally. Implementation stops at "code compiles, passes `go vet`, and golangci-lint is clean without the six removed exclusions". The user then exercises:

1. `make bin` — all six binaries build clean.
2. `golangci-lint run` — passes with no exclusions needed (this is the lint gate for Tier 1).
3. `docker compose up` demo stack — one happy-path scan end to end; no spurious error logs on the clean path.
4. Regression: pause the mosquitto container mid-scan, confirm the new error-log lines appear for the failed publishes; unpause, confirm behaviour is unchanged from today (no retry yet — that's Tier 2).

### What Tier 1 does **not** do

- Does not change what happens when `SendScanCompleted` / `SendScanFailed` fails — scan will still look stuck to the API. (That's Tier 3.)
- Does not detect crashed workers. (That's Tier 2b.)
- Does not retry transient publish failures. (That's Tier 2a.)

---

## Tier 2a — Idempotent retry in the wrapper

**Status:** **shipped.** Scope-split from the original "Tier 2" based on user decision to ship retry first and observe before committing to LWT.

### Context feeding this tier

Tier 1 left `SendMQPayload` in a state where every publish either succeeds, returns a paho error, or returns the 15 s timeout error we added when we killed the silent-hang loop. All three outcomes propagate up the call stack and are logged by the Tier 1 check-and-log shim at every caller. The piece still missing: transient broker hiccups (reconnect in progress, single-packet loss, momentary mosquitto unavailability) surface as user-visible failures even when a half-second retry would have succeeded.

### Design principles (already settled)

- **Retry lives in the wrapper, never at callers.** 47+ caller sites across 6 helper functions — wrong place to add retry. Callers keep their Tier 1 shape; retry is invisible to them.
- **`json.Marshal` error stays non-retryable.** It's deterministic and pre-dates the retry loop in the function body.
- **Classification by outcome, not by error type.** Any `token.Error()` or quiesce-timeout → retry candidate. No paho-specific error taxonomy (fragile across paho versions and unreliable in practice).

### Concrete shape

Inside `src/g3lib/task.go`, wrap the current publish-wait-check region of `SendMQPayload` in a bounded loop. New constants at the top of the file next to the existing `MQTT_*` group:

```go
const MQTT_MAX_ATTEMPTS = 3
var   MQTT_BACKOFFS     = []time.Duration{1 * time.Second, 3 * time.Second}
```

New function body shape (replacing the current lines 358-373):

```go
func SendMQPayload(client MessageQueueClient, topic string, msg any) error {
    log.Debug("Publishing to: " + topic)
    msgtext, err := json.Marshal(msg)
    if err != nil {
        return err
    }
    var lastErr error
    for attempt := 0; attempt < MQTT_MAX_ATTEMPTS; attempt++ {
        if attempt > 0 {
            backoff := MQTT_BACKOFFS[attempt-1]
            log.Debugf("Retrying publish to %q (attempt %d/%d) after %s",
                topic, attempt+1, MQTT_MAX_ATTEMPTS, backoff)
            time.Sleep(backoff)
        }
        token := client.Publish(topic, MQTT_QOS, MQTT_PERSIST, msgtext)
        if !token.WaitTimeout(MQTT_QUIESCE * time.Second) {
            lastErr = fmt.Errorf("publish to %q timed out after %ds", topic, MQTT_QUIESCE)
            continue
        }
        if err := token.Error(); err != nil {
            if log.LogLevel == "DEBUG" {
                debug.PrintStack()
            }
            lastErr = err
            continue
        }
        if attempt > 0 {
            log.Debugf("Publish to %q succeeded on attempt %d", topic, attempt+1)
        }
        return nil
    }
    return fmt.Errorf("publish to %q failed after %d attempts: %w",
        topic, MQTT_MAX_ATTEMPTS, lastErr)
}
```

### Tuning

- **3 attempts total** (1 initial + 2 retries).
- **Backoffs `[1 s, 3 s]`.** Fixed, no jitter (single publisher per process; thundering-herd risk negligible).
- **`MQTT_QUIESCE` stays 15 s** per attempt, same as Tier 1.
- **Worst-case latency before a genuine failure surfaces:** 3 × 15 s quiesce + 1 s + 3 s = ~49 s. Acceptable because a persistent broker outage is already a severe incident; users see the final error via the Tier 1 caller-side logs.
- **No `context.Context` threading.** Would touch every caller, violating the wrapper-only principle. Graceful shutdown tolerates up to ~49 s latency on an in-flight publish. Revisit only if field experience says it's too long.

### Idempotency rationale (carried forward from the original Tier 2 outline)

Retry is safe because every consumer already tolerates duplicates:
- Task dispatch → worker dedup via `CancelTracker.AddTaskIfNew` at `g3worker.go:482`.
- Responses → tagged by `TaskID`; scanner tolerates duplicates.
- Cancels → naturally idempotent.

### Files touched (Tier 2a)

| File | Change |
|---|---|
| `src/g3lib/task.go` | Add `MQTT_MAX_ATTEMPTS` + `MQTT_BACKOFFS`; rewrite the body of `SendMQPayload` around a retry loop. |

One file, one function body. No caller edits.

### Verification (Tier 2a) — user-owned

1. `make bin` — builds clean.
2. `go vet ./...` on `src/g3lib/` — no new findings.
3. Happy-path regression: `docker compose up` + a small valid scan; no retry log lines in the normal path.
4. Transient-failure test: `docker pause mosquitto` mid-scan; confirm retry Debug lines appear; `docker unpause mosquitto` within 4 s; publish succeeds on retry, no caller-side error log.
5. Persistent-failure test: keep mosquitto paused longer than `MQTT_MAX_ATTEMPTS × MQTT_QUIESCE`; confirm eventual "failed after 3 attempts" error propagates to the caller's Tier 1 error log.
6. Oversize test (against a real 7.3 MB script): confirm 3 retries all fail identically; final error surfaced after ~49 s. (Deterministic failures will waste the retry budget — expected trade-off.)

### What Tier 2a does **not** do

- Does not detect crashed workers. (See "Deferred — ungraceful worker crash handling" below.)
- Does not promote publish failures into DB state (Tier 3).
- Does not add any form of durable queue or persistent outbox — retries are in-memory only. If the g3api or scanner process dies mid-retry, the publish is lost.

---

## Tier 2b — Bounded-retry on broker connect

**Status:** **shipped.** Rescoped from the original LWT design after discussion: LWT was discarded entirely (see "Why LWT was retired" below), and the only remaining Tier 2 work was a sibling of the Tier 2a wrapper — the broker-connect path had the identical silent-hang loop bug.

### Context

`ConnectToBroker` at `src/g3lib/task.go` had a `for !token.WaitTimeout(...) {}` at what was line 147 — the same pattern Tier 1 fixed in `SendMQPayload`. If mosquitto wasn't accepting connections at worker boot (very possible in a compose bring-up because `depends_on: { condition: service_started }` doesn't wait for readiness), the worker would hang indefinitely at startup with no log line, no retry, no timeout.

### Design principle

Connect and publish are the same *shape* of problem (bounded retry with backoff) but different *tolerance profiles*:
- **Publish** is steady-state. Should fail fast so the user sees problems in time. 3 attempts, 1 s / 3 s backoff.
- **Connect** is a startup concern. Must tolerate the broker being seconds-to-tens-of-seconds late to ready. 5 attempts, 2 s / 4 s / 8 s / 16 s backoff.

Separate constants, independent tuning.

### Implementation

New constants alongside the existing `MQTT_*` group:

```go
const MQTT_CONNECT_TIMEOUT      = 15
const MQTT_CONNECT_MAX_ATTEMPTS = 5
var   MQTT_CONNECT_BACKOFFS     = []time.Duration{
    2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
}
```

`ConnectToBroker` rewritten around a retry loop with the same shape as `SendMQPayload`'s: per-attempt `WaitTimeout`, outcome-based classification (timeout and error both eligible for retry), debug-logged retries, wrapped final error.

### Files touched (Tier 2b)

| File | Change |
|---|---|
| `src/g3lib/task.go` | Add `MQTT_CONNECT_*` constants. Rewrite `ConnectToBroker` around a bounded retry loop. |

### Why LWT was retired

The original plan had LWT as the core of Tier 2, with re-dispatch. Discussion surfaced three blockers:

1. **LWT cannot distinguish crash from transient disconnect.** MQTT keepalive + paho's silent auto-reconnect means a network hiccup lasting longer than the broker's client-timeout produces an LWT publish indistinguishable from a real crash. Without reconciliation machinery (grace periods, heartbeats, "I'm back" signals), acting on LWT is unreliable.
2. **Graceful shutdown is already handled.** The worker's SIGTERM path calls `cancelTracker.CancelAllTasks()` at `g3worker.go:311,316`, which cancels each running task's context; the plugin runner exits, the worker sends responses back on the normal path. No LWT need.
3. **Ungraceful crash is a real problem, but LWT doesn't solve it cleanly** — and the problem is entangled with a separate "plugin stuck in an infinite loop inside a live worker" failure mode that LWT cannot see at all. Both are better served by observability + user-driven intervention for now.

### Deferred — ungraceful worker crash handling

Parked, explicitly not in scope:

- **The problem.** A worker process dies (SIGKILL, OOM, panic). Plugin containers orphan (they live in dockerd's namespace, not the worker's). Scanner waits forever for task responses that will never arrive.
- **Why deferred.** Likely solution is smart per-plugin timeouts in the scanner. But plugin-runtime varies wildly (nmap of a /16 can be hours; dig is seconds), so picking defaults requires data. Current mitigation — user sees no progress, cancels the scan manually — is adequate because task execution today is purely user-driven.
- **When to revisit.** When task execution becomes non-interactive (LLM/agentic integration, scheduled scans, etc.) user-driven cancellation stops working. That milestone is the natural trigger for revisiting this tier.

---

## Tier 3 — Promote terminal publish failures to DB state

**Status:** **deferred until observed.** Outlined below for reference; not scheduled.

**Why deferred:** The combination of shipped tiers has shrunk this from a correctness gap to belt-and-suspenders. Tier 1 surfaces every terminal publish failure as a loud error log. Tier 2a retries transient failures automatically. Tier 5 gives real per-task state in `g3cli ps` so the task view stays truthful even if the scan header goes stale. The remaining failure mode (retries exhausted + logs not read + `ps` not consulted) is narrow and mostly a concern for unattended/automated deployments.

**Trigger to revisit:** a concrete case where stale scan status misleads a user or breaks an integration. Until then this tier is a hypothetical — its blast radius (touches every `SendScan*` call site in the scanner, changes write ordering with SQL, needs careful consumer-side reconciliation logic) doesn't justify the work.

### Objectives

The biggest user-visible failure mode today: a scan finishes, `SendScanCompleted` publish drops, scanner logs the error and exits, API/user forever see `RUNNING`. Fix by making SQL/Mongo state the source of truth for terminal transitions, with MQTT notification as an optimization.

### Approach sketch

- When scanner decides a scan is `FINISHED` / `ERROR` / `CANCELED`, write the terminal state to SQL **before** publishing the status message.
- If publish succeeds, API gets the push notification path (fast).
- If publish fails, API's next query/poll reconciles from SQL (slow but correct).
- Mirror the pattern for `g3api`'s own publishes (`SendNewScan`, `SendScanStop`) — on publish failure, mark the scan as `ERROR` with a reason like "dispatch failed" instead of leaving it `WAITING`.

### Likely file targets

- `src/g3api/g3api.go` — lines ~491, ~620
- `src/g3scanner/g3scanner.go` — all `SendScan*` terminal transitions (numerous)
- `src/g3lib/datastore.go` / `sql.go` — may need a helper for "write terminal state + publish, reconcile on failure"

### Risks

- Most intrusive tier. Touches handler code in every terminal path. Needs care about write ordering (write SQL first, then publish — not the other way around).
- Existing code assumes MQTT delivery is the primary signal; reviewer needs to confirm no consumer of the status message *also* expects SQL not yet to be updated.

---

## Tier 4 — Observability: g3cli per-task visibility

**Status:** **shipped.** Promoted ahead of Tier 3 because ungraceful-crash handling (which this indirectly addresses via user-driven cancellation) was deferred and visibility is the interim mitigation.

### Context

The MariaDB `logs` table at `src/g3lib/sql.go:111-115` already records `(timestamp, scanid, taskid, text)` for every line a plugin emits (workers save via `SaveLogLine` in the plugin runner's stderr pipe at `g3worker.go:585`). `QueryLogForTask` at `sql.go:195` already computes `Start`, `End`, and `Lines` per task — `End` is the last-seen timestamp.

The data to answer "is this task still alive?" already exists. We just need a compact query and a compact presentation. Today, `g3cli logs` dumps every line; that's too noisy for a liveness check.

### Design principles

- **No new data collection.** The `logs` table already has what we need. Workers reliably write at least one log line per task at dispatch (see `QueryTaskIDsFromLog` comment at `sql.go:167-174`), so tasks-that-have-logged covers tasks-that-exist in practice. No worker heartbeat code needed for v1.
- **Server-side aggregation, not client-side.** A `MAX(timestamp) GROUP BY taskid` returns one row per task. Sending all log lines over the wire just to extract per-task max timestamps would be orders of magnitude wasteful for large scans.
- **Extend existing idioms, don't invent new ones.** `g3cli ps` already means "what's active right now." Drilling into a scan via `g3cli ps <scanid>` to see per-task status mirrors Unix `ps` behaviour exactly — no need for a new subcommand.

### Concrete shape

#### Server-side: new endpoint `/scan/tasks/status`

New request struct in `src/g3lib/api.go` next to `ReqQueryScanTaskList`:

```go
type ReqQueryScanTaskStatus struct {
    AuthenticatedRequest
    ScanID string `json:"scanid" validate:"uuid"`
}
func (req *ReqQueryScanTaskStatus) Decode(r *http.Request) error {
    if err := ValidateHttpRequest(r); err != nil { return err }
    if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
    return validator.New().Struct(req)
}
```

New response struct in `src/g3lib/sql.go` next to existing log types:

```go
type TaskStatusEntry struct {
    TaskID     string `json:"taskid"`
    FirstLogTS int64  `json:"first_log_ts"`  // Unix timestamp of first log line
    LastLogTS  int64  `json:"last_log_ts"`   // Unix timestamp of most recent log line
    LineCount  int    `json:"line_count"`
    AgeSeconds int64  `json:"age_seconds"`   // server-computed: now - LastLogTS
}
```

New query helper in `src/g3lib/sql.go`:

```go
func QueryTaskStatus(db SQLDBClient, scanid string) ([]TaskStatusEntry, error) {
    query := `SELECT taskid,
                     MIN(timestamp) AS first_ts,
                     MAX(timestamp) AS last_ts,
                     COUNT(*)       AS line_count
              FROM logs
              WHERE scanid = ?
              GROUP BY taskid
              ORDER BY last_ts DESC`
    // ... scan rows, compute AgeSeconds as now - last_ts, return slice
}
```

New handler in `src/g3api/g3api.go` registered as `apiPath + "/scan/tasks/status"` right after the existing `/scan/logs` handler (around line 563). Follows the same authenticate → decode → query → respond pattern as `/scan/tasks`.

#### Client-side: `g3cli ps` accepts an optional scan ID

Update `PsCmd` at `src/g3cli/g3cli.go:62`:

```go
type PsCmd struct {
    Output string `short:"o" type:"path"         default:"-"     help:"Output file."`
    ScanID string `arg:""    optional:""                         help:"Optional scan ID; when given, drills into per-task status."`
}
```

`PsCmd.Run` at `g3cli.go:721` gains an if-branch: if `ScanID == ""`, keep existing scan-table behaviour; otherwise call `/scan/tasks/status` and render a per-task table with columns `TASK ID | FIRST SEEN | LAST SEEN | AGE | LINES`, sorted by age descending (most stale first → most visible at the top).

Age formatting: human-readable — "5s", "2m 14s", "1h 23m" — computed from `AgeSeconds`. Timestamps formatted as HH:MM:SS (or full date if not today; follow whatever format the logs command already uses for consistency).

No colour codes for v1; the age numbers themselves are sufficient signal. Thresholds (red/yellow/green) can be a follow-up once real use reveals what "stuck" looks like in the field.

### Files touched (Tier 4)

| File | Change |
|---|---|
| `src/g3lib/sql.go` | Add `TaskStatusEntry` struct and `QueryTaskStatus` helper function. |
| `src/g3lib/api.go` | Add `ReqQueryScanTaskStatus` + `Decode`. |
| `src/g3api/g3api.go` | Register `/scan/tasks/status` handler. |
| `src/g3cli/g3cli.go` | Add optional `ScanID` arg to `PsCmd`; add per-task rendering branch to `PsCmd.Run`. |

Four files, each small. No schema changes (logs table already has all needed columns).

### Verification (Tier 4) — user-owned

1. `make bin` — builds clean.
2. `go vet ./...` on each touched module — no new findings.
3. Behavioural: run a normal scan; `g3cli ps` (no arg) still shows the scan table. `g3cli ps <scanid>` shows per-task rows with plausible timestamps and ages.
4. Stuck-task simulation: run the stress test with `force-exec` to produce many tasks; while running, pause mosquitto or simulate slow plugins; confirm the per-task view clearly shows which tasks aren't advancing (ages climbing).
5. Empty-scan check: `g3cli ps <scanid>` against a scan that has no logged tasks yet shows an empty table, not an error.

### What Tier 4 does **not** do

- Does not *act* on stuck tasks — only surfaces them. Cancellation is still via `g3cli cancel`.
- Does not handle tasks that never logged (empirically rare, see `sql.go:167-174` comment).
- Does not add colour-coded thresholds; reserved as a follow-up.
- Does not define "stuck" — the user reads the age and decides.

---

## Tier 5 — Live task state in Redis + structured audit log lines

**Status:** **shipped.** Added after Tier 4 to fix the "no per-task state anywhere" architectural gap surfaced during review.

### Context

Tier 4 shipped with a scan-level status proxy for per-task state because per-task state literally wasn't stored anywhere — completion signals flowed through MQTT from workers to the scanner's in-memory maps and were discarded at the end of the response handler. Once the scanner process ended (or the scan reached terminal), the "did task T succeed or fail?" question was unanswerable without heuristic log parsing.

### Design principles (settled across iterations)

- **Redis for live state, SQL for durable audit.** Short-lived tasks don't churn the DB; audit trail lives in structured log lines in the existing `logs` table. No schema changes.
- **Single writer per state, period.**
  - Scanner writes only `DISPATCHED`. Written *before* `SendTask` publishes the MQTT message, so no worker can ever race ahead of it.
  - Worker writes everything post-dispatch: `RUNNING` on accept, `DONE` / `ERROR` / `CANCELED` at every termination path.
  - No `CANCELING` task state — the "task is winding down" UI signal is derived client-side from the combination `scan.Status == CANCELED && task.state ∈ {DISPATCHED, RUNNING}`.
- **Structured log lines are the audit primitive.** Four event types: `[g3:dispatch]`, `[g3:start]`, `[g3:cancel]`, `[g3:done]`. Human-readable, regex-parseable, stable prefix. `[g3:cancel]` is emitted by the scanner as a pure audit record (user-intent capture) — not backed by any Redis write.
- **Worker's terminal write is EXISTS-guarded.** If the scan's Redis keys have already been cleaned up by the time a slow-winding-down worker finishes, `SetTaskTerminal` is a no-op. Prevents orphan hashes.
- **Redis keys are scan-scoped and cleaned up on terminal scan or explicit delete.** No TTL — scanner owns the lifecycle via `defer DeleteTaskStates`.
- **`SendTask` takes a caller-generated taskid.** API change that enables the "write Redis, then publish MQTT" ordering above. Callers use `uuid.NewString()` before the dispatch call.

### Redis schema

- `g3:scan:<scanid>:tasks` — set, task IDs.
- `g3:scan:<scanid>:task:<taskid>` — hash with fields `tool`, `dispatch_ts`, `worker`, `start_ts`, `state`, `complete_ts`, `error_msg`.

### Write sites

- **Scanner dispatch** (`g3scanner.go` parallel + sequential): generates `taskid := uuid.NewString()`, then `SetTaskDispatched` + `[g3:dispatch] task=<id> tool=<name>` log, **then** `SendTask(..., taskid, ...)`. On dispatch failure: `SetTaskTerminal(ERROR)` + `[g3:done state=ERROR]` so the task doesn't linger in DISPATCHED forever.
- **Worker accept** (`g3worker.go` at case-2 of `AddTaskIfNew`): `SetTaskRunning` (DISPATCHED → RUNNING, stamps worker ID + start_ts) + `[g3:start] task=<id> worker=<id>` log.
- **Scanner cancel handler** (`SubscribeToStop` in main): emits `[g3:cancel] task=<id>` per running task, then `SendTaskCancel` MQTT broadcast. **No Redis writes** — the UI derives the "winding down" signal from the scan status.
- **Worker termination sites** (every path that reaches `SendEmptyResponse` or `SendResponse`): `SetTaskTerminal` + `[g3:done] task=<id> state=<X>` log. Classifications:
  - **CANCELED:** SIGTERM drop (worker shutting down), case-1 reject (task was in `CancelTracker.rejectTasks` from a prior cancel), plugin cancellation post-execution (`cancelled` flag set after `RunPluginCommand`).
  - **ERROR:** default switch branch, tool-not-supported checks, plugin-not-found, command-index-out-of-range, MongoDB load failures, `BuildToolCommand` errors, plugin execution errors.
  - **DONE:** successful plugin completion path (`SendResponse` with valid output).
  - A small closure `markTerminal(scanid, taskid, state)` in the worker's main() wraps these two calls to keep the termination sites compact.
- **Scanner response handler**: just cleans up in-memory tracking (`runningTasks.Delete`, etc.). **Does not touch Redis or emit audit lines** — worker already did that before sending the response.
- **Scanner terminal** (ScanRunner exit): `defer DeleteTaskStates(rdb, scanid)` — Redis cleared, audit trail remains in SQL logs.

### UI: deriving "winding down" without a CANCELING state

`g3cli ps <scanid>` renders the STATE column directly from Redis (`DISPATCHED` / `RUNNING` / `DONE` / `ERROR` / `CANCELED`) except when the scan itself is CANCELED and the task is still in DISPATCHED or RUNNING — in that case the displayed state is replaced with `CANCELING` for the user. The underlying Redis value is unchanged; this is purely a display-layer projection. Wind-down duration for cancelled tasks is measurable as (task.complete_ts − scan.canceled_ts) once the worker eventually writes its terminal state.

### Files touched (Tier 5)

| File | Change |
|---|---|
| `src/g3lib/kvstore.go` | Add `TaskState` struct; `SetTaskDispatched`, `SetTaskStarted`, `SetTaskTerminal`, `GetTaskStates`, `DeleteTaskStates` helpers. |
| `src/g3lib/sql.go` | Extend `TaskStatusEntry` with Redis-derived fields (Tool, Worker, State, DispatchTS, StartTS, CompleteTS, ErrorMsg). |
| `src/g3api/g3api.go` | `/scan/tasks/status` now merges Redis state with SQL log summary; `/scan/delete` fanout calls `DeleteTaskStates`. |
| `src/g3scanner/g3scanner.go` | Main-level Redis connection for cancel handler; ScanRunner opens its own SQL connection; write sites at dispatch (×2), response (×2), cancel, terminal. |
| `src/g3worker/g3worker.go` | Redis connection at startup; write site at task-accept. |
| `src/g3cli/g3cli.go` | `runTaskView` decodes richer response; STATE column now shows real per-task state; AGE hidden for terminal tasks; adds TOOL and WORKER columns. |
| `docker-compose.yml` | Redis `--save 60 100` for disk persistence; 5 worker services gain `REDIS_HOST/PORT/PASSWORD` env + `redis: condition: service_started` dependency. |

### Known v1 limitations

- **`SetTaskTerminal` EXISTS-guard is not atomic.** `EXISTS` then `HSet` has a narrow race window where the scanner's cleanup could fire between the two ops, resurrecting an orphan hash. In practice the window is milliseconds and the leak per occurrence is ~200 bytes. Promote to a Lua script if this ever matters.
- **No scanner-restart recovery.** Redis state persists across scanner restarts, so a restarted scanner *could* query `g3:scan:<scanid>:tasks` to reconcile in-flight work. v1 doesn't implement this — noted as a future capability that Redis state enables.
- **Tasks with no logs still show in Redis.** `passthrough` and `force-exec` produce no stderr so they used to be invisible in Tier 4's log-only view. Tier 5 fixes this: they're in Redis the moment they're dispatched.
- **Ungraceful crashes leave tasks stuck.** Worker OOM/SIGKILL means no terminal write — the task stays visibly in RUNNING (or DISPATCHED if it never got picked up). This is honest state, not a bug; the `AGE` column climbing makes the condition visible. Real fix belongs in the deferred "per-plugin timeouts" milestone.

### Verification (Tier 5) — user-owned

1. `make bin` + `golangci-lint run` — clean.
2. `docker compose up` with a fresh stack — workers connect to Redis successfully.
3. Run a scan with mixed outcomes (some passing, some `error`-plugin). `g3cli ps <scanid>` shows real per-task state (DONE for successes, ERROR for failures).
4. Start a long scan; `g3cli cancel` mid-flight; confirm tasks show CANCELED state in `ps` and `[g3:cancel]` lines in `g3cli logs`.
5. Delete a scan: confirm Redis keys under `g3:scan:<scanid>:*` are gone (`redis-cli KEYS 'g3:scan:<scanid>:*'`).
6. Restart Redis container: confirm state survives (RDB snapshot via `--save 60 100`).

---

## Explicitly out of scope

- Replacing MQTT with another broker (issue #5 option 5). The diagnosis doesn't justify it — the problems are application-layer. Revisit only if Tiers 1-3 fail to stabilize.
- Turning on paho's `retained` flag. Wrong semantics for shared-subscription work queues.

---

## Global verification plan

Each tier carries its own verification section (Tier 1 above). General approach:

1. `make bin` from repo root builds all six binaries clean.
2. `golangci-lint run` per module — no new findings (for Tier 1, without the six exclusions).
3. `docker compose up` demo stack — run one happy-path scan end to end.
4. Targeted regression for that tier's scenario (pause broker for Tier 1, `kill -9` a worker for Tier 2, etc.).
5. Update issue #5 with which options are now addressed.

---

## Critical files (across all tiers)

- `src/g3lib/task.go` — MQTT primitives, constants, LWT config
- `src/g3scanner/g3scanner.go` — orchestration, 30 of the 32 Tier 1 sites
- `src/g3worker/g3worker.go` — worker publish sites, LWT registrant
- `src/g3api/g3api.go` — HTTP/WS surface, dispatch publishes
- `src/g3lib/datastore.go`, `src/g3lib/sql.go` — state propagation target for Tier 3
- `src/g3cli/*` — Tier 4 surface
- `.golangci.yml` — errcheck exclusions removed in Tier 1
