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

**Status:** outlined only. Not started. Tier 2a (retry) plus Tier 1's check-and-log has absorbed the common cases; Tier 3 is now specifically about *reconciliation* when retry is exhausted. Worth revisiting after Tier 4 (visibility) ships, since visibility may reveal which terminal failures actually occur in practice.

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

## Tier 4 — Observability: g3cli alive-check

**Status:** outlined only. Not started. Lowest priority; revisit once Tiers 1-3 are in place.

### Objectives

Match issue #5 option 2: `g3cli` sub-command that shows per-task last-activity timestamp, answering "is this task still alive or just stuck?" Leans on the existing MariaDB execution log (workers already write there).

### Approach sketch

- New `g3cli` command: `g3cli task list <scanid>` or `g3cli task show <taskid>` — fetches from `g3api`, which in turn reads the last log row timestamp from MariaDB per task.
- Add an `age` column (`now() - last_log_ts`). Red/yellow/green thresholds configurable.
- Optional: emit a per-minute heartbeat row from workers so tasks that don't produce output still advance the timestamp.

### Likely file targets

- `src/g3cli/*`
- `src/g3api/g3api.go` — new endpoint
- `src/g3lib/sql.go` — query helper for per-task last-log timestamp
- `src/g3worker/g3worker.go` — optional heartbeat writer

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
