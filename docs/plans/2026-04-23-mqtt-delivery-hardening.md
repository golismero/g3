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
- Does not detect crashed workers. (That's Tier 2.)
- Does not retry transient publish failures. (That's Tier 2.)

---

## Tier 2 — LWT + idempotent retry

**Status:** outlined only. Not started. Revisit and expand this section with the user before any implementation begins; open questions below must be answered first.

### Objectives

- **LWT on every worker.** Worker connects with a Last Will message on a well-known topic (e.g. `worker/lwt/<workerid>`). Scanner subscribes. When a worker dies without graceful disconnect, scanner sees the LWT within keepalive + grace and can re-dispatch any tasks it had assigned to that worker.
- **Idempotent retry inside the wrapper layer, not at callers.** Transient `token.Error()` → exponential backoff retry (e.g. 3 attempts, 1s/3s/9s). The Tier 1 grep counted 32 caller sites across 6 per-message helper functions and one shared primitive (`SendMQPayload`). The ratio tells the design: push retry into the primitive so every caller benefits without editing any of them a second time. Callers keep Tier 1's simple "check-and-log" shape; the log line now only fires when retry has already been exhausted.
- **Why this is safe in our system.** Retry causes duplicates iff the consumer isn't idempotent. Ours is:
  - Task dispatch: workers dedupe by UUID via `CancelTracker.AddTaskIfNew` at `g3worker.go:482` (returns 0 → duplicate, ignored).
  - Responses: tagged by `TaskID`; scanner already tolerates duplicates.
  - Cancels: naturally idempotent.

### Open questions to resolve at Tier 2 start

- LWT topic shape and who owns re-dispatch — scanner or g3api?
- MQTT keepalive interval (determines LWT latency) — currently default paho 30s?
- What counts as a "transient" error worth retrying? Broker-disconnected yes; marshal error no. The split happens inside `SendMQPayload` where both kinds are already observable: `json.Marshal` error returns immediately; `token.Error()` after `WaitTimeout` is the retry candidate.
- Does the retry loop need to be cancellable (e.g. for graceful shutdown during backoff)?

### Likely file targets

- `src/g3lib/task.go` — LWT setup in `ConnectToBroker`; retry loop wrapped around the existing `token.Error()` check in `SendMQPayload` (no new public API, no caller churn).
- `src/g3worker/g3worker.go` — register LWT on connect, publish "I'm leaving" on graceful shutdown. **No caller-site edits for retry.**
- `src/g3scanner/g3scanner.go` — subscribe to LWT topic, track worker → active tasks, re-dispatch on LWT. **No caller-site edits for retry.**

---

## Tier 3 — Promote terminal publish failures to DB state

**Status:** outlined only. Not started. Revisit with the user after Tier 2 ships and is observed in practice — Tier 2 may change the scope or urgency of Tier 3.

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
