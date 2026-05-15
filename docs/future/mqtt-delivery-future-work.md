# MQTT Delivery Hardening — Future Work & Known Limitations

Carry-over notes from [`2026-04-23-mqtt-delivery-hardening.md`](./2026-04-23-mqtt-delivery-hardening.md) (issue [#5](https://github.com/golismero/g3/issues/5), now closed). The bulk of that plan shipped; this file captures only what's left unfinished or shipped-with-caveats, so neither needs to be rediscovered from a 500-line plan doc later.

This is a watchlist, not a plan. Each item names:
- the **trigger** that should pull it from "deferred" into "scheduled", and
- the **direction** to take when it does.

No code changes are proposed here. When any item is picked up, write a fresh plan for it.

---

## Deferred work

### 1. SQL-as-source-of-truth for terminal scan state (was Tier 3)

**The hole.** A scan finishes, `SendScanCompleted` (or `SendScanFailed` / `SendScanStopped`) drops on the floor after the bounded retry budget is exhausted. The scanner logs the error and exits. The API row in MariaDB still says `RUNNING`. The user-facing scan looks stuck forever.

**Why it's not urgent today.**
- Tier 1's check-and-log shim surfaces every terminal publish failure as a loud error in the scanner log.
- Tier 2a's in-wrapper retry (3 attempts, ~49 s ceiling) eats every transient broker hiccup.
- Tier 5's per-task Redis state means `g3cli ps <scanid>` still tells the truth about individual tasks even if the scan-level row goes stale.

So the remaining failure mode is narrow: retries exhausted **and** logs not read **and** `ps` not consulted. Almost entirely a concern for unattended/automated deployments.

**Triggers to revisit.**
- A concrete user/integration report of "the scan said RUNNING but it was actually done hours ago."
- Any non-interactive consumer (scheduled scans, LLM/agentic driver, dashboards) starts depending on the scan-level status field being timely.

**Direction when it lands.**
- Write the terminal state to SQL **before** publishing the MQTT status message. Publish becomes an optimization; SQL is authoritative.
- On publish failure, API's next query/poll reconciles from SQL.
- Mirror the pattern on `g3api`'s own dispatch publishes (`SendNewScan`, `SendScanStop`): on publish failure, mark the scan `ERROR` with reason `"dispatch failed"` rather than leaving it `WAITING`.
- Most intrusive change of any tier — every `SendScan*` terminal site in the scanner plus the two in g3api. Watch write ordering carefully; no consumer should observe a status message that arrives before the SQL row is updated.

**Likely files when scheduled:** `src/g3api/g3api.go`, `src/g3scanner/g3scanner.go` (all `SendScan*` terminal transitions), possibly a helper in `src/g3lib/datastore.go` or `src/g3lib/sql.go`.

---

### 2. Ungraceful worker crash handling

**The hole.** A worker process dies hard — SIGKILL, OOM, panic. Its plugin container keeps running (it lives in dockerd's namespace, not the worker's). The scanner waits forever for a task response that will never arrive. Nothing in the shipped tiers fixes this.

**Why LWT was rejected as the solution.** From the original Tier 2 discussion: MQTT keepalive + paho's silent auto-reconnect means a network hiccup longer than the broker's client-timeout produces an LWT message indistinguishable from a real crash. Acting on LWT would require grace periods, heartbeats, and "I'm back" reconciliation — a lot of machinery for an unreliable signal.

**Why deferred.** The likely solution is **per-plugin timeouts in the scanner**, but plugin runtimes vary wildly — nmap of a `/16` can run for hours; dig is seconds. Picking defaults requires field data. Today's mitigation is adequate: the user sees no progress in `g3cli ps <scanid>` (the AGE column climbs visibly), and cancels the scan by hand.

**Trigger to revisit.** When task execution becomes non-interactive — LLM/agentic driver, scheduled/automated scans, anything where there's no human watching for stalled tasks. That milestone is the natural moment to instrument per-plugin runtime data and pick timeouts.

**Direction when it lands.**
- Collect per-plugin runtime statistics first; don't guess defaults.
- Timeouts probably belong in the scanner, applied per task. Plugin `.g3p` files may need an optional `expected_runtime` hint with a multiplier for the hard timeout.
- Pair with a janitor for orphan plugin containers (a worker that's been declared dead leaves its container running in dockerd).

---

## Known limitations shipping today

These were accepted as part of the shipped tiers. Each is honest (visible, not hidden) but worth knowing about.

### 1. `SetTaskTerminal` EXISTS-guard is not atomic *(Tier 5)*

`EXISTS` then `HSet` has a narrow race: the scanner's `defer DeleteTaskStates` can fire between the two ops, resurrecting an orphan hash. Window is milliseconds; leak per occurrence is ~200 bytes of Redis memory.

**What to do.** Ignore until it matters. If orphan hashes start accumulating, promote the EXISTS-guarded write to a single Lua script (`EVAL`) so it's atomic.

### 2. No scanner-restart recovery from Redis *(Tier 5)*

Redis task state persists across scanner restarts (RDB snapshots configured via `--save 60 100`). A restarted scanner *could* query `g3:scan:<scanid>:tasks` to reconcile in-flight work — but v1 doesn't. After a scanner crash, in-flight scans become zombies: the data is there, nobody reads it.

**What to do.** The infrastructure is in place. When a use case appears for "scanner can resume after a crash without losing scans," wire up a reconcile pass on scanner startup. No data-model changes needed.

### 3. Worker crashes leave tasks stuck in `RUNNING` *(Tier 5)*

A worker that dies ungracefully never writes the terminal state. The task stays visibly `RUNNING` in `g3cli ps`. This is **honest state** — not a bug — and the AGE column makes the condition observable. The real fix is the per-plugin timeout work in [§2 above](#2-ungraceful-worker-crash-handling).

### 4. Retries are in-memory only *(Tier 2a)*

`SendMQPayload`'s retry loop (3 attempts, backoffs `[1 s, 3 s]`, ~49 s worst-case ceiling) is process-local. If the scanner or g3api process dies mid-retry, the publish is lost permanently. There is no durable outbox or persistent queue.

**What to do.** Acceptable as long as Tier 3 (SQL-as-source-of-truth) is the long-term answer to "publish drops shouldn't matter for terminal transitions". If a non-terminal publish (e.g., progress) becomes load-bearing for an integration, revisit.

### 5. Graceful-shutdown latency *(Tier 2a)*

A worker or scanner that needs to exit while a publish is mid-retry can take up to ~49 s to wind down (`MQTT_MAX_ATTEMPTS × MQTT_QUIESCE` = 3 × 15 s, plus backoffs). No `context.Context` threading through the wrapper — would have meant editing every caller, violating the wrapper-only retry principle.

**What to do.** Tolerate. If field experience says 49 s is too long during compose-down or container restarts, thread a context into the wrapper and have callers cancel it on shutdown.

---

## Explicitly out of scope (don't propose without evidence)

- **Replacing MQTT with a different broker.** Issue #5 listed this as option 5. The diagnosis pointed at application-layer gaps, not broker behavior — and Tiers 1–5 closed those gaps. Only revisit if Tier 3 ships and scans *still* go stale, or if mosquitto itself becomes a performance bottleneck under realistic load.
- **Turning on paho's `retained` flag (`MQTT_PERSIST = true`).** Wrong semantics for shared-subscription work queues — a retained message is delivered to *new* subscribers, which has nothing to do with reliability for work-queue consumers.

---

## Quick reference: critical files

For anyone picking up any item above.

| File | What lives here |
|---|---|
| `src/g3lib/task.go` | MQTT constants (`MQTT_QUIESCE`, `MQTT_MAX_ATTEMPTS`, `MQTT_BACKOFFS`, `MQTT_CONNECT_*`); `SendMQPayload`; `ConnectToBroker` |
| `src/g3lib/kvstore.go` | Redis task-state helpers (`SetTaskDispatched`, `SetTaskStarted`, `SetTaskTerminal`, `GetTaskStates`, `DeleteTaskStates`) |
| `src/g3lib/sql.go` | `TaskStatusEntry`, `QueryTaskStatus` — server-side aggregation for `g3cli ps <scanid>` |
| `src/g3scanner/g3scanner.go` | All `SendScan*` terminal transitions (Tier 3 target); dispatch-site Redis writes |
| `src/g3worker/g3worker.go` | Worker terminal-state write sites; `markTerminal` closure |
| `src/g3api/g3api.go` | Dispatch publishes (`SendNewScan`, `SendScanStop`); `/scan/tasks/status` handler |
