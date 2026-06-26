# WebSocket Event Protocol — Future Work

Sequel to `http-routing-and-rest-migration.md` → *WebSockets (sequel, not this doc)*. That note recorded two boundaries and deferred the rest here. This doc fleshes out the **subscription protocol, event taxonomy, and filtering** for expanding `/ws` beyond its current near-PoC shape.

Like its parent, this is a **watchlist, not a plan** — deferred, not scheduled. When picked up, write a fresh plan with concrete file edits and a tier structure. Discussion notes from the 2026-06-25 architecture chat.

---

## Inherited boundaries (locked by the parent doc)

1. **OpenAPI does not describe WebSockets.** The event surface lives outside the generated REST clients. If generated WS clients are ever wanted, **AsyncAPI** is the counterpart spec and can `$ref` the same schema components as the OpenAPI doc. For "a few more events + filters," a documented message protocol is enough — no spec generator required.
2. **Reuse domain payload types, not the HTTP decode path.** WS events carry the same domain structs (`G3ScanStatus`, `G3Task`, …) as their `data`. Driving WS through the request-decode machinery is the anti-pattern to avoid. (This is *stronger* now: under the REST migration the `Req*.Decode`/`Validate*` machinery is being deleted outright — there is no decode path left to misuse.)

---

## Where `/ws` is today

The current handler ([`src/g3api/g3api.go`](../../src/g3api/g3api.go) `/ws`) is a single near-PoC feed. Three facts shape everything below:

- **Two feeds, both scan-level, no filtering.** Only `scanprogress` and `scanremoved`. One global `NotifyTracker` per feed (`progressNotify`, `removeNotify`) **broadcasts every scan's update to every subscriber**; clients filter locally (see `src/g3tui/internal/client/stream.go`). The `scanid` field already exists in `WSRequest` (`src/g3lib/api.go`) but is **dead** — no handler reads it.
- **Fan-out is synchronous under a write lock.** `NotifyTracker.SendNotification` holds `tracker.Lock()` while doing **blocking sends on unbuffered channels**. MQTT delivery itself isn't the bottleneck — g3api sets `SetOrderMatters(false)` (`src/g3lib/mqtt.go`), so each status message is handled in its own goroutine. The wedge is the **shared tracker mutex**: one stalled subscriber (its writer goroutine not draining its channel) freezes the goroutine holding the lock, and every subsequent status-message goroutine then piles up blocked on `Lock()` — accumulating one stuck goroutine per message. Status delivery freezes system-wide. Backpressure is a latent bug, not a hypothetical, and the fix is to release the lock before sending (Tier 1).
- **No `unsubscribe`, leaky teardown.** The only way to stop a feed is to close the socket. `defer RemoveChannel(...)` sits *inside* the read loop, so re-subscribing accumulates defers and leaks goroutines/channels until the connection ends.

There is also a **misleading comment** at the batch-cancel handler referencing a "WebSocket task channel pipeline" — **no such channel exists.** `G3ScanStatus` carries no `taskid`; task state reaches clients only via DB polling of `/scan/tasks/status`. This is the same **managed-scan reply-consumer gap** recorded elsewhere, and it's Tier 2's hard dependency (below).

So the sequel isn't "add events" — it's "introduce a real subscription protocol," giving the server its first filter-aware registry, lifecycle, and fan-out semantics.

---

## Protocol shape: flat (decided)

**Decided (2026-06-25):** keep the flat `{msgtype, …}` frame rather than introducing a subscribe-envelope with subscription IDs or MQTT/NATS-style topic strings. Rationale: matches the parent's YAGNI posture ("a documented message protocol is enough"); the feed has two event types today and grows to a handful, not hundreds; and the cheapest client migration. The richer shapes were considered and rejected *for now* — see *Forward-looking* for the NATS evolution path the flat shape keeps open.

The consequence: **subscription identity is the `(msgtype, scanid?, taskid?)` tuple itself** — there is no sub-id to cancel, so `unsubscribe` addresses a subscription by re-stating its tuple.

### Wire changes

- **Add `taskid`** to the request frame, alongside the already-present (and finally-activated) `scanid`.
- **Add an `unsubscribe` frame:** `{"msgtype":"unsubscribe","target":"<feed>","scanid":…,"taskid":…}`.
- **Rename events to a consistent dotted scheme (breaking, bundled):**

  | Today | New | Notes |
  |---|---|---|
  | `scanprogress` | `scan.status` | scan-level status updates |
  | `scanremoved` | `scan.removed` | already exists |
  | *(new)* | `scan.created` | push on scan create/start |
  | *(new)* | `task.status` | Tier 2 |
  | *(new)* | `task.removed` | Tier 2 |
  | *(new)* | `log.line` | Tier 3 |

  The rename is breaking, but `g3tui`'s `stream.go` is the only Go consumer and updates in the same change. The Python SDK does not consume `/ws` today. One flag-day, same as the REST migration's logic.

Example frames:

```jsonc
// subscribe to one scan's status
{"msgtype":"scan.status","scanid":"abc"}
// subscribe to one task's status
{"msgtype":"task.status","scanid":"abc","taskid":"t1"}
// unsubscribe (same tuple, addressed by target)
{"msgtype":"unsubscribe","target":"task.status","scanid":"abc","taskid":"t1"}
// event pushed by server
{"msgtype":"task.status","data":{ /* …G3Task… */ }}
```

---

## Server internals (the real work)

The flat wire format is cheap; the server gains its first filter-aware subscription machinery. Three internal shifts:

### 1. Per-channel filters

Each registered channel carries its `(scanid, taskid)` filter. Fan-out matches the filter before delivering, instead of broadcasting to all. This is what activates the dead `scanid` field and adds `taskid`. A no-filter (system-wide) subscription stays legal — it's the dashboard case.

### 2. Per-connection subscription registry

Replaces the leaky `defer RemoveChannel` inside the read loop. The registry tracks a connection's live subscriptions so that:
- `unsubscribe` can find and tear down one subscription without closing the socket,
- the count/overlap limits (below) can be enforced,
- all subscriptions are cleaned up deterministically on disconnect.

### 3. Backpressure fix (the latent bug)

Stop letting a slow client wedge the shared fan-out. Buffered per-subscriber channels, and **never hold the registry lock during a blocking send** (the lock contention above is the actual failure mode, not MQTT serialization). Plus a **per-feed slow-consumer policy**:

- **Status feeds are latest-wins** (`scan.status`, `task.status`) → coalesce / drop-oldest. A subscriber that missed three intermediate progress values only cares about the newest.
- **Log feeds are not coalescible** (`log.line`) → bounded buffer; on overflow, drop with an explicit **gap marker** in the stream (or disconnect the laggard). Exact choice is an open question (below).

---

## Tiers

Outline all, detail the current one. Tier 1 is the entry point; 2–4 are sketched and re-detailed when scheduled.

### Tier 1 — Scan lifecycle *(current / detailed)*

| Event | Source | Notes |
|---|---|---|
| `scan.created` | push from create/start handlers | new; mirrors how `scan.removed` is pushed directly |
| `scan.status` | existing `SubscribeAsAPI` MQTT feed | **managed scans never emit** — `g3scanner` never produces `MSG_STATUS` for a `STATUS_MANAGED` scan |
| `scan.removed` | push from delete handler | already exists (renamed from `scanremoved`) |

- **Filter:** optional `scanid` narrows to one scan; no `taskid` at this tier.
- **No new event source.** Tier 1 is the filter retrofit + `scan.created` + the dotted rename + the backpressure fix. It is the natural first increment because it touches only feeds that already have sources.

### Tier 2 — Task events *(outline)*

- **Events:** `task.status`, `task.removed`, filterable by `scanid` **and** `taskid`. Applies to **managed scans' tasks too** — unlike scan-level status, the tasks of a managed scan *do* produce status updates.
- **Hard dependency — a new event source.** g3api currently subscribes only to scan status (`SubscribeAsAPI`), not worker replies. Live task events require g3api to consume `MSG_RESPONSE` (`SubscribeToResponses`) or a dedicated task-status feed. This **is** the managed-scan reply-consumer gap; closing it is a precursor, not part of the WS work itself. Cross-reference that work when scheduling.
- **Limits (regular scans only):** a small per-socket subscription cap + no overlapping subscriptions (see *Limit gating*). **Lifted for managed scans** — they're machine-driven and the restriction would be counterproductive.

### Tier 3 — Log lines *(outline)*

- **Event:** `log.line`, **per-scan XOR per-task XOR none** — for regular scans, at most **one** live-log subscription at a time (read one scan's logs, or one task's logs within a scan, or none). Exclusive by design to cap traffic. **Lifted for managed scans.**
- **Needs a live log feed.** Logs land in SQL today and are pulled via `GET /scans/{scanid}/logs`. WS adds a live tail; the pull endpoint remains the history/backfill path. The two compose: backfill via GET, then tail via WS.
- **Most backpressure-sensitive feed** — this is the tier that forces the slow-consumer policy to be real.

### Tier 4 — Data / artifacts *(optional / future enhancement)*

- **Events:** `data.inserted` (new `G3Data`; potentially high-volume), `artifacts.ready` (task outputs downloadable; low-volume, rides the task-terminal transition).
- Explicitly **not committed** — listed so the taxonomy is complete. New hooks in the insert / task-completion paths; revisit only if a consumer asks.

---

## Limit gating (decided)

The Tier 2/3 limits need a way to tell "regular" (interactive, e.g. g3tui / a future web GUI) from "managed" (machine-driven) subscriptions. **g3api is internal with a single shared bearer token — there is no per-client identity**, so the distinction cannot key off *who* connects.

**Decided (2026-06-25):** derive it from **what is subscribed to**. A subscription scoped to a specific scan whose status is `STATUS_MANAGED` has its limits **lifted**; system-wide subscriptions and those scoped to regular scans are **enforced**. The managed flag is already the scan's status (`STATUS_MANAGED`, `src/g3lib/mqtt.go`), which g3api already stores and serves — **no new field, no schema migration**, just a status lookup at subscribe time.

**Overlap rule.** A system-wide status subscription overlaps a single-`scanid` subscription of the *same* feed (one is a subset of the other) — reject the redundant one. Two distinct single-`scanid` subscriptions do not overlap. (The single-live-log rule of Tier 3 is a stricter, feed-specific case of the same idea.)

---

## Forward-looking

- **NATS JetStream consolidation** ([`nats-jetstream-consolidation.md`](nats-jetstream-consolidation.md)). Complementary, not conflicting — and it resolves two of this doc's open dependencies. The key boundary: **NATS terminates *at* g3api** (it replaces the upstream bus behind the `mqtt.go` seam — `SubscribeAsAPI` becomes a JetStream consumer), while WS clients sit *downstream* of g3api. The g3api→clients fan-out is always g3api's own job, never the broker's, so the backpressure fix above is substrate-independent and survives the migration untouched.
  - **It supplies the event sources this doc is blocked on.** Tier 2's task-event source *is* the JetStream KV authoritative task state (that doc closes the managed-scan reply-consumer gap there). Tier 3's live-log feed *is* the log stream — and its subject hierarchy maps exactly onto the per-scan-XOR-per-task rule: wildcard `logs.<scanid>.*` = per-scan tail, narrow `logs.<scanid>.<taskid>` = per-task. The flat `(msgtype, scanid, taskid)` filter becomes a NATS subject filter; the wire format is unchanged.
  - **It makes the backpressure fix load-bearing.** Against a *durable* JetStream consumer, g3api defers its ack until processed — so a wedged fan-out would stop acking, hit `MaxAckPending`, and back-pressure the stream itself. Decoupling ingestion from the slow-client fan-out (buffered channels, ack promptly) is what stops WS-client lag from propagating into the bus.
  - **Don't let durability leak downstream.** g3api should be a *durable* consumer upstream but a *lossy* broadcaster downstream. The slow-consumer policy (coalesce status, gap-marker/disconnect logs) is exactly that intended downstream lossiness — a browser is not a durable consumer to redeliver to; it must not inherit JetStream's AckWait/MaxDeliver semantics.
- **AsyncAPI / generated WS clients** — only if/when wanted; the prose protocol in this doc suffices until then. AsyncAPI can `$ref` the OpenAPI schema components so payload types stay single-sourced.
- **Per-subscription authorization / g3bouncer** — out of scope. Under the future internal-API trust boundary (`docs/future/redis-mqtt-and-internal-api-boundary.md`), scoped tokens might gate which scans a connection may subscribe to; today's single shared token makes this moot.

---

## Open questions for when this is scheduled

- **Task-event source** — close the managed-scan reply-consumer gap (consume `MSG_RESPONSE`, or add a task-status feed) before Tier 2. The shape of that source determines `task.status`'s payload and ordering guarantees. The underlying primitive is a persisted `{taskid → inputDataID, outputDataIDs[]}` record; the REST migration's proposed `GET …/tasks/{taskid}/output` is the **pull** view of that same record, and this Tier 2 feed is the **push** view — design the record once (see [`http-routing-and-rest-migration.md`](http-routing-and-rest-migration.md) → *Task input/output*). NATS JetStream KV authoritative task state is one home for it — see *Forward-looking*.
- **Live-log feed mechanism** — how log rows reach g3api live for Tier 3 (tap the write path vs a dedicated feed), and how it relates to the SQL store the pull endpoint reads. (A NATS log stream is the natural answer if that substrate lands — see *Forward-looking*.)
- **Slow-consumer policy specifics** — drop-with-gap-marker vs disconnect for `log.line`; buffer sizes; whether status coalescing is per-`scanid` or per-subscription.
- **Subscription cap value** — the exact per-socket limit for regular scans (a small fixed number; pick at plan time against the real g3tui / web-GUI usage).

---

## Triggers to revisit

Pull from "deferred" into "scheduled" when any of:

1. **A web GUI** (the BFF/web-client direction) needs finer-grained live updates than the current broadcast-everything feed — the primary driver.
2. **The managed-scan reply-consumer gap is closed** for its own reasons — Tier 2's precursor is then already paid for.
3. **The current broadcast fan-out causes a real incident** (a slow client stalling status delivery system-wide) — the backpressure fix in Tier 1 stops being optional.
4. **NATS JetStream consolidation is scheduled** — re-evaluate the filter layer against native subject filtering at that point.
