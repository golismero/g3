# NATS JetStream as the Consolidated Substrate — Future Work

Discussion notes from an architecture session on **2026-06-14**. Triggered by a concrete
bug — managed tasks being executed by *two* workers at once — which opened into a deep
review of MQTT's delivery internals and, from there, into the question of whether a single
substrate could replace the message bus, the coordination store, **and** the internal
trust boundary at once.

This is a **design direction / watchlist, not a committed plan.** The only thing *shipped*
this session is the one-line bug fix (below). Everything else is captured so the reasoning
isn't re-derived later. When picked up, write a fresh tiered plan.

**Status: deferred.** Current deployment contract remains single-machine, single-user,
trusted network. None of the below is urgent under that contract — but it is the most
*consolidating* direction we've found, and it **supersedes the conclusions of**
[`redis-mqtt-and-internal-api-boundary.md`](redis-mqtt-and-internal-api-boundary.md)
(which concluded "keep MQTT, drop Redis, build g3bouncer as a separate HTTPS gateway").
NATS JetStream is a single mechanism that does all three roles.

---

## 0. The bug that started it (SHIPPED)

Managed `testssl` task ran on two workers simultaneously, then both mutually cancelled →
surfaced as CANCELED in the client. Root cause: `SubscribeAsDispatcher` subscribed to the
**plain** `dispatch` topic, not a shared subscription. With `g3scanner` at `replicas: 2`,
every dispatch fanned out to *both* scanners, each forwarding the task to a worker.

**Fix (shipped):** added `G3DISPATCHSUBTOPIC = "$share/g3scanner/dispatch"`; the dispatcher
now subscribes to (and returns) the shared topic. Publish side stays on the plain
`G3DISPATCHPUBTOPIC = "dispatch"` (you cannot publish to a `$share/` address). Mirrors the
existing `$share/g3scanner/scan` vs `scan` split. See `src/g3lib/mqtt.go`.

This fixes the *fan-out*. Two latent issues remain (and motivate the rest of this note):

1. **Mutual-cancel friendly fire.** Workers don't arbitrate task ownership; the cross-worker
   "I handled this" broadcast (`SendTaskCancelHandled`) doubles as a *completion* signal, so
   the first finisher's broadcast triggers `ForgetTask → cancel()` on a peer still running
   the same task. The `cancel` topic conflates three events (please-cancel / I-cancelled /
   I-finished) behind one `Handled` bool.
2. **No idempotency guard.** `dispatchHandler` forwards unconditionally; `SetTaskDispatched`
   is a blind overwrite. A redelivered dispatch → another duplicate run.

Both are facets of one absence: **no single authoritative, idempotent "this task is
claimed" record.** Correctness rests entirely on the broker delivering exactly once.

---

## 1. Why MQTT is the wrong *grain* for this job

MQTT is a pub/sub telemetry protocol; g3 uses it as a work queue. The friction is the
friction of the wrong-shaped tool. Findings, all verified this session against code/docs:

- **We are on MQTT 3.1.1, not v5.** `github.com/eclipse/paho.mqtt.golang v1.5.1` maxes out
  at protocol level 4 (`net.go` CONNECT builder has no `case 5`). Shared subscriptions work
  anyway because `$share/` is a **mosquitto broker extension** honored for 3.1.1 clients —
  it's a topic-filter *string*, needs no client protocol support. (Past-Mario likely tried
  the then-immature `paho.golang` v5 client, found it unusable, and built on the mature
  3.1.1 client + the `$share` trick. A decade later this was misremembered as a v5 stack.)

- **The "flow control" is emergent, not designed.** With `SetOrderMatters(false)` paho runs
  one goroutine *per message* (`router.go`) — work is already concurrent, never serial. The
  comment "Call the task handler synchronously… prevents receiving more tasks" (`mqtt.go`)
  is **wrong about the mechanism**: throttling comes from the broker's in-flight window
  (mosquitto `max_inflight_messages`, default 20) because paho defers the ack (PUBREC) until
  the handler returns (ack-on-success). So in-flight count == running tasks, by accident.

- **Ack-on-success does double duty, and both duties are load-bearing:** (a) retry-on-crash
  (un-acked until done → worker dies → broker redelivers) and (b) backpressure (in-flight
  window caps concurrency). They're inseparable — which means **(a) is the same mechanism
  that causes duplicate concurrent runs on a transient disconnect.** The un-acked window ==
  the whole (minutes-long) task duration; any disconnect/crash in it can redeliver, and with
  a shared subscription the retry can land on a *different* worker.

- **Exactly-once *delivery* is impossible** (protocol ACK ≠ application completion). MQTT
  gives at-least-once at best; the floor. Worse, MQTT 3.1.1 has **no dead-letter queue and
  no max-redelivery count** — a poison task that kills its worker redelivers forever. And
  redelivery is an **unsafe, unbounded, undifferentiated retry policy** for a domain where
  re-running can be the *harmful* action (invasive tests, exploits, brute-force). A failed
  task is a *result*; retry should be an explicit, bounded, per-tool decision — which the
  transport cannot express. (Mitigating note: a *tool* failure is already caught, marked
  ERROR, and acked — no cascade; the poison case is only a *worker-process* death mid-task.)

- **Per-client concurrency isn't reachable in 3.1.1.** `max_inflight_messages` is
  broker-global. A worker-side semaphore doesn't help: with late-ack it's redundant with the
  in-flight window; with early-ack it relocates the queue into volatile worker memory (tasks
  die with the process) — reinventing the queue, badly. v5's per-client Receive Maximum
  would fix it, but that means a different library anyway.

**Conclusion:** if a transport rewrite is on the table regardless, spend it on a protocol
that fits the job natively — not a newer version of one that doesn't.

---

## 2. Candidate evaluation — NATS JetStream wins

| Requirement (surfaced this session) | MQTT 3.1.1 | MQTT 5 | RabbitMQ | NATS JetStream |
|---|---|---|---|---|
| Work distribution to a pool | `$share` (bolted on) | `$share` | native queue | native consumer group |
| Per-consumer concurrency cap | ❌ global only | Receive Max | `basic.qos` | `MaxAckPending` |
| Ack *after* processing | PUBREC trick | PUBREC trick | default idiom | explicit ack + AckWait |
| Bounded retry / dead-letter | ❌ | ❌ | DLX + x-death | MaxDeliver → DLQ |
| Per-message TTL (kill stale invasive tasks) | ❌ | Msg Expiry | per-msg TTL | stream MaxAge / TTL |
| Independent control channel | separate conn | separate conn | separate queue | separate subject |
| TLS / mTLS / ACLs | ✓ | ✓ | ✓ + vhosts | ✓ + accounts |
| Multi-host HA | add-ons | add-ons | quorum queues | native clustering |
| **Built-in KV store (claim store)** | ❌ | ❌ | ❌ | **✅ JetStream KV** |
| **Go client w/ auto-reconnect** | ✓ | ✓ | ❌ (DIY/wrapper) | ✅ (Go-native) |

**RabbitMQ** is a textbook work-queue fit and now mature, BUT its official Go client
(`rabbitmq/amqp091-go`) **deliberately does not implement auto-reconnect** — you own it or
trust a wrapper. For a fleet of workers on flaky links holding long-lived connections, that
reconnection logic is exactly the correctness-critical wheel we don't want to reinvent —
which was MQTT's original selling point. RabbitMQ also has **no KV store**, so the claim
store stays a separate system.

**Kafka:** wrong shape (offset/partition model, no per-message selective redelivery, heavy
ops). Rejected.

**NATS JetStream** is the winner — and by a lot — because it's the only option that
**consolidates** rather than just swaps:
- Server and client both Go-native; client has robust built-in reconnection.
- `jetstream` package (`nats.go/jetstream`, the current recommended API) gives streams,
  pull/push consumers, explicit ack, `MaxAckPending`, server-side publish dedup.
- **JetStream KV** is the atomic claim store: `Create` = create-if-absent (SETNX), `Update` =
  compare-and-set via revision, bucket TTL = automatic claim expiry. Built on streams,
  **file-backed = durable** (or memory-backed if you want ephemeral). A real KV database, not
  RAM-only like Redis — durability is per-bucket choice.

---

## 3. Verified NATS facts (so they aren't re-derived)

- **Payload:** `max_payload` default **1 MB**, configurable to **64 MB** (8 MB recommended).
  Regular stream messages are **not** auto-chunked. **ObjectStore** *does* chunk arbitrary
  sizes (separate key/blob API, file-backed). → Send normal G3Data inline (bump max_payload
  to ~8 MB); huge results via ObjectStore. "Payload size becomes *manageable*, not
  irrelevant — pick the right door."
- **Persistence:** file storage + a mounted volume → streams, consumer state, and pending
  un-acked messages survive a server restart. A broker restart becomes "a flurry of TCP
  reconnections," not orphaned tasks. (This is JetStream's reason to exist; it replaced the
  old NATS Streaming/STAN.)
- **Dedup:** `Nats-Msg-Id` is an **arbitrary client-chosen string**; server dedups on it
  (never the body) within a **time window (default 2 min, per-stream configurable)**. → Use
  `taskid` as Msg-Id for *task dispatch* (a content hash would wrongly swallow a legitimate
  re-dispatch of identical data); use a content hash for *idempotent data ingestion*. The
  window is a near-term guard; the **KV `Create` claim is the durable backstop**.
- **KV durability:** persistent (file-backed) or ephemeral (memory) per bucket. Many buckets
  per server. Multi-tenancy via **scanid-in-the-key + subject permissions**, NOT bucket-per-
  scan (each bucket is a stream; practical ceiling ~2k HA assets — don't explode streams).
- **Streams as log store:** Limits retention with no MaxAge = durable long-term (disk-bound).
  Subject filtering + replay by seq/timestamp. **Not a query engine** (no WHERE/JOIN/agg/
  search). Fine for "replay this scan's/task's lines in order"; cross-scan analytics needs a
  real store (which can be a *consumer* that ships the stream onward — deployment change, not
  code change).
  - **Both current log views are preserved** — logs are partitioned by **subject**
    (`logs.<scanid>.<taskid>`) within **one** stream, *not* one stream per task. Per-task =
    narrow filter `logs.<scanid>.<taskid>`; **per-scan = wildcard `logs.<scanid>.*`**, which
    returns the scan's lines interleaved across tasks in stream-sequence (arrival) order —
    reproducing today's behavior (current SQL: `… WHERE scanid=? [AND taskid IN …] ORDER BY
    timestamp, id`, `mysql.go`, where `timestamp` is *insert-time at 1-sec granularity*). So
    the move is strictly more flexible, not a forced regression to per-task grouping. Stream
    order ≈ today's insert-time order; for exact line-generation ordering, embed a real
    timestamp in the payload and sort client-side (not cleanly possible today either).
- **PoC is trivial** — one service replacing both mosquitto and redis:
  ```yaml
    nats:
      image: nats:latest
      command: ["-js", "-sd", "/data"]   # -js enable JetStream, -sd store dir
      ports: ["4222:4222", "8222:8222"]  # clients, monitoring (/healthz, /jsz)
      volumes: ["./volumes/nats:/data"]
      restart: unless-stopped
  ```

Sources: docs.nats.io (FAQ payload, jetstream streams/KV/objectstore, model_deep_dive),
pkg.go.dev/github.com/nats-io/nats.go/{jetstream,micro}, github.com/rabbitmq/amqp091-go
(reconnect note), nats-server discussions (stream scaling).

---

## 4. Target architecture

```
            ┌──────────────────────── NATS JetStream (single TCP port, TLS) ───────────┐
   workers  │  streams        : task dispatch / responses / report tasks (the bus)      │
   ──TLS──▶ │  KV (durable)   : task-claim (Create=claim), scan/task state (g3bouncer-  │
   one conn │                   authoritative; retires Redis + SQL task_states)         │
            │  KV (memory)    : ephemeral coordination / cache if needed                │
            │  streams (log)  : worker log lines (retires the direct-SQL log hack)      │
            │  ObjectStore    : large G3Data blobs                                      │
            │  request-reply  : g3data service (micro) — SOLE Mongo-facing component    │
            └───────────────────────────────────────────────────────────────────────────┘
                                          │ (only g3data holds a Mongo connection)
                                       MongoDB  ── stays: queryable document system-of-record
```

- **g3data = g3bouncer, realized.** A `nats.go/micro` service (named/versioned endpoints,
  built-in discovery + stats), run as a **queue group** of N replicas (load-balanced, no
  SPOF). It is the *only* component holding a Mongo connection. Workers `Request()` on
  **constrained, vetted** subjects (`data.get.<scanid>`, `data.find.<type>`,
  `data.put`); they hold **no Mongo credentials and have no route to Mongo**.
- **The dedup fix & mutual-cancel both dissolve:** publish dispatch with `Nats-Msg-Id =
  taskid` (server drops the double), and claim via KV `Create` (loser drops cleanly — no
  run, no cancel broadcast). The conflated `cancel` topic and `CancelTracker` friendly-fire
  go away; cancel becomes a direct message to the claim owner.
- **Retry becomes explicit & bounded:** consumer AckWait + MaxDeliver → DLQ; per-tool retry
  policy (passive tools retry; invasive/exploit tools do not) lives in metadata, not the
  transport. Stale tasks die via stream MaxAge / message TTL.

---

## 5. Security model & the red-team threat case

NATS auth and TLS are **separable layers** and can be **fused**:
- TLS-only-to-connect: cert gates the *connection*; identity established separately (a
  generic internal node behind a cert wall).
- Fused (mTLS, `verify_and_map`): the cert **is** the credential → pins a worker to one
  account, cannot switch. Chain is **cert → user → account**: the cert authenticates the
  *user* (connection identity); the *account* is the namespace that user belongs to.
- Auth options: token, user/pass (bcrypt), NKEY (Ed25519 challenge), decentralized JWT.
- **Accounts = isolation boundary** (independent subject namespaces); **subject permissions
  = fine-grained ACL within**. Per-tenant = account-per-tenant; per-scan hardening =
  subject/key prefixes + perms.

**Threat model (the payoff).** On-prem red-team node (Raspberry Pi behind a couch, single
egress). With Mongo behind g3data over request-reply:
- Worker holds only its NATS creds, one outbound TLS connection, **no DB creds, no DB route**.
- A popped device yields only the ability to publish *vetted* requests on *its* subjects —
  no arbitrary Mongo access, no lateral movement, no reach into other accounts.
- **Per-tenant isolation holds**: cracking one client's device cannot reach another's data.
  "They see what we're doing on this job, but can't hack us back or reach other clients."

This is **g3bouncer**, achieved via NATS request-reply instead of a separate HTTPS gateway —
absorbing Part 2 of the predecessor note.

---

## 6. Honest costs & caveats (the trade is real)

1. **You're designing an API, not moving a connection.** A vetted, fixed operation set —
   NOT an "arbitrary Mongo query" proxy (that moves the connection but adds **zero**
   boundary). The constraint *is* the security benefit; it's also ongoing API-surface work.
   Aligned with the BFF/g3bouncer goal, not pure overhead.
2. **Authorization must be per-request, or it's theater.** A worker may only fetch data for
   scans it's authorized for (subject scoping + g3data validation). A generic "find anything"
   subject is security cosplay.
3. **Reads vs writes.** Core request-reply is at-most-once → fine for idempotent reads
   (retry on timeout). Writes are **immutable inserts keyed by `_id`** (objects are never
   mutated), so they're naturally idempotent — a redelivered insert is a no-op on the
   duplicate `_id`, no CAS needed. For durability of the write itself, route via JetStream.
4. **A latency hop** (NATS + service vs. direct driver). Negligible at g3's coarse per-task
   grain; hot reads can be cached in KV.
5. **The exactly-once-*processing* floor remains.** No broker removes it — but `Nats-Msg-Id`
   dedup + KV `Create` shrink the residue to "set an id, claim a key."
6. **Migration is a transport rewrite behind the `mqtt.go` seam** (the `MessageQueueClient`
   type + `SubscribeAs*`/`Send*` funcs are already a transport abstraction — reimplement
   behind it, don't rewrite g3). Plus the ops change.
7. **JetStream persistence is younger** than mosquitto's decade-old engine; the accounts/JWT
   security model has a learning curve (start with config-file accounts + mTLS).
8. **Mongo stays.** KV/ObjectStore/streams have no secondary indexes or ad-hoc queries;
   report generation needs document queries. Mongo is the lone, justified survivor.

---

## 7. The consolidation tally (why this is the goldmine)

| Today | NATS JetStream | Verdict |
|---|---|---|
| mosquitto (MQTT bus) | streams + consumers | ✅ replace |
| Redis (coordination / cache) | KV | ✅ replace |
| MariaDB (log lines) | streams (append log) | ✅ replace (no cross-scan querying) |
| MongoDB (queryable scan data) | — (behind g3data) | ❌ stays |

**One Go-native binary** absorbs: the MQTT-vs-Redis question, the atomic claim store, the
duplicate-delivery fix, the mutual-cancel friendly-fire, bounded/safe retry, the SQL-log
decoupling, the Mongo-isolation security win, **and** g3bouncer (the internal trust
boundary) — collapsing several scattered future directions into one mechanism. Three of four
backing services + the bus → one. Mongo is the sole survivor, behind the gate.

---

## 8. Phased migration (outline only — detail when picked up)

Tiers outlined; revisit with a fresh detailed plan before starting each.

- **Tier 0 — Spike (PoC).** Single-node NATS in compose; model one tool dispatch as a
  stream + pull consumer with `MaxAckPending`; implement the task-claim as KV `Create`. Goal:
  *feel* the API + ops before committing. No production wiring.
- **Tier 1 — Bus swap behind the seam.** Reimplement `mqtt.go`'s `SubscribeAs*`/`Send*` over
  JetStream; task dispatch/response/report on streams; `Nats-Msg-Id = taskid` dedup. Keep
  Mongo/SQL access direct for now.
- **Tier 2 — Authoritative task state in KV.** Move scan/task state + the claim to KV;
  delete `ReconstructTaskStatesFromLogs`, the Redis fallback, and the `CancelTracker`
  friendly-fire. Retire Redis.
- **Tier 3 — Logs over streams.** Workers publish log lines to a stream; retire the direct
  SQL log table (MariaDB gone, unless kept for other relational needs). Optional consumer →
  specialized log store (deployment-only).
- **Tier 4 — g3data gateway.** Stand up the `micro` request-reply service as the sole
  Mongo-facing component; rewire worker data call-sites; delete workers' Mongo credentials.
  This is the trust boundary; gate it behind the "untrusted edge" decision.
- **Tier 5 — Security hardening.** mTLS + accounts + per-scan/per-task subject scoping;
  per-tenant accounts. Bounded/per-tool retry policy via DLQ + metadata.

**The hinge (unchanged from the predecessor note):** *how real is the genuinely-untrusted
edge node?* Trusted-only (current contract) → Tiers 0–3 are the hygiene/consolidation win;
Tiers 4–5 are deferred. Genuinely untrusted (client DMZ / red-team drop) → Tiers 4–5 become
mandatory and clearly worth it.

---

## Cross-references

- [`redis-mqtt-and-internal-api-boundary.md`](redis-mqtt-and-internal-api-boundary.md) —
  **predecessor; this note supersedes its "keep MQTT + HTTPS g3bouncer" conclusion.** Its
  threat model, scope analysis, and the "races are a state-machine problem, not a transport
  problem" point all still hold and carry over.
- [`mqtt-delivery-future-work.md`](mqtt-delivery-future-work.md) — the MQTT delivery-hardening
  watchlist; **largely absorbed** if the bus moves to JetStream (durable streams = the durable
  outbox; `AckWait`+`MaxDeliver`→DLQ = crash detection; KV = authoritative state). What
  carries over transport-independently: per-plugin runtime data (to size `AckWait`/timeouts)
  and an **orphan plugin-container janitor** (a dead worker leaves its container in dockerd
  regardless of bus).
- Managed-scan reply-consumer gap — the missing persisted task-result model *is* the KV
  authoritative state here; this closes that gap.
- [`websocket-event-protocol.md`](websocket-event-protocol.md) — the WS event-expansion
  sequel **consumes** this substrate: its Tier 2 task-event source is the KV authoritative
  task state, and its Tier 3 live-log feed is the log stream (`logs.<scanid>.<taskid>`),
  whose subject hierarchy maps directly onto the WS per-scan/per-task filter. NATS terminates
  at g3api; the g3api→client fan-out (and its backpressure handling) stays g3api's job
  regardless of substrate.
