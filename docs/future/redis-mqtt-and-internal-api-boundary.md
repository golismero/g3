# Coordination Substrate & Trust Boundary — Future Work

> **Superseded (2026-06-14):** the "keep MQTT + drop Redis + build g3bouncer as a separate
> HTTPS gateway" conclusion below is revised by
> [`nats-jetstream-consolidation.md`](nats-jetstream-consolidation.md), where a single NATS
> JetStream substrate fills the bus, coordination, and trust-boundary roles at once. The
> threat model, scope analysis, and "races are a state-machine problem, not a transport
> problem" reasoning here all still hold and carry over.

Discussion notes from an architecture session on 2026-06-09. Triggered by a g3tui bug
(a finished scan's tasks vanishing from the status view) that opened into a broader
review of **what Redis is for**, **whether MQTT is the right bus**, and **where the
security boundaries actually are**.

This is a **watchlist, not a plan** — the complex scenarios it prepares for (untrusted
edge nodes, multi-instance scaling, multiuser) are far off. Captured so the reasoning
isn't re-derived from scratch later. When picked up, write a fresh tiered plan.

**Status: deferred / nice-to-have.** Current deployment contract is single-machine,
single-user, trusted network. None of the below is urgent under that contract.

---

## Part 1 — Coordination substrate: drop Redis, keep MQTT

### What Redis is actually used for (audit)

Exactly two things, using **none** of Redis's distinguishing features (no TTL, no
pub/sub, no atomic structures, no Lua):

| In Redis today | Shape | Belongs in |
|---|---|---|
| `…:metadata` | one JSON string per scan (report config + issue list) | Mongo (co-located with scan data) |
| `…:tasks` + `…:info` | a set + hashes per task (live task state) | a SQL `task_states` table |

It is a plain key-value dictionary. The original author added it a decade ago without a
clear purpose for it (it predates understanding what Redis was for).

### Decision: drop Redis

Move report metadata → Mongo, task state → a durable SQL `task_states` table (indexed by
scanid, like `scan_states` already is). Benefits:

- Deletes `ReconstructTaskStatesFromLogs` and the all-or-nothing Redis-vs-SQL fallback
  (the `len(entries)==0` gate) — i.e. removes the entire class of bug that started this
  session. State stops being something parsed back out of log lines.
- Collapses 3 datastores to 2 (Mongo for documents, MariaDB for relational state + logs).
- Nothing lossy is load-bearing, so "Redis evicted/lost the data" stops being a failure mode.

The worker's `CancelTracker.rejectTasks` (a TTL'd reject-list, the one genuinely
Redis-shaped thing) does **not** save Redis: it's small, per-worker, already a working
local file, and — better — it folds into the SQL `task_states` table. A re-delivered
canceled task is rejected by checking its durable terminal/CANCELED state (exact), not a
time-based heuristic. (Reinforced by the interim "retain task state until scan delete"
fix shipped this session — see bottom.)

### Decision: keep MQTT

MQTT was chosen years ago out of familiarity from an unrelated IoT project, but it turns
out to fit g3's **most distinctive** scaling scenario better than the alternatives:

- v5 **shared subscriptions** are already in use for task assignment (competing consumers).
  Not perfectly load-balanced, but a pentest tool doesn't need instant reactions.
- Current settings: `QoS 2` (exactly-once) + `cleanSession=false` (survives reconnects).
  Delivery is *strong*. `SetOrderMatters(false)` deliberately processes callbacks
  concurrently (to avoid a reply-in-callback deadlock) — so ordering is given up at the
  consumer by choice, which is fine once races are handled at the state-machine layer.
- Genuinely good fit for **segmented / untrusted / flaky-link edge nodes** (pentest jobs
  inside a client network): outbound-from-firewall, keep-alive + last-will death
  detection, low bandwidth, and — critically — **per-topic ACLs give a tiny blast radius**.

### The races are NOT a transport problem

Scenarios like cancel-before-start, or a task-start for an already-canceled scan, are
**fundamental distributed concurrency** — independent events with no causal order. No bus
(MQTT, Redis Streams, Kafka) fixes them. The cure is at the **state-machine layer** and
is transport-independent:

- Monotonic **sequence numbers / logical clocks** + last-writer-wins or conditional
  transitions (the pattern already built for scan status).
- **Idempotent, absorbing transitions**: `CANCELED` can't be un-set; a cancel for a
  not-yet-existent scan writes a **cancel-intent tombstone** the eventual start checks.

**Do this independently of, and before, any bus decision.** It's what actually stops the
bugs, and it makes the MQTT-vs-anything choice a calm infrastructure decision rather than
a bug-driven panic.

### Redis Streams: considered, deferred

Redis **Streams** (not Pub/Sub) is the only serious MQTT alternative — consumer groups,
monotonic IDs, `XAUTOCLAIM` for dead-consumer reclamation. It would subsume the bus +
coordination roles in one substrate, but:

- It does **not** eliminate the fundamental races (see above).
- It's weaker/riskier at the untrusted edge (handing a possibly-compromised node a
  connection into the central coordination store — the opposite of the trust boundary
  in Part 2), with a bigger security surface than scoped MQTT topics.
- It's a rewrite of the core nervous system.

**Revisit trigger:** central task throughput grows until SQL-lease polling is a *measured*
bottleneck. At that point, run Streams **centrally** while keeping **MQTT at the edge**
(hybrid, each idiomatic). Measure first; don't pay for it preemptively.

---

## Part 2 — Trust boundary & the g3bouncer internal API

### The realization

MQTT topic ACLs are security theater while g3worker / g3scanner hold **direct Mongo, SQL,
and shared-filesystem credentials** (plus the Docker socket). You cannot defend one
boundary and leave the others open. Defending MQTT on security grounds *obligates*
threat-modeling the rest.

### Threat model

For a pentest framework the realistic compromise is **the g3worker**: it runs tools
against hostile targets and is deployed into networks you don't control. It is
simultaneously the *most exposed* and (via the Docker socket) *most privileged*
component. **Assume it will be popped.**

Blast radius *today* of one popped worker: **the entire multi-tenant platform** — every
scan's findings (all clients), all logs/state, all artifacts, root on its host, and the
single shared "god-mode" credential. That is the finding.

(The Docker-socket-as-root and god-mode token are both known-temporary single-machine
shortcuts, not load-bearing architecture, and are documented as such. The socket is a
devops concern — the code only needs `docker` to work; DinD / sandboxed docker server /
ephemeral VMs all satisfy it. Not an architectural problem.)

### Target boundary: core vs edge, one gateway

```
   CORE (trusted)                     EDGE (untrusted)
   g3api  ── sole DB/FS-facing        g3worker / edge g3scanner
   g3bouncer ── internal gateway      - NO db/fs credentials
   Mongo / SQL / FS                   - API + MQTT clients only
        ▲  ▲                             │ MQTT (control, scoped ACL)
        └──┴───────────────────────────  │ HTTPS (data, scoped token)
```

Principle, one sentence: **g3api + g3bouncer are the only components that touch the
datastores; everything on the execution edge is a scoped API + MQTT client holding no
database credentials.**

**g3bouncer** (this session's name for the internal, node-facing API; distinct role from
the user-facing g3api) is the **single authorization chokepoint**. Do **not** add a
permission layer to each backend — that multiplies checkpoints and chances to get it
wrong. One gate, governed by **one scope model** (a SQL table). This is the move that
turns "rewrite five access layers" into "build one thin gateway over existing g3lib ops."

### Claim-check pattern (resolves the original snag)

Direct Mongo access was originally allowed because Mosquitto choked on large data-object
payloads. The correct fix is the **claim-check pattern**, which also fixes the boundary:

- **MQTT carries control only** — small messages (`dispatch{taskid, scanid, tool, ref}`,
  `cancel`, `status`). References, not payloads. Mosquitto stays in its comfort zone.
- **g3bouncer carries data** — nodes fetch inputs and submit results/artifacts over
  authenticated HTTPS. The machinery already exists (`UploadFile`/`DownloadFile` in
  `g3lib/api.go`).

### Token system: opaque tokens in SQL, not JWT

- **Instant revocation** is the clincher — scoped tokens live in hostile territory and
  must be killable *now*: `DELETE` the row. JWT revocation needs a blocklist (a DB lookup),
  defeating its only advantage. (Hand-rolled JWT was already tried once and dropped as
  needlessly complex.)
- **Scales fine**: keep the gateway **stateless**, all state in shared SQL/Mongo; run N
  instances behind a VIP. That — not JWT's decentralization — answers the SPOF worry.
- Middleware is trivial: `bearer → SELECT scope WHERE token=? AND expires>now → context`.

### Scoping

- Floor: **per-scan**. Target: **per-task** (`{scanid, taskid}`) — smaller blast radius
  (a popped worker sees only its current task's data), nearly free with the gateway
  (insert token on dispatch, delete on completion), and aligns with task artifact-slot
  isolation.
- **God-mode = the unscoped token**, used against the *same* g3bouncer path, enabled only
  when explicitly turned on for local/dev. One code path; scope is the only variable.
- Tenants: deferred (feels premature).

### The five backends, through the gate

| Need | Approach |
|---|---|
| **Logs** | Write-only `POST /…/logs`, scope-checked, SQL-backed (nodes never read them back). |
| **State coordination** | Endpoints applying the seq-number/LWW logic **server-side in g3bouncer**; nodes assert transitions, the gate enforces monotonicity. |
| **Mongo objects** | **App-layer scanid scoping in g3bouncer, not Mongo-native** (Mongo RBAC has no document-level ACL without per-scan DBs/collections — not worth it). Expose only the few concrete plugin-contract ops, not a general Mongo-query proxy (narrow surface). |
| **Artifacts** | **HTTP up/download at the gate + a *local* bind-mount for plugins.** Plugins keep a dumb local dir (no FUSE, no transport awareness); the worker uploads results scoped by token, then wipes. Central store (FS/S3/…) deferred to devops behind the gate. Avoid a shared mount to the core for untrusted nodes. |
| **MQTT** | Stays. Dynamic per-scan ACLs via **mosquitto-go-auth (HTTP/SQL backend)** reading the *same* scope table — no broker swap needed (EMQX is a fine later upgrade). |

Note the unification: logs/state/MQTT all read the **same SQL scope table**; the HTTP
backends share the **same auth middleware**. One scope model, one chokepoint — not five
security systems.

### One data path — don't fork the worker

"g3worker as-is for trusted, g3bouncer for untrusted" looks scope-reducing but isn't —
two data-access code paths is a permanent maintenance tax and two security models. Route
**all** workers through g3bouncer; trusted vs untrusted is only a difference of **network
placement + token scope**. Defense-in-depth applies uniformly.

---

## Scope verdict & the hinge

Bounded, **not a rewrite**: a thin gateway (mostly re-homing existing g3lib ops behind one
auth check) + a token/scope table + rewiring the worker's known data call-sites + an MQTT
auth backend. The operations already exist; the work is putting one gate in front of them
and deleting the workers' DB credentials.

**The single decision that sizes everything: how real is the genuinely-untrusted edge node?**

- *Trusted-only* (workers VPN into a trusted segment) — **current contract**. The network
  is the boundary; at most do the data-plane API for hygiene; **defer tokens/ACLs**.
- *Genuinely untrusted* (worker in a client DMZ) — the full scope/token/dynamic-ACL stack
  is mandatory, and clearly worth it (nothing else contains a compromised pentest node).

Today: trusted-only. So ~70% of Part 2 is nice-to-have, deferred.

---

## Interim changes shipped this session (context)

Two small fixes for the triggering g3tui symptom, independent of the above direction:

1. `g3lib.MakeApiRequest` now accepts the whole **2xx** range (was `== 200`), so the
   `202 Accepted` from async dispatch stops surfacing as "Failed to load report: 202
   Accepted." (See the status-code note in `http-routing-and-rest-migration.md`.)
2. Task-state Redis keys are **retained until scan delete** (the terminal-cleanup defer
   was removed), fixing tasks vanishing when a report is dispatched on a finished scan.
   This is an interim correctness fix; the durable answer is the SQL `task_states` table
   in Part 1, at which point the retained-Redis behavior and its TODO go away.

---

## Cross-references

- `docs/future/http-routing-and-rest-migration.md` — the user-facing g3api REST migration;
  the internal/external API split here is the companion to that. The status-code-contract
  subsection there overlaps with the 2xx fix above.
- Architectural-direction context: g3api becoming internal-only with a future BFF assumed
  a single trusted network + single shared credential. **The untrusted-edge ambition
  contradicts that assumption** — per-principal scoping is what resolves it. Pin "trusted
  segment + VPN" vs "genuinely untrusted edge" as the contract before building Part 2.
