# Knife ⇄ Golismero Integration — Design & Roadmap

> Status: design notes, 2026-06-03. Captures a long design discussion between
> the Golismero author and a Knife working session. This document lives in the
> **Golismero** repo because the immediate work is Golismero-side (refactor the
> Python client; optionally add a Magenta endpoint). The Knife-side work is
> summarized here as external context so it can be resumed in a fresh session.
>
> Companion docs:
> - Magenta: `docs/g3-integration-discussion.md`, `docs/data-model-comparison.md`
> - Knife: `docs/design-decisions.md` §10 "g3 (Golismero) Tool Bridge"

---

## TL;DR — what to do next

In order:

1. **Refactor `g3client` into a thin, agnostic g3api client.** Delete the
   `g3client.llm` policy layer (multiton, `run()`, `DATA_PRIMER`, `bind`). Keep
   the protocol-correctness layer. One method per g3api endpoint; no hidden
   polling; no global state. See §5.
2. **(Quick win) Add an on-demand g3api endpoint to run Magenta against a
   task's artifacts** and return structured issue objects. Near-zero Golismero
   change; unblocks Knife's first deliverable. See §4.2.
3. Bring the new thin client back to the Knife session and build the **SSL
   Analysis vertical slice** (testssl → Magenta → issues → Knife findings). See
   §7.
4. Later: **auto-process artifacts with Magenta per task** and retire
   Golismero's built-in reporting (§4.3); then the **deep Magenta/G3Data
   merge** (§4.4).

---

## 1. Context & goals

Golismero's integration with Knife is meant to fill two gaps:

1. Let Knife's LLM agents call security tools **off-process**, with a
   **normalized I/O contract**.
2. Let tool execution **scale horizontally** — which Golismero already provides.

Knife is an AI web-app security platform: it captures HTTP traffic, and a fleet
of LLM agents analyze it for vulnerabilities and emit structured findings.

## 2. The core realization (the inversion)

The first integration attempt (`g3client.llm`) was built on a wrong assumption:
that Golismero tools would be called like Knife's existing tools — synchronously,
inline, with the agent reasoning on the result mid-conversation.

That is backwards. Two facts force the inversion:

- **Knife's agents are already fast, inline, HTTP-level probers.** A survey of
  Knife's ~41 agents found ~38 reason inline on each tool result, but every one
  of them operates at HTTP-request granularity (seconds per call). **None calls
  a long-running scanner.** There is no existing inline loop for a 10–15 minute
  g3 tool to slot into.
- **Golismero's tools are categorically the *other* kind** — long-running,
  off-process, horizontally scaled (testssl ~10 min, nmap ~15 min). They belong
  to an **asynchronous enrichment / confirmation** lane, not a reasoning loop.

Concretely, Knife runs agents on a **3-thread pool** (`ROUTE_EXECUTOR`,
`max_workers=3`) and caps any single tool call at **300 s** in two places. A
blocking 15-minute call would (a) blow the cap and (b) starve the pool — three
concurrent scans freeze the orchestrator. So **Golismero must never be awaited
inline by an agent.**

**Conclusion:** Knife owns all LLM/agentic orchestration. Golismero is an
**asynchronous, scalable tool-dispatch + execution layer**. The agentic
assumptions baked into `g3client.llm` should move out of the library and onto
Knife's side (where Knife wants them) or be dropped.

## 3. Architecture decisions

### 3.1 Division of responsibility

| Concern | Owner |
|---|---|
| LLM agents, reasoning, triggers, finding model | **Knife** |
| Scan lifecycle (create/persist/dispose per host) | **Knife** (using the thin client) |
| Task dispatch, polling, result/artifact retrieval | **Knife** (the thin client is the transport) |
| Off-process tool execution + horizontal scaling | **Golismero** |
| Issue parsing / structured reporting | **Magenta** (run by Knife, or by g3 — see §4) |

### 3.2 Drop `g3client.llm` → thin agnostic client

The `.llm` submodule conflated *transport* with *policy*. Split them:

**Keep (protocol correctness — genuinely reusable):**
- the `{status, data}` envelope parser;
- the streaming artifact download;
- the **zip-slip-safe** archive extraction;
- `Content-Disposition` filename handling.

**Drop (policy — belongs to Knife, or is obsolete):**
- the `Client` **multiton** (`__new__`/`_instances`, `bind`/`unbind`/`keys`);
- **eager scan creation** in the constructor;
- **`run()`** — the convenience wrapper that hides dispatch + polling +
  multi-task fan-out + state aggregation. Knife wants those primitives exposed,
  not hidden.
- **`DATA_PRIMER`** (an LLM prompt — pure Knife concern);
- the `RunResult` aggregation policy.

The result is a stateless binding: construct with `(base_url, token)`, one
method per endpoint, returns parsed data, never blocks on task completion.

### 3.3 Async-everything execution model

Knife consumes Golismero through one generic pipeline:

```
trigger → build g3 input → dispatch (returns task_ids, no wait)
        → [single poller advances a MySQL state machine]
        → on terminal: fetch results + artifacts
        → apply handler → ingest as findings/events / trigger follow-up
```

- **Never assume a tool is fast.** Every tool is launched and left; a single
  background poller (modeled on Knife's existing Interactsh/OOB poller) finds
  completions. One poller suffices to consume all results.
- **MySQL is the source of truth** (a Knife principle). The poller rebuilds its
  in-flight set from non-terminal rows on restart; state is never only in memory.
- **Do not resume the live agent.** When results arrive, write them as Knife
  events/findings (with provenance) and let the normal pipeline spawn a *fresh*
  agent if a follow-up is needed. Live-conversation resumption is fragile and
  restart-unsafe; Knife agents already hydrate context from the DB.

### 3.4 Integration granularity = G3Data **type**, not tool

This is the key to avoiding "one bespoke integration per tool":

- Golismero normalizes tool output into typed G3Data (`issue`, `host`, `url`,
  `service`, …). Many tools emit the same types. So Knife maps a handful of
  **types**, not N tool formats — this is integration goal #1 actually paying
  off.
- A **default type-based handler** gives every g3 tool zero-config coverage
  (any `issue` → a generic finding; `host`/`service` → host enrichment).
- Per-tool work becomes **opt-in polish** (richer templates, dedup keys,
  confirmation-tool input). The marginal cost of the Nth tool is low, often zero.

> Golismero lever: the more **structured and machine-readable** the issue
> metadata (a stable category/template id, not free-text titles), the more of
> Knife's mapping stays config instead of code. This is exactly what the Magenta
> direction provides.

## 4. Magenta integration

### 4.1 What Magenta is, and the data-model contrast

Magenta is a later, narrower-scope offshoot of Golismero: **issue reporter
only** — no tool execution, pipelines, or scaling. It has **file parsers** and
**issue templates** (already including a `testssl` parser and a
`multiple_ssl_issues` template with per-cipher severities, an SSL-Labs grade,
grade caps, client simulations, JSON schema, and localized Markdown).

Data-model difference (see Magenta `docs/data-model-comparison.md`):

| | Golismero | Magenta |
|---|---|---|
| Schema | deliberately schema-less | **rigid JSON schema per template** |
| Issue identity | tied to the **producing plugin** | **decoupled** from the tool |
| Cross-type info passing | cross-type **conventions** | formalized, schema-backed |
| Mergers | **per-plugin** | **per-template** |

Magenta's structured, tool-decoupled issues are strictly better for Knife's
finding model than Golismero's primitive, tool-tied issues. The long-term plan
(§4.4) is to converge Golismero onto Magenta's parsers + schemas.

### 4.2 Near-term option A (do first): on-demand Magenta endpoint per task

Add a g3api endpoint that runs Magenta against the artifacts of a given
`task_id` and returns the structured issue objects (JSON).

- **Why first:** additive, practically no Golismero change, fully Knife-driven,
  lowest risk. It unblocks the SSL demo immediately.
- **Shape:** `POST /scan/task/magenta {scanid, taskid} → issues[]`. Magenta
  parsing is fast (seconds), so a **synchronous** endpoint is fine — no extra
  poll cycle. (If uniformity with the task model is preferred later, it can be
  promoted to a dispatched task.)
- **SSL demo flow it enables:** dispatch testssl → poll to done → call
  `/scan/task/magenta` → receive structured SSL issues JSON → Knife maps to
  findings.

### 4.3 Near-term option B (do next): auto-process artifacts + retire built-in reporting

Today Golismero has its own built-in reporting **and** can optionally run
Magenta against the whole artifact directory for a Markdown report. Replace both
with: **auto-run Magenta per task on that task's artifact slot, producing issue
objects** attached to the task.

- **Why second:** it *removes* existing behavior (higher risk) and is best done
  after option A has validated the Magenta-as-parser path.
- **Per-task, not per-scan:** processing each task's artifacts (not the whole
  scan dir at the end) matches Knife's per-task polling grain.
- **Accepted cost:** artifacts get read twice (Golismero parses output for
  assets; Magenta re-parses for issues). Wasteful but far simpler than a full
  merge. Eliminated in §4.4.

### 4.4 Long-term: drop the g3 `issue` type; Magenta-native G3Data

The roadmap end-state (large, separate effort):

- **Drop Golismero's `issue` data type**, replace with a G3Data-adapted Magenta.
- **Reuse all of Magenta's parsers** (drop Golismero's, almost entirely).
- **Add true G3Data support to Magenta** (or wrap it) so parsers produce not
  just issues but **assets** too (Golismero needs `host`/`url`/`service`/…).
- **Tighten schemas + formalize the cross-type conventions** in a
  machine-readable form (this is also the §3.4 lever for Knife).
- Single parse per artifact (eliminates the §4.3 double-read).

## 5. The thin g3client refactor (tomorrow's main task)

Expose one method per g3api endpoint; let Knife own scan lifecycle, polling, and
aggregation.

Endpoints to surface (from current `client.py`):

| Method | Endpoint | Notes |
|---|---|---|
| `scan_create()` | `POST /scan/create` | returns scan_id; **not** eager — Knife calls it |
| `scan_delete(scanid)` | `POST /scan/delete` | |
| `target_add(scanid, targets[])` | `POST /scan/target/add` | returns data ids |
| `data_get(scanid, dataids=… | taskid=…)` | `POST /scan/data` | fetch G3Data |
| `data_insert(scanid, data[])` | `POST /scan/data/insert` | |
| `task_dispatch(scanid, tool, dataid, kind="tool")` | `POST /scan/task/dispatch` | **returns task_ids, no wait** |
| `tasks_status(scanid)` | `POST /scan/tasks/status` | batch; the poller's workhorse |
| `task_artifacts(scanid, taskid, dest)` | `POST /scan/task/artifacts` | streaming + zip-slip-safe |
| `plugin_describe()` | `GET/POST /plugin/describe` | contracts |
| `file_upload(path)` | `POST /file/upload` | returns file id |
| `import_file(scanid, tool, fileid)` | `POST /scan/import` | |
| `config_env()` | `POST /config/env` | |
| *(new, §4.2)* `task_magenta(scanid, taskid)` | `POST /scan/task/magenta` | structured issues |

Remove: the multiton, `bind/unbind/keys`, eager-create, `run()`, `DATA_PRIMER`,
`RunResult`. Keep: envelope parsing, streaming download, zip-slip-safe extract,
Content-Disposition handling.

## 6. g3api improvements to consider (ranked)

1. **Completion push, not poll** — a subscribable stream / webhook of
   task-terminal events (Redis is already internal). Deletes Knife's per-scan
   polling fan-out, lowers latency, scales. Biggest win.
2. **Idempotent dispatch + correlation passthrough** — a client-supplied
   correlation/idempotency key on dispatch that g3 echoes back in status/results.
   Makes dispatch safely retryable after a Knife crash and lets provenance ride
   with the task.
3. **Richer, stable plugin descriptors** — estimated runtime, intrusiveness/
   safety class, required inputs (needs-auth? single-URL vs whole-host?),
   idempotency. Feeds Knife's policy defaults and poll cadence.
4. **Auth/session passthrough** — hand a tool cookies/bearer/headers for
   authenticated requests (needed for the confirmation lane, e.g. sqlmap on a
   found injection).
5. **Caller-facing cancellation** — stop in-flight tasks when an engagement/host
   is deleted mid-scan or a user aborts (scan-delete should cascade to running
   tasks).
6. **Machine-readable issue category/template ids** (ties into Magenta) — lets
   Knife auto-route issues to its finding templates generically.
7. **On-demand Magenta endpoint** (§4.2).

## 7. First deliverable: "SSL Analysis Agent" (vertical slice)

The smallest end-to-end win. SSL is the ideal first target because it sidesteps
every hard Knife-threading problem: **no session cookies, no bearer auth, no
agent-memory threading, no inline reasoning** — pure host-in → findings-out.

Slice:

1. Thin g3 client: `task_dispatch(testssl)`, `tasks_status`, `task_artifacts`.
2. A **dedicated worker thread** (NOT Knife's 3-slot `ROUTE_EXECUTOR`) that
   dispatches testssl, blocking-polls to done, downloads the artifact. Blocking
   is fine here — it's its own thread — and skips building the generic poller.
3. Run Magenta (`/scan/task/magenta` per §4.2, or subprocess) → structured
   `multiple_ssl_issues` (+ Markdown).
4. Map → Knife `findings` (host-owned), write to MySQL, publish
   `findings:created` → live on the dashboard.
5. Trigger: **manual** API/button for the demo. Later: auto-trigger on host
   discovery (see §8) — "scan SSL ports as Knife finds them in scope."

Two framings for "Agent": a deterministic Magenta→findings **mapper** (fastest,
no LLM cost) ships first; optionally wrap an LLM `ssl_analysis_agent` spec that
reads the structured output and writes nicer prose/remediation via Knife's
existing `emit_result → findings` path (earns the literal "Agent" name).

## 8. Knife-side facts to remember (external context)

For when this resumes in a Knife session:

- **Findings are host-owned rows.** `findings` table keys on `host_id`; fields
  include `source`, `type`, `severity`, `summary`, `description`,
  `evidence_refs`, `remediation`, **`template`**, `cwe/cve/capec`. Set
  `source="magenta:testssl"`; **`template` can map directly to Magenta's
  template id** — the schemas already rhyme. Severity from the cipher/grade.
- **Findings belong to hosts, not engagements** (engagements are temporal
  lenses). One g3 scan per host; the scan is disposed when the host is deleted.
  (Knife already has `g3_scans(host_id→scan_id)` + teardown hooks from the first
  integration pass; that survives the client refactor — only the layer beneath
  it swaps from the multiton to the thin client.)
- **Triggers.** The orchestrator consumes Redis `events:ingested:{host_id}`;
  hosts are created/linked in `_upsert_and_link_host` (engagements). Demo = a
  manual trigger; prod = hook host/URL discovery (e.g. first https URL or TLS
  port seen) to auto-dispatch testssl.
- **Surfacing.** Write finding to MySQL + publish Redis `findings:created` →
  Web UI SocketIO → dashboard, live.
- **Cookies / session / agent memory.** Needed only for the **confirmation**
  lane (authenticated tools like sqlmap). NOT needed for SSL/enrichment — defer.

## 9. Phasing

| Phase | Golismero | Knife | Outcome |
|---|---|---|---|
| 0 | Thin client refactor (§5); add Magenta endpoint (§4.2) | — | New `g3client`; Magenta-on-demand |
| 1 | — | SSL vertical slice (§7), manual trigger | "Knife has an SSL Analysis Agent" |
| 2 | Auto-process artifacts per task; retire built-in reporting (§4.3) | Auto-trigger on host discovery (§8); generic dispatch/poll/ingest engine | testssl/wafw00f/nmap as enrichment |
| 3 | Deep Magenta/G3Data merge (§4.4); g3api push + idempotency (§6) | Confirmation lane (sqlmap on found injections) + auth passthrough | Full async tool fabric |

Each phase is independently demoable. Phases 0–1 are the near-term boss-facing
win; nothing after is a prerequisite for it.
