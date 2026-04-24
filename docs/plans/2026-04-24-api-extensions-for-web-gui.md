# API Extensions for Web GUI — Tiered Plan

Scope: changes to `g3api` (and supporting types in `g3lib`) plus `g3cli` updates. A separate GUI backend (BFF) and magenta integration are out of scope; they can be built on top once this lands.

**Status:** all tiers outlined. No tier started. Detail for each tier is revisited at kickoff per project convention.

---

## Context

A web GUI is being scoped for g3. Brainstorming across 2026-04-23 and 2026-04-24 refined not just the specific API gaps but — more fundamentally — the role of `g3api` itself in the architecture. This plan documents the resulting direction before any implementation.

### Architectural decision: `g3api` becomes an internal-only service

The shape that emerged:

- **`g3api`** = internal-only scan engine RPC. Sits behind a trust boundary (VPN/firewall/docker network) alongside MongoDB, MariaDB, Redis, Mosquitto. Same deployment posture as those services.
- **BFF** (to be built, deliberately not in Go) = user-facing web backend. Owns user authentication, sessions, RBAC, audit, pagination, search, scheduling, report format conversion, scan history, per-user preferences. Mature web-framework ecosystem lives in Python/Node/Ruby/Rust, not Go.
- **magenta** ([https://github.com/golismero/magenta](https://github.com/golismero/magenta), tracked by [issue #2](https://github.com/golismero/g3/issues/2)) = replaces `g3api`'s built-in reporting. Takes JSON data objects plus raw artifact files, produces text reports.
- **Shared artifacts volume** ([issue #9](https://github.com/golismero/g3/issues/9)) = new infrastructure where plugins write raw tool outputs keyed by `{scanid}/{taskid}/`; magenta reads them alongside the JSON data.

Under this model, `g3api`'s user/auth machinery becomes redundant. Authentication reduces to a single service credential via environment variable (same posture as the existing MongoDB/MariaDB/Redis credentials: hardcoded default in `.env`/docker-compose, operator override in any real deployment). Authorization disappears entirely — inside the trust boundary, any authenticated caller can do anything.

### Why this simplification is defensible

- **No real user base yet.** Project is being rescued from abandonment; there is one user (the author). No existing deployments to migrate.
- **Existing ACL is already half-baked.** Five scan-scoped endpoints (`/scan/progress`, `/scan/tasks`, `/scan/logs`, `/scan/tasks/status`) plus the WebSocket channel already skip the ownership check and have `// no authorization needed` comments in the code. Only six endpoints enforce it. Default credentials (`admin:admin`, `user:user`) ship hardcoded in `volumes/mariadb/initdb.d/create_tables.sql`. The compose file itself states it is not for production.
- **Go is not the natural webapp language.** Session management, OAuth flows, CSRF, password reset, admin UIs — the mature ecosystem is elsewhere. Building those inside `g3api` means reinventing them badly.
- **Dual human UIs planned** (web GUI + complex TUI). Both route through a proper internet-facing service with proper auth. Under that model, every caller of `g3api` is a service, not a person.
- **Agentic integration** (future, shape TBD) is easier against a single-cred model than a JWT/user model. Agents don't map naturally to human-user ACLs regardless of which interpretation wins.

### Concrete implications mapped to existing code

Endpoints to **remove**:
- `/auth/login`, `/auth/refresh`, `/auth/ticket` — user/JWT infrastructure goes away.
- `/file/download`, `/file/ls`, `/file/rm` — confirmed dead code (no consumer in `g3cli` or anywhere else; pure GUI-anticipatory).

Endpoints to **keep but re-authenticate via shared cred**:
- Everything else, including `/file/upload`. Upload *is* in use: `g3cli` uploads import files here (`g3cli.go:252-356`) and `/scan/start` reads them from `/tmp/{userid}/{uuid}.bin` into the import plugin's stdin (`g3api.go:437-489`).

Filesystem paths to **flatten**:
- `/tmp/{userid}/{uuid}.bin` → `/tmp/{uuid}.bin` across `/file/upload` and `/scan/start`. No user namespace.

Database tables to **drop**:
- `users` — bcrypt passwords, seed inserts of `admin:admin` / `user:user`.
- `scans` (the permissions table, not to be confused with the concept of "scan records") — the `(userid, scanid)` permissions join.

`g3lib` functions to **drop**:
- `IsUserAuthorized`, `AddUserToScan`, `GetScansForUser`, `Login`, `GetUserID`, plus `g3lib/jwt.go` in its entirety.

Admin special cases to **retire** naturally:
- `userid == 1` short-circuit in `IsUserAuthorized`.
- `OR 1 = ?` trick in `GetScansForUser`.

What **stays unchanged**:
- Scan lifecycle, MongoDB data model, MariaDB logs/progress tables, Redis task state, MQTT topology. This is purely removal of the auth/user layer, not a redesign of the engine.

### Related workstreams (out of scope for this plan)

- [#2](https://github.com/golismero/g3/issues/2) — replace built-in reporting with magenta.
- [#9](https://github.com/golismero/g3/issues/9) — shared artifacts volume for plugins.
- BFF implementation (separate service, not Go).
- Agentic framework integration (future; shape TBD).

---

## Tiers

### Tier 0 — Strip auth and users; single service credential

**Intent.** Make `g3api` internal-only. Replace user/JWT/ACL infrastructure with a single shared service credential via environment variable. Default in `.env`/docker-compose, operator overrides for real deployments. Matches existing MongoDB/MariaDB/Redis posture.

**Anticipated shape.**
- Authentication: HTTP Basic over the internal network, or bearer token — both trivially cheap, decide at kickoff.
- Remove `/auth/*` endpoints (`login`, `refresh`, `ticket`) and `/file/download`, `/file/ls`, `/file/rm`.
- Flatten `/tmp/{userid}/{uuid}.bin` → `/tmp/{uuid}.bin`. Update `/file/upload` and `/scan/start` accordingly.
- Drop `users` and `scans` (permissions) tables and their seed inserts; retire the hardcoded default credentials.
- Delete `IsUserAuthorized`, `AddUserToScan`, `GetScansForUser`, `Login`, `GetUserID`, and `g3lib/jwt.go`.
- Replace the `ValidateJwt` + optional `IsUserAuthorized` pattern at the top of every handler with one middleware-level credential check.
- `g3cli`: remove login/refresh flows, read shared credential from env, request shape otherwise unchanged.
- docker-compose: new env var (name TBD) for the shared credential, with a hardcoded default flagged for operator override in `.env.example`.

**Character.** Mostly deletions. Opens the door for Tier 1+ to be simple filter-only features with no auth story to reconcile.

**Defer to kickoff.** Exact auth mechanism (Basic vs bearer), env var naming, whether to fold cleanup into one PR or split.

### Tier 1 — Per-scan WebSocket subscription

**Intent.** Let a WS client subscribe to updates for a specific scan instead of getting the broadcast firehose. Pure filter; no ACL, matching Tier 0's posture.

**Anticipated shape.**
- `scanprogress` with optional `scanid` field → filter to that scan. Without `scanid` → broadcast (today's behavior preserved for the no-scanid case).
- New `unsubscribe` msgtype so GUIs can navigate without reconnecting.
- `NotifyTracker` refactored from "one set of channels" to "per-subscription record with `{channel, scanid}` filter".
- `g3cli get --scan <scanid>` to consume.

**Files.** `g3lib/api.go` (message types), `g3api/g3api.go` (`NotifyTracker` + `/ws` handler), `g3cli/g3cli.go` (`GetCmd`).

### Tier 2 — WebSocket log stream

**Intent.** Replace "fetch the whole log blob at the end" with "tail new log lines as they arrive." Unblocks `g3cli logs -f` and provides a natural surface for future agents that consume tool output live.

**Anticipated shape.**
- Subscribe by `(scanid)` or `(scanid, taskid)` — multiplex vs per-task — decide at kickoff.
- Ingest channel candidates: MariaDB polling with `WHERE timestamp > ?` (simplest, ~1s latency), Redis pub-sub alongside the SQL insert (lower latency), new MQTT topic (rejected — unneeded queue semantics).
- Backfill-since-timestamp vs live-only — decide at kickoff.

**Files.** `g3api/g3api.go`, `g3lib/sql.go` (query helper), `g3lib/api.go` (types), `g3cli/g3cli.go` (`LogsCmd` gains `-f`).

### Tier 3 — Individual task cancel

**Intent.** Surface the `TaskID` field that already exists on `CancelCmd` so one stuck task can be killed without cancelling the whole scan. Lowest priority; common case (whole-scan stop) is already covered.

**Anticipated shape.**
- New endpoint (probably `/scan/task/stop`) taking `{scanid, taskid}`.
- Publishes the existing `CancelCmd` MQTT message with `TaskID` populated.
- Open question: does the per-task failure cascade normally through the pipeline, or is it suppressed?
- Interaction with the scan-level `CANCELING` state from the recent state-machine work.

**Files.** `g3lib/api.go`, `g3api/g3api.go`, `g3scanner/g3scanner.go`, `g3worker/g3worker.go` (verify), `g3cli/g3cli.go`.

---

## Cross-cutting observations

- **Agent integration is orthogonal.** Across the four plausible interpretations (MCP server / external orchestrator / in-plugin agent / plugin-as-agent-caller), none of this plan's decisions change. Tier 1 and Tier 2 become *more* valuable in any agent world because agents want focused live feedback more than batch results. The magenta split (golismero handles JSON, magenta handles text) gives agents two natural integration layers with no overlap.
- **magenta integration** naturally inherits "scan-keyed, not user-keyed" from Tier 0. The shared artifacts folder (#9) keys by `{scanid}/{taskid}/` with no user namespace — one fewer decision to make.
- **JSON out of `g3api`, text out of magenta** is the durable split. Agents compose at either layer according to purpose.

## Explicitly out of scope

- The BFF itself (its design, routes, auth, UI state, users, audit, pagination, search, scheduling).
- magenta implementation (#2).
- Shared artifacts volume (#9) — plugin-framework concern.
- Agentic integration — future, not committed.
- Any kind of permissions/RBAC system within `g3api` — rejected. If per-user access control is ever needed, it lives in the BFF.
