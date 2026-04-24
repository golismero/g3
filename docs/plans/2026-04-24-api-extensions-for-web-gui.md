# API Extensions for Web GUI — Tiered Plan

Scope: changes to `g3api` (and supporting types in `g3lib`) plus `g3cli` updates. A separate GUI backend (BFF) and magenta integration are out of scope; they can be built on top once this lands.

**Status:** Tier 0 detailed and ready to implement (kickoff 2026-04-24). Tiers 1-3 remain outlined; detail each at its own kickoff per project convention.

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

**Kickoff decisions (2026-04-24).**
- **Auth mechanism: bearer token.** `Authorization: Bearer <token>`. Expresses "service credential, not a user" directly; Basic would smuggle a vestigial username back in. Smallest diff in `g3cli` — the JWT-bearing header path stays, only the token source changes.
- **Env var: `G3_API_TOKEN`.** Matches the existing `G3_API_*` family; avoids the third-party-cred collision that `G3_API_KEY` would create alongside `VULNERS_API_KEY` / `VIRUSTOTAL_API_KEY`. One var, same value on both server and client.
- **PR shape: single PR.** No staging deploy, no outside reviewers, no user base to preserve. Splitting would manufacture a compilable intermediate state (middleware landed, old JWT code still around) for no reviewer benefit. One atomic "remove auth layer, add token middleware" change.
- **WebSocket handshake auth: covered in the same middleware.** Today `/ws` has no auth at all; Tier 0 closes that gap, not just simplifies the existing pattern.

#### End state

**Request lifecycle** (HTTP and WS identical):
1. Request arrives.
2. Middleware reads `Authorization: Bearer <token>`. Constant-time compare against `G3_API_TOKEN` loaded at startup. Miss → 401, stop.
3. Handler runs with no auth concerns.

**What leaves the request envelope.** The `Token` field on every `Req*` struct in `g3lib/api.go`. The `ReqLogin` / `ReqRefreshJwt` / `ReqTicket` structs and their responses. The multipart `auth` form field on `/file/upload`. The per-message `Token` field in the WS envelope.

**Endpoints after Tier 0:** `/scan/start`, `/scan/stop`, `/scan/list`, `/scan/get`, `/scan/progress`, `/scan/tasks`, `/scan/tasks/status`, `/scan/logs`, `/file/upload`, `/report/*`, `/plugin/*`, `/script/*`, `/ws`.

**Endpoints removed:** `/auth/login`, `/auth/refresh`, `/auth/ticket`, `/file/download`, `/file/ls`, `/file/rm`.

#### Middleware

Single Go wrapper applied to every `http.HandleFunc` registration in `g3api.go`, including `/ws`:

- Reads `Authorization: Bearer <token>` via `strings.CutPrefix`.
- Compares with `subtle.ConstantTimeCompare` against the startup-loaded token.
- On failure: `SendApiError(w, 401, "Unauthorized.")` and return — handler never runs.
- Token loaded once from `G3_API_TOKEN` at `g3api` startup. Empty value → fail-fast log and exit; the binary refuses to start without a configured token. This is strictly stricter than today's `G3_JWT_SECRET` posture.

Handler body becomes pure business logic. Today's representative shape:

```go
userid, err := g3lib.ValidateJwt(request.Token)
if err != nil { ...401... }
isAuthorized, err := g3lib.IsUserAuthorized(sql_db, userid, request.ScanID)
if err != nil { ...401... }
if isAuthorized != 1 { ...401... }
// actual handler work
```

After:

```go
// actual handler work
```

Same collapse for the four handlers that today carry `// no authorization needed` and call only `ValidateJwt`.

#### WebSocket handshake

`/ws` registers through the same middleware wrapper. The check runs on the initial HTTP GET before `upgrader.Upgrade()`; a failed token returns a plain 401 and no upgrade happens. Safe because the middleware only writes to `w` on the failure path — success delegates untouched to the handler, so `gorilla/websocket`'s "nothing written before Upgrade" requirement holds.

`g3cli`'s WS dialer already passes an `http.Header` to `DialContext`. The header value swaps from JWT to `G3_API_TOKEN`. No other client-side change.

Per-session trust: once the socket is open, no per-message re-auth. The message envelope's `Token` field is dropped.

#### Cleanups

**Filesystem.**
- `/file/upload` and `/scan/start`: `/tmp/{userid}/{uuid}.bin` → `/tmp/{uuid}.bin`. No userid dir, no `MkdirAll` for it. UUID namespace is already collision-free.
- No migration of existing `/tmp` files. Nothing is live.

**Database schema — `volumes/mariadb/initdb.d/create_tables.sql`.**
- Delete the `users` table block (lines 22-27).
- Delete the `scans` permissions table block (lines 29-37).
- Delete both seed `INSERT`s and their comment (lines 39-42).
- Final file contains only the `logs` and `progress` tables.
- Redeploy via `docker compose down -v && docker compose up` to wipe the MariaDB volume. Not a migration — a reset.

**`g3lib` deletions.**
- `g3lib/jwt.go` — whole file.
- From `g3lib/sql.go`: `IsUserAuthorized`, `AddUserToScan`, `RemoveUserFromScan`, `GetScansForUser`, `Login`, `GetUserID`, plus any private helpers only those functions use.
- From `g3lib/api.go`: `ReqLogin`, `ReqRefreshJwt`, `ReqTicket` and their responses. `Token` field stripped from every remaining `Req*` struct and from the WS message envelope.

**`g3cli` (`g3cli.go`).**
- Drop `Username` / `Password` CLI flags.
- Remove the login round-trip (lines 182-194) and any refresh logic.
- `MakeApiRequest` loads `G3_API_TOKEN` once at startup, injects it on every HTTP and WS call. Unset env → fail-fast, same posture as `g3api`.
- `/file/upload` multipart builder: drop the `auth` form field.

**Environment and compose.**
- `.env`: add `G3_API_TOKEN=changeme` with a comment flagging operator override. Remove `G3_JWT_SECRET` and `G3_JWT_LIFETIME`.
- `docker-compose.yml`: pass `G3_API_TOKEN` through to `g3api`; remove `G3_JWT_SECRET` plumbing.
- `nginx`: expected unchanged. Read the config before deleting endpoints — any `/auth/*` rewrites or `X-Auth-*` forwarding gets removed in the same PR.

**Grep list at implementation time** (belt-and-braces): `ValidateJwt`, `GenerateJwt`, `GenerateTemporaryJwt`, `IsUserAuthorized`, `JWT_SECRET`, `auth/login`, `auth/refresh`, `auth/ticket`. Hits outside the files above are unanticipated call sites — surface before deleting.

#### Verification

Manual smoke via `docker compose up` + `g3cli`. No Go test harness introduced — out of scope.

1. **Auth gate.** `g3cli list` with correct `G3_API_TOKEN` succeeds. Wrong value → 401. Unset env → CLI fails at startup.
2. **WS handshake.** `g3cli get --scan <id>` receives progress events. `websocat` or `curl -i --http1.1 -H "Upgrade: websocket"` without the bearer header returns 401 before upgrade.
3. **File upload path.** Run a scan with an import file through `g3cli`. Confirm `/tmp/<uuid>.bin` appears briefly and is consumed by `/scan/start`.
4. **Schema boots clean.** `docker compose down -v && docker compose up` on a fresh MariaDB volume. End-to-end scan populates `logs` and `progress` rows.
5. **Dead endpoints 404.** `curl -H "Authorization: Bearer $G3_API_TOKEN" .../auth/login` etc. return 404, not a silent handler hit.
6. **Lint gate.** Existing correctness-only `golangci-lint` run passes. Unused-function flags from deletions get resolved by finishing the deletion, not by `_ = foo` silencing.

#### Risks

- **Unknown call site we didn't grep for.** Mitigated by the grep list plus the Go compiler — any remaining importer of a deleted symbol fails the build. Residual risk is scripts or docs referencing `admin:admin`; low.
- **nginx config carries `/auth/*` or `X-Auth-*` logic.** Read before deleting endpoints.
- **`G3_API_TOKEN` accidentally unset.** Fail-fast at both `g3api` and `g3cli` startup prevents a silent "accept anything" window. Strictly stricter than today's `G3_JWT_SECRET` behaviour (which silently accepts JWTs signed with the empty string).

#### Non-risks (named so they don't drift into scope)

- User-data migration. No users to migrate.
- Backwards compatibility for external API consumers. There are none.
- Token rotation, revocation, expiry. Single shared cred; rotated by editing `.env` and restarting. Rotation semantics are BFF concerns.

#### Character

Almost entirely deletions plus one small middleware. Opens the door for Tiers 1-3 to ship as pure filter / stream / routing features with no auth story to reconcile.

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
