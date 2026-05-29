# HTTP Routing & REST Migration — Future Work

Discussion notes from an architecture chat on 2026-05-29. Captures a proposal to migrate `g3api` from its current "POST + JSON body for everything on `net/http`" shape to **Go 1.22+ enhanced `ServeMux`** with method+path routing, GET for read endpoints, and path parameters. Not scheduled.

This is a watchlist, not a plan. When picked up, write a fresh plan with concrete file edits, tier structure, and a coordinated client-update strategy.

---

## Why this is on the watchlist

The current `g3api` uses POST + JSON body for every endpoint, including obvious reads (`/scan/list`, `/scan/progress`, `/scan/tasks/status`, `/plugin/list`, `/plugin/describe`, `/config/env`, …). Every handler manually re-asserts its method via `ValidateHttpRequest`, every `Req*` struct carries `ScanID` in the body even when it identifies the resource being addressed, and 404 vs 405 are indistinguishable to clients.

This works, but bakes in three losses:

1. **Verb-as-intent is gone.** Middleware, proxies, audit layers, and access logs can't tell reads from writes without parsing JSON. A bearer-token retry loop will retry POSTs that look identical to mutations.
2. **No path parameters.** Every per-scan endpoint puts `scanid` in the body, which means the handler can't validate "this scan exists" at the router level, and URLs aren't shareable / inspectable.
3. **One middleware (`requireToken`) wraps every handler manually.** Adding a second (request IDs, structured access logs, panic recovery, per-route timeouts) means touching every registration.

None of those are urgent on an internal, bearer-token-auth'd API consumed by trusted clients. They become important the moment any of:

- A BFF or external consumer needs to sit in front of `g3api` (per the April 2026 architectural direction memory).
- HTTP-level caching, retry, or audit infrastructure needs to behave correctly.
- Middleware grows beyond `requireToken`.

---

## What the change looks like

Three coupled moves, executed together (separating them creates work that gets thrown away — every one of these is a breaking client-side change, and clients only want to update once):

### 1. Go 1.22+ enhanced `ServeMux`

The stdlib mux gained method+path routing and `{param}` extraction in Go 1.22. Since g3 is on Go 1.25 (`src/*/go.mod`), this is sitting available with zero dependencies. The route table changes from:

```go
http.HandleFunc(apiPath + "/scan/start",    requireToken(apiToken, startScanHandler))
http.HandleFunc(apiPath + "/scan/progress", requireToken(apiToken, scanProgressHandler))
```

…to:

```go
mux := http.NewServeMux()
mux.HandleFunc("POST " + apiPath + "/scans",                           requireToken(apiToken, startScanHandler))
mux.HandleFunc("GET "  + apiPath + "/scans",                           requireToken(apiToken, scanProgressHandler))
mux.HandleFunc("GET "  + apiPath + "/scans/{scanid}/tasks",            requireToken(apiToken, listTasksHandler))
```

Method routing replaces the per-handler `ValidateHttpRequest` method check. Path parameters extract via `r.PathValue("scanid")`. `requireToken`'s signature (`func(http.HandlerFunc) http.HandlerFunc`) needs no change — stdlib mux uses the same shape.

**Why not chi/gin/echo/fiber?** chi is the natural escalation if middleware ever grows past `requireToken`, but the stdlib mux covers everything g3api currently needs. gin/echo are heavier than this codebase wants; fiber breaks `net/http` compatibility (would require rewriting `requireToken`). Stay on stdlib until a concrete reason to leave.

### 2. GET for reads, POST for mutations, path params for resources

Every read endpoint becomes `GET`, with `scanid`/`taskid`/`dataid` lifted from body to path. Every mutation stays `POST` (or becomes `DELETE` for teardowns). A `ValidateHttpGetRequest` helper would just check the method; the real work is rerouting `Req*.Decode` to populate fields from `r.PathValue(...)` / `r.URL.Query()` instead of always from the JSON body.

One genuine exception: `POST /scans/{scanid}/data/filter` — bulk-by-ID lookups don't fit cleanly in a query string (up to 100 × 24-hex Mongo IDs = ~2.5 KB). This becomes a documented "POST as search" escape hatch, used only for this specific case.

### 3. Plural collection names

Today's API uses singular paths (`/scan`, `/task`, `/plugin`, `/file`), which is internally consistent but non-standard externally. Bundling the rename into this migration since every client is already updating their call sites — paying the flag-day cost once is strictly cheaper than twice.

Three categories stay singular and earn it:

- **`/data`** — mass noun in English; no natural plural form. "Insert data" reads correctly; "insert datas" doesn't.
- **`/config`** — singleton (one config per deployment), not a collection. `GET /config/env` reads as "the config's env block."
- **Action paths** (`.../stop`, `.../import`, `.../report`, `.../filter`, `.../describe`) — these are operations or singletons on a resource, not collections of operations.

Everything else gets pluralized. The naming-conventions section below has the full rule and rationale.

---

## The full endpoint table

After a systematic symmetry check (every collection answers list-with-data / list-of-IDs / get-one / create / search / delete / state-transition where applicable).

### Scans

| Method | Path | Was | Notes |
|---|---|---|---|
| `POST` | `/scans` | `POST /scan/start` | Pipeline-driven scan. Body: script, mode, … |
| `POST` | `/scans/managed` | `POST /scan/create` | Managed scan. Empty body. |
| `GET` | `/scans` | `POST /scan/progress` | All scans, with status. |
| `GET` | `/scans/list` | `POST /scan/list` | IDs only — lightweight poll. |
| `GET` | `/scans/{scanid}` | *(new)* | One scan's `ScanStatusEntry`. |
| `POST` | `/scans/{scanid}/stop` | `POST /scan/stop` | State transition, keeps history. |
| `DELETE` | `/scans/{scanid}` | `POST /scan/delete` | Full teardown. |

### Targets and data (within a scan)

| Method | Path | Was | Notes |
|---|---|---|---|
| `POST` | `/scans/{scanid}/targets` | `POST /scan/target/add` | Add canonicalized targets (managed-only). |
| `POST` | `/scans/{scanid}/data` | `POST /scan/data/insert` | Insert raw G3Data (managed-only). |
| `GET` | `/scans/{scanid}/data` | `POST /scan/data` (no dataids) | All data; `?taskid={uuid}` filter. |
| `GET` | `/scans/{scanid}/data/{dataid}` | *(new)* | Single G3Data object. |
| `POST` | `/scans/{scanid}/data/filter` | `POST /scan/data` (with dataids[]) | Bulk-by-ID / future complex queries. **Only POST-as-search endpoint.** |
| `GET` | `/scans/{scanid}/data/list` | `POST /scan/datalist` | IDs only. |

### Tasks (within a scan)

| Method | Path | Was | Notes |
|---|---|---|---|
| `POST` | `/scans/{scanid}/tasks` | `POST /scan/task/dispatch` | Dispatch a new task. |
| `GET` | `/scans/{scanid}/tasks` | `POST /scan/tasks/status` | Task list with status. |
| `GET` | `/scans/{scanid}/tasks/list` | `POST /scan/tasks` | IDs only. |
| `GET` | `/scans/{scanid}/tasks/{taskid}` | *(new)* | Single task status. |
| `POST` | `/scans/{scanid}/tasks/{taskid}/stop` | `POST /scan/task/cancel` | State transition (was `DELETE` in earlier draft — corrected for verb symmetry). |
| `GET` | `/scans/{scanid}/tasks/{taskid}/artifacts` | `POST /scan/task/artifacts` | Tar.gz / zip download. |

### Imports / files

| Method | Path | Was | Notes |
|---|---|---|---|
| `POST` | `/files` | `POST /file/upload` | Multipart upload. Returns file UUID. |
| `POST` | `/scans/{scanid}/import` | `POST /scan/import` | Run importer on a previously-uploaded file (managed-only). |

### Reports / logs

| Method | Path | Was | Notes |
|---|---|---|---|
| `GET` | `/scans/{scanid}/report` | `POST /scan/report` | Generated report content. Single report per scan — stays singular. |
| `GET` | `/scans/{scanid}/logs` | `POST /scan/logs` | Logs. Query params for `?taskid=`, range, …. |

### Plugins / config

| Method | Path | Was | Notes |
|---|---|---|---|
| `GET` | `/plugins` | `POST /plugin/list` | Human-facing list (name/url/description/image). |
| `GET` | `/plugins/describe` | `POST /plugin/describe` | LLM contract list. |
| `GET` | `/config/env` | `POST /config/env` | Shared `G3_ENV_*` map. `/config` is a singleton, stays singular. |

### WebSocket (unchanged)

| Method | Path | Was | Notes |
|---|---|---|---|
| `GET` | `/ws` | `GET /ws` | HTTP/1.1 Upgrade — already GET, nothing changes. |

**Net: 27 endpoints, two new (`GET /scans/{scanid}/tasks/{taskid}`, `GET /scans/{scanid}/data/{dataid}`), one verb change (`POST .../tasks/{id}/stop` instead of `DELETE`).**

---

## Key design decisions

### Naming conventions

- **Plural collection names** (`/scans`, `/tasks`, `/plugins`, `/files`). Standard REST convention; bundled into this migration since we're already paying the flag-day cost. Three exceptions stay singular and have reasons:
  - **`/data`** — mass noun in English; no natural plural. Bare "data" reads correctly.
  - **`/config`** — singleton resource (one config per deployment), not a collection. `GET /config/env` reads as "the config's env block."
  - **Action paths** (`/scans/{id}/stop`, `/scans/{id}/import`, `/scans/{id}/report`) — these are operations or singletons, not collections.
- **`/{resource}/list` = IDs only.** Applied uniformly to scans, tasks, data. Routing is unambiguous because `list` is a literal and the sibling `/{id}` param is `validate:"uuid"` or `validate:"mongodb"` checked.
- **POST to a collection creates; POST to a sub-path is an action.** `POST /scans/{scanid}/data` inserts data; `POST /scans/{scanid}/data/filter` searches; `POST /scans/{scanid}/stop` transitions state.

### Verb-to-semantics mapping (uniform)

- **`GET`** — read, no side effects.
- **`POST`** *to a collection root* — create.
- **`POST .../{action}`** — state transition that preserves history (`/stop`, `/filter`).
- **`DELETE`** — actually remove the resource and its dependents.
- **No `PUT`, no `PATCH`** — nothing in g3api is updated-in-place. Scans/tasks/data are append-only by nature. If scan editing ever lands, that's the moment to introduce PUT.

The earlier draft of this table used `DELETE /scan/{scanid}/task/{taskid}` for task cancellation. That was a verb-to-semantics mismatch: at the scan level `DELETE` tears down everything; at the task level it left the record with `state=CANCELED`. Same verb, different behavior. Corrected to `POST .../stop` for both scan halt and task cancel, with `DELETE` reserved for true removal.

### `POST /scans/managed` vs alternatives

Three options were considered for managed-scan creation:

1. **`POST /scans/managed`** *(chosen)* — preserves the "separate handler for clarity" decision from the original Tier 2 design. Reads as "create a managed-flavor scan."
2. `POST /scans` with `{kind: "managed"}` body discriminator — REST-purest but loses the clean handler isolation.
3. `POST /managed-scans` — clearer at the URL level but invents a sibling root resource for what is conceptually still a scan.

(1) wins on continuity with current architectural choices.

### Intentional asymmetries (defend in writing)

These look like gaps but are deliberate. Comment near the route table to keep them from being "fixed" by mimicry later:

- **No `/plugins/list` (IDs only).** Plugins are static config loaded once; no polling pressure. The full `/plugins` list is cheap enough.
- **No `/files` list, no `GET /files/{id}`.** Files are write-only by design: upload → immediately import → gone. (See deferred item: orphan-file cleanup.)
- **`POST /scans/{scanid}/data/filter` is the *only* POST-as-search endpoint.** Justified by the Mongo-ID bulk problem. Keep this comment in the handler to prevent the pattern spreading.
- **No PUT/PATCH anywhere.** g3api has nothing that's updated-in-place.

---

## Migration considerations

### Client coordination

Every change is a breaking API change. Clients to update in the same PR:

- **`src/g3cli/`** — the existing Go CLI client.
- **`src/g3tui/`** — the TUI client.
- **`clients/python/`** — the Python client (Tier 4 of the knife integration work). **If the knife integration is built first against the current API shape, the Python client will need rewriting during this migration. If this migration is done first, the Python client is born on the new shape.** Sequencing decision; not free either way.
- **Any external scripts** hitting `g3api` directly — internal use only, but document the breaking change in release notes.

### Skipped versioning

`g3api` is internal and all clients are controlled. URL versioning (`/v2/scans/...`) adds permanent complexity for a benefit that doesn't apply. Ship the migration as one flag-day breaking change with simultaneous client updates. If `g3api` ever gets exposed to a BFF or third party, *that's* the moment to add `/v1/` and start versioning forward.

### `Req*.Decode` rewrite

Today every `Req*.Decode` does `ValidateHttpRequest` + `json.NewDecoder(r.Body).Decode(req)` + `validator.New().Struct(req)`. After the migration:

- **For GET endpoints:** populate fields from `r.PathValue(...)` and `r.URL.Query()`. No body. The `validator.Struct` step is unchanged — the struct fields' `validate:` tags still gate correctness.
- **For POST/DELETE endpoints with path params:** populate path fields from `r.PathValue(...)`, body fields from `json.Decode`. The `ScanID` field becomes path-sourced; the rest stays body-sourced.

A small per-source helper (`decodePathParams`, `decodeQueryParams`, `decodeBody`) inside the decode method keeps the pattern uniform. Or hand-write per-Req — both work; the choice is "boilerplate vs reflection" with no obvious winner at g3api's size.

### `Validate*` helpers retire (or shrink)

- `ValidateHttpRequest` shrinks to checking only `Content-Type` and `Content-Length` (method check moves to the router).
- `ValidateHttpGetRequest` is a no-op (the router handles method).
- Both probably collapse into the `Decode` method's helpers and disappear as standalone functions.

### Behavior changes to verify carefully during migration

- **Trailing slashes.** Stdlib mux has specific behavior (`/scans/` redirects to `/scans`). Worth a one-time audit.
- **405 responses.** Previously every wrong-method request got a generic 400 from `ValidateHttpRequest`. Stdlib mux will return 405 with an `Allow` header. Better but different — clients that hardcoded "400 = bad request" might confuse themselves.
- **Empty-body POSTs.** Stdlib mux doesn't enforce `Content-Length > 0`. If you keep the body-presence check in `Decode`, behavior is preserved. If you drop it, some endpoints become callable with no body.
- **Path matching precedence.** `GET /scan/list` (literal) must win over `GET /scan/{scanid}` (param). Stdlib mux 1.22 does this correctly, but worth verifying with a test of overlapping routes.

---

## Deferred items (don't tackle in this migration)

### Single-plugin lookup (`GET /plugin/{name}`)

Mostly useful for inspection / debugging. The LLM client caches the full `/plugin/describe` response, so it doesn't need per-plugin lookup. Defer until a real consumer asks for it.

### File-orphan cleanup (`GET /file`, `DELETE /file/{fileid}`)

Files uploaded via `POST /file` that are never imported sit in `_uploads/` forever. Today there's no API to list orphans or clean them up. Real issue, but an ops-hygiene feature separate from the routing migration. Own ticket.

### Migration to chi

If/when middleware grows beyond just `requireToken` (request IDs, structured access logs, panic recovery, per-route timeouts, route groups, sub-routers), chi is the natural step. Stdlib mux gives routing but not declarative middleware chains. Don't preempt.

---

## Triggers to revisit

Pull this from "deferred" into "scheduled" when any of:

1. **A BFF or external consumer is planned in front of `g3api`** — per the April 2026 architectural direction. External consumers care a lot more about HTTP semantics than internal ones do.
2. **HTTP-level retries, audit logs, or caching infrastructure** starts mattering and behaves incorrectly under the current "everything is POST" shape.
3. **Middleware grows past `requireToken`** — at that point the stdlib mux refactor pays for itself even without verb correctness.
4. **`g3api` is exposed beyond the trusted perimeter** for any reason, including a public-facing demo.
5. **Routing migration is bundled with another large `g3api` refactor** where the per-handler churn is already being paid.

Until one of those lands, the current shape works, every existing client knows how to drive it, and the migration cost stays unjustified.

---

## Open questions for when this is scheduled

- **Exact `Req*.Decode` shape** — per-source helpers vs reflection vs hand-written per-Req.
- **Where path-param validation lives** — at decode time (re-validate `validate:"uuid"` tags) or trust the mux pattern matcher.
- **Logging strategy** — structured access logs become natural with stdlib mux; pick a logger that fits the existing `g3log` shape.
- **`apiPath` prefix handling** — today every route is registered under a configurable prefix. Stdlib mux 1.22 patterns support this fine (just include `apiPath` in the pattern string) but verify the prefix-stripping behavior under sub-routers if chi is later adopted.
- **Whether the singular→plural rename gets bundled** — slightly bigger client churn but you only pay flag-day once.

**Likely files when scheduled:** `src/g3api/g3api.go` (every route registration), `src/g3lib/api.go` (every `Req*.Decode` method), all clients (`src/g3cli/`, `src/g3tui/`, `clients/python/`).
