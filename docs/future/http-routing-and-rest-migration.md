# HTTP Routing & REST Migration — Future Work

Discussion notes from architecture chats on 2026-05-29 and 2026-06-24. The original proposal (2026-05-29) was to migrate `g3api` from its current "POST + JSON body for everything on `net/http`" shape to **Go 1.22+ enhanced `ServeMux`** with method+path routing, GET for read endpoints, and path parameters.

The 2026-06-24 discussion went further: the right modernization isn't a hand-refactored `net/http` route table, it's a **code-first OpenAPI** approach — define the API as Go types, generate the spec, generate the clients. That subsumes the original proposal and dissolves several of its open questions. See **Direction (2026-06-24)** below. Still not scheduled.

This is a watchlist, not a plan. When picked up, write a fresh plan with concrete file edits, tier structure, and a coordinated client-update strategy.

---

## Direction (2026-06-24): code-first OpenAPI

The 2026-05-29 notes below describe migrating the hand-written `net/http` route table to Go 1.22 `ServeMux` and rewriting every `Req*.Decode`. That's still a faithful description of the **target API surface** (verbs, paths, plural names — see the endpoint table), but it's no longer how we'd *build* it. Decision:

**Define the API code-first with [huma](https://github.com/danielgtaylor/huma), generate the OpenAPI 3.1 spec as a build artifact, and generate clients from that spec.**

Rationale:

- **The recurring cost here is client coordination, not server code.** Every API change is a flag-day across `g3cli`, `g3tui`, and `sdk/python`. A generated spec turns the boring half of each client — types, per-operation methods, request/response validation — into regenerated code that never drifts. The ergonomic layers stay hand-written (see *Client story*).
- **Go is a smaller maintenance surface than hand-authored YAML, and the spec stays verifiable.** With code-first the Go types are the single source of truth; the OpenAPI doc is generated, committed as an artifact, and gated in CI (lint with spectral, breaking-change diff with oasdiff). Because it's regenerated from the implementation it *cannot* drift from the handlers — strictly stronger than a hand-maintained YAML that can.
- **Code-first wins on cross-transport type reuse.** REST and the WebSocket event surface share domain structs (see *WebSockets*). With code-first those are plain Go types both transports import; with spec-first YAML the types are generated from the spec and the WS layer would couple to that output or duplicate it.

(The "spec-first vs code-first" distinction is mostly philosophical here — both produce the spec that generates clients. Code-first wins on the three points above; the only thing it costs is the "hand-authored contract" feeling, which we don't need.)

### What huma dissolves

huma extracts and validates request fields from struct tags and maps handler return values / typed errors to responses. Several 2026-05-29 open questions stop existing:

- **`Req*.Decode` shape** (was open) — gone. Input structs use `path:`/`query:`/`json:` tags; there is no `Decode` method to write. The 21 identical `Decode` methods in `src/g3lib/api.go` are deleted.
- **Path-param validation** (was open) — gone. `format:"uuid"` on the input field validates before the handler runs; the matcher no longer needs to be trusted for shape.
- **`Validate*` helpers** — `ValidateHttpRequest` / `ValidateHttpGetRequest` retire entirely.

### What still applies from the 2026-05-29 notes

- **The endpoint table** is the target surface huma will express (one `huma.Operation` per row), minus `/plugins/describe` (removed — see below).
- **Plural collection names** — still bundled; expressed as huma `Path` strings. Same flag-day logic.
- **Routing substrate** — huma mounts on Go 1.22 `ServeMux` (`humago`) or chi (`humachi`); the stdlib-vs-chi reasoning still holds, now reduced to one adapter choice. `apiPath` is the mount prefix.
- **Skipped versioning, client coordination** — unchanged; one flag-day, all clients updated together.

### Response envelope: a real breaking change

huma's default error shape is RFC 7807 `problem+json`, not g3api's `{status, data}` envelope. Adopting huma means changing the response shape — folded into the same flag-day, but a genuine decision (see *Status-code contract* and *Open questions*). The permissive "any 2xx = success" client check becomes largely moot for *generated* clients, which key off the operation contract rather than a hand-written 2xx range.

### Client story

Today there is no real client SDK: `g3cli` calls `g3lib.MakeApiRequest(...)` directly with hand-written endpoint strings (15+ sites), and `g3tui` wraps the same call in a thin `internal/client` package. So **`g3lib` is the de-facto client transport today** — `MakeApiRequest`/`DownloadFile`/`UploadFile` + the `Req*` structs all live in `src/g3lib/api.go`. That accidental role goes away:

- **Go (`g3cli`, `g3tui`)** — the generated Go client lives in its **own package outside `g3lib`** (e.g. `sdk/go/`, mirroring `sdk/python/`); the binaries import it and stop calling `g3lib.MakeApiRequest`. `g3lib` keeps domain types (`G3Data`/`G3Task`/`G3Plugin`), MQTT, datastore, SQL — but is no longer the HTTP client. Because the two binaries are end-user *apps* (not a published SDK), they consume the generated client directly; no extra hand-written Go facade needed. This realizes the "Go client outside `g3lib`" idea floated earlier — codegen makes it the natural choice, not a judgment call.
- **Python (`sdk/python`)** — it *is* a published SDK (Knife consumes it), so it keeps its hand-written ergonomic facade (`scanner`/`manager` tiers, LLM-safe naming) over a **regenerated** transport. The current bespoke `_transport.py` (retries/backoff, zip-safe extraction, the async-ready seam, envelope parsing) and the `api/` submodule are what the generated transport replaces — so those bespoke behaviors either come from the generator or relocate up into the facade. Per the existing design the facade gets *adjusted, not rewritten*, on each spec change. "Close to free" — by design, not as a failure.

### `/plugin/describe` removed

> **✅ Done (2026-06-25):** removed standalone ahead of the migration — handler/route, `g3lib` `PluginContract`/`G3LLMMetadata`/`G3Plugin.LLM`, and the Python SDK `describe()`/`PluginContract` are all deleted. See `docs/superpowers/specs/2026-06-25-remove-plugin-describe-design.md`.

`POST /plugin/describe` (the LLM-contract list) is **phased out**. The original intent — integrating LLM support into g3api — has been dropped in favor of a clean API; LLM tooling becomes a separate project consuming the generated clients. `GET /plugins` (human-facing list) stays. This also voids the "LLM client caches `/plugin/describe`" rationale that was blocking the deferred `GET /plugin/{name}` — re-evaluate that on its own merits.

### WebSockets (sequel, not this doc)

The current `/ws` is a near-PoC single feed. A planned expansion adds more subscribable event types and finer-grained subscription filters (by `scanid`/`taskid`) — **a subscription protocol over the existing socket, not a second API.** Two boundaries to record now:

- **OpenAPI does not describe WebSockets.** The event surface lives outside the generated REST clients. If generated WS clients are ever wanted, **AsyncAPI** is the counterpart spec and can `$ref` the same schema components as the OpenAPI doc. For "a few more events + filters," a documented message protocol is enough — no spec generator required.
- **Reuse domain payload types, not the HTTP decode path.** Separate transport (HTTP envelope vs WS frame) from payload (shared Go structs): WS events carry the same domain structs as their `data`. Driving WS through the request-decode machinery is the anti-pattern to avoid.

Its own design doc, written: **[`websocket-event-protocol.md`](websocket-event-protocol.md)** (2026-06-25) — flat subscription protocol, tiered event taxonomy (scan → task → logs → data/artifacts), server-side filtering + backpressure fix, and managed-vs-regular limit gating. Deferred like this doc.

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

> **Note (2026-06-24):** this section describes the *target API surface* (verbs, paths, names). The *implementation mechanism* is now code-first OpenAPI via huma, which subsumes moves #1 and #2 — see **Direction (2026-06-24)** above. Kept for the verb/path/naming rationale, which still holds.

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

**Why not chi/gin/echo/fiber?** chi is the natural escalation if middleware ever grows past `requireToken`, but the stdlib mux covers everything g3api currently needs. gin/echo are heavier than this codebase wants; fiber breaks `net/http` compatibility (would require rewriting `requireToken`). Stay on stdlib until a concrete reason to leave. *(2026-06-24: huma mounts on top of either stdlib mux (`humago`) or chi (`humachi`), so this is now just which adapter huma sits on — `net/http` compatibility is preserved either way. See Direction.)*

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
| `GET` | `/scans/{scanid}/tasks/{taskid}/artifacts` | `POST /scan/task/artifacts` | Artifacts zip download. |
| `GET` | `/scans/{scanid}/tasks/{taskid}/input` | **New endpoint** | Input data sent to this task when it was started. |
| `GET` | `/scans/{scanid}/tasks/{taskid}/output` | **New endpoint** | Output data returned from this task when it finished. Error if task is running. |

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
| `GET` | `/config/env` | `POST /config/env` | Shared `G3_ENV_*` map. `/config` is a singleton, stays singular. |

(`POST /plugin/describe` — the LLM-contract list — is **removed**; LLM tooling moves to a separate project. See *Direction (2026-06-24)*. ✅ Done 2026-06-25.)

### WebSocket (unchanged)

| Method | Path | Was | Notes |
|---|---|---|---|
| `GET` | `/ws` | `GET /ws` | HTTP/1.1 Upgrade — already GET, nothing changes. |

**Net: 28 endpoints, four new (`GET /scans/{scanid}/tasks/{taskid}`, `GET /scans/{scanid}/data/{dataid}`, and the task `…/input` + `…/output` pair), one verb change (`POST .../tasks/{id}/stop` instead of `DELETE`), and `POST /plugin/describe` removed (2026-06-24, see Direction).**

The `…/input` and `…/output` pair is *not* a routing rename like the rest of the table — it exposes data that is currently transient and requires new persistence. See *Task input/output: a persisted task↔data model* below.

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

### Task input/output: a persisted task↔data model (new functionality, not a rename)

`GET /scans/{scanid}/tasks/{taskid}/input` and `…/output` are the two table rows that add capability rather than re-route an existing handler. They expose, per task, **which data the task consumed and which data it produced** — and that mapping does not survive anywhere today.

Verified against the data model:

- **Output is genuinely transient.** A worker's result is `G3Response.Response []string` (`src/g3lib/mqtt.go`) — the mongodb ids of the `G3Data` it produced. The `G3Data` objects themselves are persisted in Mongo and are already queryable scan-wide (`GET /scans/{scanid}/data`), but the **task→produced-ids association lives only in the reply message** and is discarded once handled. For *managed* scans there is no consumer for `G3Response` in g3api at all — this is the **managed-scan reply-consumer gap**.
- **Input is recoverable but unstored.** A task's input is `G3Dispatch.DataID` (a single id, `src/g3lib/mqtt.go`), known to the dispatcher at dispatch time but not written against the task record.
- **`TaskStatusEntry` (`src/g3lib/mysql.go`) carries no data ids** — only state, worker, timestamps, and log stats. So neither endpoint can be served from what exists.

The missing primitive is small and singular: a persisted **`{taskid → inputDataID, outputDataIDs[]}`** record, written when a task is dispatched and when its `G3Response` arrives. `…/output` returns the produced-id list (or the resolved `G3Data`); per the table it **errors while the task is still running** (no terminal result yet). `…/input` returns the consumed data.

**This primitive is a convergence point — design it once, not per-consumer:**

- It is the *same* "persisted task-result model" the WebSocket sequel needs as its **Tier 2 task-event source** ([`websocket-event-protocol.md`](websocket-event-protocol.md)). REST `…/output` is the *pull* view; the WS `task.status` feed is the *push* view of the same record.
- It **closes the managed-scan reply-consumer gap** by giving managed-scan replies a durable home instead of being reconstructed lossily from logs.
- It maps directly onto **NATS JetStream KV authoritative task state** ([`nats-jetstream-consolidation.md`](nats-jetstream-consolidation.md)) — a KV key per task holding input/output ids + terminal state is precisely that doc's Tier 2.

Because the primitive is shared, these two endpoints are best treated as a thin REST surface over that model — gated on building it — not as standalone migration work. If the model lands via the NATS direction, the endpoints become a near-free read over KV.

### Response status-code contract (client-side)

Today `g3lib.MakeApiRequest` accepts any `2xx` as success. It was broadened from `== 200` after `/scan/task/dispatch`'s legitimate `202 Accepted` was surfaced to the g3tui report view as `"Failed to load report: 202 Accepted"`. The sibling helpers `DownloadFile`/`UploadFile` already document the same "2xx = success" convention. This is deliberately *permissive*: the client trusts the server to only emit success codes it means, decodes the `{status,data}` envelope regardless of which 2xx it was, and keys behavior off the envelope's `status` field, not the HTTP code.

That permissiveness is the right default for the current "everything is POST, everything returns 200 (plus one 202)" shape. An allowlist (`200,201,202`) would just re-introduce the exact bug it replaced: every new server-side code silently becomes a client "error" until someone remembers to extend the list.

The REST migration changes the calculus, because verbs acquire well-defined success codes:

- `GET` → `200 OK`
- `POST` to a collection (create) → `201 Created` (likely + `Location`)
- `POST .../{action}` async dispatch → `202 Accepted`
- `DELETE` → `204 No Content` (no body) or `200 OK`

Once success codes carry meaning, there's a real case to make the client contract *explicit per endpoint* — assert the expected code and treat anything else (even another 2xx) as a contract violation worth logging — rather than blanket-accepting the range. Tighter contracts catch server/client drift that the permissive check hides. Two concrete things to resolve when this is picked up:

- **Bodyless 2xx.** `MakeApiRequest`'s success path unconditionally `json.Unmarshal`s the body, which errors on an empty one. A `DELETE → 204 No Content` would break it. Either keep DELETE on `200 + envelope`, or teach the client to treat an empty 2xx body as a no-data success.
- **`201 Created` + `Location`.** If creates return `201` with the new id in a `Location` header rather than the `data` envelope, every client that reads the id from `data` updates in the same flag-day.

Whether to keep the permissive "any 2xx" check or move to explicit per-endpoint expected codes is a client-contract decision to make *with* the route table, not before it.

**Decided (2026-06-24):** adopt RFC 7807 `problem+json` end-to-end and **drop the `{status,data}` envelope** — it was a convenience hack, not a contract worth keeping. Success codes become real (`200`/`201`/`202`, `DELETE → 204 No Content` with no body); errors become `problem+json`. The bodyless-`204` problem disappears *with* `MakeApiRequest` itself — the generated client handles an empty 2xx natively — so the old "keep DELETE on 200+envelope" workaround is moot. The permissive "any 2xx" check is gone; generated clients key off the per-operation contract. Both Go and Python transports stop parsing `{status,data}` (the Python `_transport._envelope` + `errors.ApiError` get reworked for `problem+json`).

---

## Migration considerations

### Client coordination

Every change is a breaking API change. Clients to update in the same PR:

- **`src/g3cli/`** — the existing Go CLI client.
- **`src/g3tui/`** — the TUI client.
- **`sdk/python/`** — the Python client. **Knife couples only to the `manager` facade**, so as long as that facade's public surface is preserved, the transport beneath it (and the rest of the client) can be regenerated/rewritten at zero cost to Knife. The earlier "sequencing dilemma" (knife-first vs migration-first) therefore mostly dissolves: do the migration whenever, keep `manager`'s surface stable.
- **Any external scripts** hitting `g3api` directly — internal use only, but document the breaking change in release notes.

Note that `g3lib` itself stops being a client (see *Client story*): the transport (`MakeApiRequest`/`DownloadFile`/`UploadFile`, `Req*`) is deleted from `src/g3lib/api.go` and replaced by a generated Go client in its own package.

### Module & package layout

No separate git repo is needed — `sdk/go/` is a separate Go *module* (its own `go.mod`) in the same repo, mirroring `sdk/python/`. Two decisions make it clean:

- **The SDK owns its types (decoupled from `g3lib`).** The generator emits model structs from the spec, so this is the *default* output, not extra work. The decisive reason is **dependency contamination**: `g3lib` drags a heavy tree, and `g3cli`'s `go.mod` already lists `mongo-driver`, `redis`, and `paho.mqtt` as *indirect* deps purely because it imports `g3lib`. A publishable SDK cannot inherit that — no matter how its module path is named. Owning its types lets `sdk/go` keep **zero `replace` directives** and a clean dependency graph, go-gettable at `github.com/golismero/g3/sdk/go`.
- **The server keeps sharing `g3lib` types.** `g3api` defines huma input/output structs referencing `g3lib` domain types (`G3Data`, …); it is never published, so it can depend on `g3lib` freely. The chain is `g3api` (source of truth) → spec → SDK; server and SDK types are kept in sync *through the spec*, not a shared package — exactly how `sdk/python` already works (its `types.py` is independent of `g3lib`).

Payoff: `g3cli`/`g3tui` import the SDK and shed their accidental `g3lib` (hence mongo/redis/mqtt) indirect dependencies. In-repo submodule tags use the `sdk/go/vX.Y.Z` prefix; a separate repo is only worth it if you later want app-independent SDK semver, but the monorepo decision below (and symmetry with `sdk/python` once it's folded back) says keep it in-repo.

**Monorepo for all clients (decided 2026-06-24).** All generated clients live in this repo — `sdk/go/` and `sdk/python/` — not in per-client repos. Generated clients are *derived artifacts* of the spec, so co-location makes a breaking change one atomic PR (huma → spec → all clients regenerated in one CI run) instead of a cross-repo flag-day. This holds *because consumption is decoupled from repo layout via published artifacts*:

- **Python → PyPI** (`pip install g3client`) — repo size irrelevant to consumers.
- **Go → module proxy** (`go get github.com/golismero/g3/sdk/go@vX` once a tag is pushed) — no repo clone.

Committing to publishing is the hinge that makes monorepo strictly better than polyrepo here; it removes the "a client drags the whole server repo" cost.

**Submodule fold-back + sequencing.** `sdk/python` is *currently a git submodule* pointing at a separate `g3client-python` repo, and Knife depends on it via a git URL (`g3client @ git+https://github.com/golismero/g3client-python.git@main`), not PyPI. Fold the submodule back into `sdk/python/` **after** the PyPI publish path exists, then migrate Knife to a plain `g3client>=X` PyPI dependency — in that order, so Knife never regresses to cloning the whole monorepo. If a fold-back lands before PyPI is ready, the interim dependency is `git+https://github.com/golismero/g3.git@main#subdirectory=sdk/python` — works, but shallow-clones the full monorepo tree on each install (temporary network/disk cost, no correctness impact). History: copy-and-archive the old repo, or `git subtree`/`git-filter-repo` to fold its history inline — an execution detail for fold-back time.

### SDK generators

**Decided (2026-06-24):** open-source generators, one per language, wired into the build — no commercial/cloud SDK services (Speakeasy/Fern), which clash with the fork-friendly OSS posture and add account friction for forks.

- **Go → [ogen](https://github.com/ogen-go/ogen)** — reflection-free, type-safe, native OpenAPI v3, generates a complete idiomatic client. `g3cli`/`g3tui` consume it directly, so a complete client (not just transport) is the right fit. Conservative fallback if ogen's 3.1 support disappoints: `oapi-codegen` (widely used but 3.0-focused — would need huma to emit 3.0.3).
- **Python → [openapi-python-client](https://github.com/openapi-generators/openapi-python-client)** — modern, `httpx`-based, fully-typed models. Produces exactly the **transport + models** layer the hand-written `scanner`/`manager` facade wraps — not a competing opinionated SDK. Preferred over `openapi-generator`'s verbose `urllib3` output.

huma emits OpenAPI 3.1 by default and can also emit 3.0.3 for tooling that lags. **The one empirical thing to confirm at plan time** (generator 3.1 support shifts release-to-release): generate the prototype endpoint with each tool and eyeball output quality + whether 3.1 or 3.0.3 is needed. Direction is locked; this is a verification, not a re-decision.

### Skipped versioning

`g3api` is internal and all clients are controlled. URL versioning (`/v2/scans/...`) adds permanent complexity for a benefit that doesn't apply. Ship the migration as one flag-day breaking change with simultaneous client updates. If `g3api` ever gets exposed to a BFF or third party, *that's* the moment to add `/v1/` and start versioning forward.

### `Req*.Decode` rewrite — obsolete under huma

**Superseded by the 2026-06-24 code-first decision.** The original plan rerouted each `Req*.Decode` to pull from `r.PathValue(...)` / `r.URL.Query()` / body, with per-source helpers or reflection. Under huma there is no `Decode` method at all: input structs declare `path:`/`query:`/`json:` tags and huma does extraction + validation. The 21 identical `Decode` methods in `src/g3lib/api.go` are deleted, not rewritten. (Historical: the open question was per-source helpers vs reflection vs hand-written per-Req — moot now.)

### `Validate*` helpers retire

Under huma both `ValidateHttpRequest` and `ValidateHttpGetRequest` retire entirely — method, content-type, and body validation are handled by huma from the operation definition and input-struct tags. (The earlier "shrink to Content-Type/Content-Length" plan applied only to the hand-rolled mux approach.)

### Behavior changes to verify carefully during migration

- **Trailing slashes.** Stdlib mux has specific behavior (`/scans/` redirects to `/scans`). Worth a one-time audit.
- **405 responses.** Previously every wrong-method request got a generic 400 from `ValidateHttpRequest`. Stdlib mux will return 405 with an `Allow` header. Better but different — clients that hardcoded "400 = bad request" might confuse themselves.
- **Empty-body POSTs.** Stdlib mux doesn't enforce `Content-Length > 0`. If you keep the body-presence check in `Decode`, behavior is preserved. If you drop it, some endpoints become callable with no body.
- **Path matching precedence.** `GET /scan/list` (literal) must win over `GET /scan/{scanid}` (param). Stdlib mux 1.22 does this correctly, but worth verifying with a test of overlapping routes.

---

## Deferred items (don't tackle in this migration)

### Single-plugin lookup (`GET /plugins/{name}`)

Mostly useful for inspection / debugging. (The earlier "LLM client caches `/plugin/describe`, so no per-plugin lookup needed" reason is void now that `/plugin/describe` is removed — re-evaluate on its own merits.) Defer until a real consumer asks for it.

### File-orphan cleanup (`GET /file`, `DELETE /file/{fileid}`)

Files uploaded via `POST /file` that are never imported sit in `_uploads/` forever. Today there's no API to list orphans or clean them up. Real issue, but an ops-hygiene feature separate from the routing migration. Own ticket.

### Migration to chi

If/when middleware grows beyond just `requireToken` (request IDs, structured access logs, panic recovery, per-route timeouts, route groups, sub-routers), chi is the natural step. Stdlib mux gives routing but not declarative middleware chains. Don't preempt.

### Logging: retire the `g3/log` wrapper for `log/slog`

**Deferred (2026-06-25).** Fully orthogonal to the REST migration and to every other tier here — it touches no HTTP code, so there is no reason to bundle it. Carve it out as its own self-contained cleanup whenever it's worth doing, not as a precursor to this work.

The shape: `src/g3/log/` is an 85-line syntactic-sugar wrapper over the (unmaintained) `github.com/apsdehal/go-logger` — leveled stderr logging, bare `%{message}` format, `G3_LOG_LEVEL` switch. No DB/MQTT log-shipping, no hidden function; it lives as a subpackage of the shared `g3` module (formerly the standalone `g3log` module), shared across all binaries. The endpoint is stdlib `log/slog`: drops a dependency and makes structured access logs fall out naturally.

In practice it's more involved than a mechanical find-replace, which is why it's not free to fold into another tier:

- **Semantics, not just calls.** Custom levels `NOTICE`/`CRITICAL` have no slog equivalent — each needs a deliberate mapping (collapse into slog's four, or define custom `slog.Level` ints) and every call site re-leveled accordingly, not blindly rewritten.
- **User-visible output change across all binaries.** Bare `%{message}` becomes structured `time/level/msg`. Desirable for access logs, but anything parsing stderr today breaks, and the handler/format choice has to be made (and made consistently) per binary.
- **Cross-module coupling.** The exported `log.LogLevel` var (from `g3/log`) is read outside the logger — `src/g3lib/mqtt.go:516` gates debug behavior on it. That, plus `G3_LOG_LEVEL`, has to move to a shared `slog.LevelVar` without breaking the gate.
- **Wide and multi-module.** Every `log.*` call site across all binaries (13 files import it today), spread over six separate Go modules each with its own `go.mod` — so it also brushes up against the module-path / `go.work` cleanup.

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

Resolved by the 2026-06-24 direction:

- ~~**Exact `Req*.Decode` shape**~~ — dissolved; huma owns extraction via input-struct tags, no `Decode` methods.
- ~~**Where path-param validation lives**~~ — dissolved; `format:`/validation tags on the input struct, checked by huma before the handler.
- ~~**Whether the singular→plural rename gets bundled**~~ — decided: bundle it (pay flag-day once).
- ~~**`apiPath` prefix handling**~~ — it's the huma mount prefix (`humago`/`humachi`); verify trailing-slash redirect behavior once.
- ~~**Response shape / status codes**~~ — decided: RFC 7807 `problem+json` end-to-end, no `{status,data}` envelope, real success codes incl. `204`. (See *Response status-code contract*.)
- ~~**huma confirmation**~~ — confirmed; no prototype needed.
- ~~**Logging**~~ — split out: orthogonal to this migration, deferred as its own standalone cleanup. (See *Deferred items → Logging: retire the g3/log wrapper*.)
- ~~**Go client location**~~ — decided: `sdk/go/`, a separate module in the same repo (no separate git repo), owning its generated types, decoupled from `g3lib`. (See *Module & package layout*.)
- ~~**Client SDK generators**~~ — decided: `ogen` (Go) + `openapi-python-client` (Python); no commercial generators. (See *SDK generators*.)

Still open:

- **Python transport niceties** — the generated transport replaces the bespoke `_transport.py`; decide where its current behaviors (retries/backoff, zip-safe extraction, async-ready seam) end up — generator config vs relocated into the `scanner`/`manager` facade. The `manager` facade's public surface must stay stable for Knife.
- **Generator 3.1 verification** — confirm ogen / openapi-python-client output quality and whether huma emits 3.1 or 3.0.3 for them; a plan-time check, not a re-decision. (See *SDK generators*.)
- **WebSocket expansion** — written up in **[`websocket-event-protocol.md`](websocket-event-protocol.md)** (event types, subscription filters, OpenAPI/AsyncAPI boundary). Deferred, out of scope here.

**Likely files when scheduled:** `src/g3api/g3api.go` (route table → huma operations), `src/g3lib/api.go` (`Req*` structs → huma input/output types; `Decode`/`Validate*`/`MakeApiRequest` deleted), a new `sdk/go/` generated client + the binaries (`src/g3cli/`, `src/g3tui/`) that import it, `sdk/python/` (regenerated transport under the kept facade), plus a generated-spec artifact + client-generation tooling in the build. (The `src/g3/log/` removal is *not* in this list — it's the separate deferred logging cleanup.)
