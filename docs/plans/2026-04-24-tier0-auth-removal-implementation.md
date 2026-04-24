# Tier 0 — Auth Removal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strip user/JWT/ACL infrastructure from `g3api`, `g3cli`, and `g3lib`. Replace with a single shared bearer token (`G3_API_TOKEN`) checked in one middleware. Add WebSocket handshake auth that was previously absent. Matches the design in `docs/plans/2026-04-24-api-extensions-for-web-gui.md` (Tier 0 section).

**Architecture:** One middleware wraps every `http.HandleFunc` registration (HTTP and `/ws`). Token loaded once at startup from env; fail-fast if unset. Constant-time compare. No per-message re-auth after WS upgrade. Handlers become pure business logic. `users` and `scans` (permissions) tables, seed credentials, JWT code, login/refresh/ticket endpoints, and dead file-listing endpoints all delete out. Flat `/tmp/{uuid}.bin` for uploads — no userid namespace.

**Tech Stack:** Go 1.25, `net/http`, `gorilla/websocket`, `crypto/subtle`, MariaDB, Docker Compose.

**Testing posture:** Manual smoke per the design doc — no Go test harness is introduced. After each task, run `go build ./...` from `src/` to catch compile breaks; `golangci-lint run` before the final commit. End-to-end manual smoke in Task 8.

**PR shape:** Single PR, eight commits (one per task). The sequence is ordered so each intermediate commit compiles. Intermediate commits may leave the binary temporarily un-runnable (e.g. middleware added but not wired) — that is acceptable within a single PR and is documented per-task.

**Reference files:**
- Design: `docs/plans/2026-04-24-api-extensions-for-web-gui.md` (Tier 0)
- Server: `src/g3api/g3api.go`
- Client: `src/g3cli/g3cli.go`
- Shared lib: `src/g3lib/api.go`, `src/g3lib/sql.go`, `src/g3lib/jwt.go` (deleted)
- SQL: `volumes/mariadb/initdb.d/create_tables.sql`
- Compose: `docker-compose.yml`
- Nginx: `volumes/nginx/app.conf`
- Env: `.env`

---

## File Structure

**Modified files:**
- `src/g3api/g3api.go` — Token middleware added; all `http.HandleFunc` registrations wrapped; handler bodies stripped of `ValidateJwt`/`IsUserAuthorized` calls; `/auth/*` and `/file/{download,ls,rm}` handler registrations deleted; `/tmp/{userid}/*` path flattened.
- `src/g3cli/g3cli.go` — `Username`/`Password` CLI flags removed; login round-trip removed; `G3_API_TOKEN` read at startup; `MakeApiRequest` and WS dialer inject `Authorization: Bearer <token>`; multipart `auth` form field removed from `/file/upload` sender.
- `src/g3lib/api.go` — `ReqLogin`/`ReqRefreshJwt`/`ReqTicket` (and their response types) deleted; `Token` field removed from every `Req*` struct and from the WS message envelope.
- `src/g3lib/sql.go` — `IsUserAuthorized`, `AddUserToScan`, `RemoveUserFromScan`, `GetScansForUser`, `Login`, `GetUserID` deleted.
- `volumes/mariadb/initdb.d/create_tables.sql` — `users` and `scans` (permissions) tables deleted; both seed `INSERT`s deleted.
- `docker-compose.yml` — `G3_JWT_SECRET` and `G3_JWT_LIFETIME` env entries removed for the `g3api` service; `G3_API_TOKEN` entry added.
- `volumes/nginx/app.conf` — `/api/auth` location block deleted (lines 16-21).
- `.env` — `G3_JWT_SECRET` and `G3_JWT_LIFETIME` removed; `G3_API_TOKEN=changeme` added with operator-override comment.

**Deleted files:**
- `src/g3lib/jwt.go` — whole file.

**Untouched:** Scan engine code, MongoDB models, MQTT topology, Redis task state, `logs`/`progress` SQL tables, nginx blocks for `/api/file`, `/api/scan`, `/api/plugin`, `/api/ws`.

---

## Task 1: Add token middleware and env wiring (additive only)

**Purpose.** Introduce the `requireToken` middleware and the `G3_API_TOKEN` env reader on both server and client. Nothing is wired up yet — no handler behavior changes. The repo still uses JWT end to end after this commit.

**Files:**
- Modify: `src/g3api/g3api.go`
- Modify: `src/g3cli/g3cli.go`

**Rationale for this intermediate shape.** Isolates the new primitive as its own commit so a reviewer can look at it without any handler noise. The binary is still functional because nothing calls the middleware yet.

- [ ] **Step 1: Add imports to `src/g3api/g3api.go`**

In the existing `import` block, add (if not already present):

```go
"crypto/subtle"
"strings"
```

- [ ] **Step 2: Add the middleware helper in `src/g3api/g3api.go`**

Place this near the top of the file (below imports, above `main`). If the file already has a top-level helpers area, add it there:

```go
// requireToken wraps an http.HandlerFunc with a bearer-token check.
// Failure returns 401 before the handler runs. Intentionally also guards
// the WebSocket upgrade path — the handshake is an HTTP GET, so the
// check runs before upgrader.Upgrade() is called.
func requireToken(expected string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(hdr, "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			g3lib.SendApiError(w, http.StatusUnauthorized, "Unauthorized.")
			return
		}
		h(w, r)
	}
}
```

- [ ] **Step 3: Load `G3_API_TOKEN` at startup in `g3api`**

Find where other env vars are loaded in `main` (grep for `G3_JWT_SECRET` and add alongside). Add:

```go
apiToken := os.Getenv("G3_API_TOKEN")
if apiToken == "" {
	log.Critical("G3_API_TOKEN is required.")
	os.Exit(1)
}
```

Use the existing logger (`log.Critical` or equivalent — match style of adjacent env-required error). Keep `apiToken` in scope for the `http.HandleFunc` registrations that will consume it in Task 2.

- [ ] **Step 4: Load `G3_API_TOKEN` at startup in `g3cli`**

In `src/g3cli/g3cli.go`, in the CLI entry point (where `cmdctx` or equivalent is constructed — grep for `os.Getenv` to find the existing env-read area), add:

```go
apiToken := os.Getenv("G3_API_TOKEN")
if apiToken == "" {
	log.Critical("G3_API_TOKEN is required.")
	os.Exit(1)
}
```

Store it on `cmdctx` (or the equivalent struct) alongside `BaseURL`. It is not yet consumed — Task 2 wires it into `MakeApiRequest` and the WS dialer.

- [ ] **Step 5: Verify build passes**

```
cd src && make ../bin/g3api && make ../bin/g3cli
```

Expected: both binaries build. If Go complains about `apiToken declared and not used` on `g3cli`, mark it unused with `_ = apiToken` *only for this commit* (Task 2 removes the workaround). Document this in the commit message.

---

## Task 2: Flip to bearer auth (wrap handlers, update g3cli, remove Token field usage)

**Purpose.** Atomic behavior flip. Every HTTP and WS handler registration is wrapped in `requireToken`. Every in-handler `ValidateJwt`/`IsUserAuthorized` call is removed. `g3cli` sends bearer header instead of logging in. The login round-trip is gone. The `Token` field on request JSON is no longer read server-side or written client-side.

After this commit, a JWT-carrying client cannot authenticate and a bearer-carrying client can. This is the point of no return for the migration.

**Files:**
- Modify: `src/g3api/g3api.go`
- Modify: `src/g3cli/g3cli.go`

**Scope note.** The `Token` field remains *declared* in the request structs in `src/g3lib/api.go` — those are deleted in Task 3. This intermediate state is fine: the Go structs tolerate missing JSON fields on both ends.

- [ ] **Step 1: Wrap every non-auth `http.HandleFunc` registration**

In `src/g3api/g3api.go`, locate every `http.HandleFunc(apiPath + "/...", func(...){...})` call *except* the three `/auth/*` handlers (those get deleted in Task 3; leave them alone for this commit — their bodies will be stripped but the registrations stay until Task 3).

For every other registration (`/scan/*`, `/file/*`, `/report/*`, `/plugin/*`, `/script/*`, `/ws`, and any others in the file), refactor from:

```go
http.HandleFunc(apiPath + "/scan/stop", func(w http.ResponseWriter, r *http.Request) {
	// ... body ...
})
```

into:

```go
http.HandleFunc(apiPath + "/scan/stop", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
	// ... body ...
}))
```

This is mechanical. If the file has 15 such calls, you make 15 edits with the same pattern.

- [ ] **Step 2: Strip auth calls from handler bodies**

Inside each now-wrapped handler body, delete the auth preamble. The existing pattern is one of two forms.

**Form A — handlers that validate token and authorize against scan** (scan-scoped endpoints like `/scan/stop`, `/scan/start`, `/scan/get`, `/scan/list` with share, `/scan/progress` when ACL was present, `/report/*`, `/plugin/*`, `/script/*`):

Delete this block at the top of each handler body:

```go
userid, err := g3lib.ValidateJwt(request.Token)
if err != nil {
	log.Error(err)
	g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
	return
}
isAuthorized, err := g3lib.IsUserAuthorized(sql_db, userid, request.ScanID)
if err != nil {
	log.Error(err)
	g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
	return
}
if isAuthorized != 1 {
	log.Error("Not authorized.")
	g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
	return
}
```

Also delete any subsequent references to the local `userid` variable in that handler's body — grep each handler after the edit. Examples: `/scan/start` uses `userid` to build `/tmp/%d/%s.bin` (that gets rewritten in Task 4); `/scan/get` uses `userid` to call `AddUserToScan`; just remove both calls. The scan will still be created in MongoDB and linked by `ScanID` as before — ACL was the only thing the `userid` touched.

**Form B — handlers with `// no authorization needed`** (the four endpoints: `/scan/progress`, `/scan/tasks`, `/scan/logs`, `/scan/tasks/status`):

Delete this block:

```go
_, err = g3lib.ValidateJwt(request.Token) // no authorization needed
if err != nil {
	log.Error(err)
	g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
	return
}
```

(Some of these have `_, err :=` rather than `_, err =` depending on whether `err` was already declared above — the compiler will tell you. Adjust to match the surrounding scope.)

**Form C — `/file/upload`** reads auth out of the multipart form:

Find the code that parses the `auth` form field (around the existing `ParseMultipartForm` block). Delete any use of the form-level `auth` string and any `ValidateJwt` call on it. Also delete any use of `userid` that derives from it — Task 4 flattens the `/tmp` path.

**Form D — `/ws` handler**:

Delete any JWT validation inside the WS handler body. It's now gated at the middleware. The handler keeps its upgrade call and its message loop; per-message `Token` handling inside the loop stays for this commit (Task 3 strips the field from the envelope struct).

- [ ] **Step 3: Update `g3cli`'s `MakeApiRequest` to send bearer header**

In `src/g3cli/g3cli.go`, the existing request code uses `g3lib.MakeApiRequest(ctx, cmdctx.BaseURL, path, request)`. That helper lives in `g3lib`. We have two compatible paths:

**Path A (preferred):** Modify `g3lib.MakeApiRequest` to accept an `Authorization` header value, and pass it from every call site. This is a small signature change but it keeps the cred injection in one place.

```go
// In src/g3lib/api.go, update MakeApiRequest's signature:
func MakeApiRequest(ctx context.Context, baseURL string, path string, token string, body any) (*ApiResponse, error) {
	// ... existing marshal code ...
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL + path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer " + token)
	// ... existing do+decode code ...
}
```

Update every call site in `src/g3cli/g3cli.go` to pass `cmdctx.ApiToken` (or whichever field Task 1 named). Grep for `MakeApiRequest(` to find them all.

**Path B (fallback if `MakeApiRequest` is also used somewhere else in a way that makes a signature change messy):** Drop to `http.NewRequest` inline in `g3cli` and set the header there. Prefer Path A if feasible.

- [ ] **Step 4: Remove the login / refresh round-trip from `g3cli`**

Delete the login block at `src/g3cli/g3cli.go:182-194` (the `ReqLogin` / `MakeApiRequest("/auth/login", …)` sequence and the `token, ok := loginResp.Data.(string)` assertion that follows).

Remove any refresh code in the CLI. Grep `g3cli.go` for `/auth/refresh` and `/auth/ticket` — delete those blocks.

Remove the `Username` and `Password` CLI flags — grep `Kong`/`CLI struct` / `--username` / `--password` to find them.

- [ ] **Step 5: Update `/file/upload` sender in `g3cli`**

Around `src/g3cli/g3cli.go:252-356` (upload helper), find the multipart form construction. Delete the `writer.CreateFormField("auth")` line (circa line 278) and the subsequent write of the JWT string into that field. The multipart request now relies on the HTTP-level `Authorization` header set via `http.Request.Header.Set("Authorization", "Bearer "+apiToken)` at the call-site before `http.DefaultClient.Do`.

Add the header explicitly since this upload path likely builds its own `http.Request` (not via `MakeApiRequest`):

```go
req.Header.Set("Authorization", "Bearer " + cmdctx.ApiToken)
```

- [ ] **Step 6: Update the WS dialer in `g3cli`**

Grep `g3cli.go` for `DialContext(` or `websocket.Dialer`. Find where the JWT-bearing `http.Header` is assembled. Replace it with:

```go
headers := http.Header{}
headers.Set("Authorization", "Bearer " + cmdctx.ApiToken)
conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, headers)
```

If the handshake previously carried a JWT in some other way, mirror the same replacement.

- [ ] **Step 7: Verify build passes on both binaries**

```
cd src && make ../bin/g3api && make ../bin/g3cli
```

Expected: both build clean. Any remaining `undefined: userid` or `unused: err` is a missed edit from Step 2 — fix before proceeding.

---

## Task 3: Delete dead endpoints and unused request/response types

**Purpose.** Remove the now-unused `/auth/*` and `/file/{download,ls,rm}` endpoints, and the request/response structs that only those handlers referenced. Remove the `Token` field from remaining `Req*` structs and from the WS envelope.

**Files:**
- Modify: `src/g3api/g3api.go`
- Modify: `src/g3lib/api.go`

- [ ] **Step 1: Delete `/auth/*` handler registrations in `src/g3api/g3api.go`**

Delete the three blocks registering `/auth/login` (around line 254), `/auth/refresh` (around line 295), and `/auth/ticket` (around line 320). Delete their whole `http.HandleFunc(...)` invocation, including the closing paren and semicolon.

- [ ] **Step 2: Delete `/file/download`, `/file/ls`, `/file/rm` handler registrations**

Grep `src/g3api/g3api.go` for `/file/download`, `/file/ls`, and `/file/rm`. Delete each matching `http.HandleFunc(...)` block in full.

- [ ] **Step 3: Delete corresponding request/response types in `src/g3lib/api.go`**

Delete these type declarations:
- `ReqLogin`, `RespLogin` (or the shape used for `/auth/login`)
- `ReqRefreshJwt`, `RespRefreshJwt`
- `ReqTicket`, `RespTicket`
- Any `ReqFileDownload`, `ReqFileList`, `ReqFileRemove` types and their responses.

Grep the repo for each type name first to confirm no other caller exists. The compiler is the second check.

- [ ] **Step 4: Remove `Token` field from remaining `Req*` structs**

In `src/g3lib/api.go`, grep for `Token` struct fields. Every remaining `Req*` (those not deleted above) carries a `Token string` field — remove it. Also remove it from the WS message envelope struct (grep for `WsMessage`, `WsReq`, or similar — match the existing naming).

- [ ] **Step 5: Verify build passes**

```
cd src && make ../bin/g3api && make ../bin/g3cli
```

Expected: both build. If `undefined: ReqLogin` appears, it means a caller wasn't fully removed in Task 2 — return and finish.

- [ ] **Step 6: Verify nothing else references the deleted endpoints**

```
cd /home/crapula/code/g3 && grep -rn "auth/login\|auth/refresh\|auth/ticket\|file/download\|file/ls\|file/rm" src/ scripts/ tests/ docs/ 2>/dev/null
```

Expected: no hits in `src/`. Any hit in `docs/` is a documentation cleanup that gets folded into this commit. Any hit in `scripts/` is genuinely surprising and needs investigation.

---

## Task 4: Flatten `/tmp/{userid}/{uuid}.bin` → `/tmp/{uuid}.bin`

**Purpose.** Remove the userid segment from upload paths. `/file/upload` and `/scan/start` are the only callers.

**Files:**
- Modify: `src/g3api/g3api.go`

- [ ] **Step 1: Update `/file/upload` handler**

Find the upload handler in `src/g3api/g3api.go`. Locate the `os.MkdirAll` call that creates `/tmp/{userid}` and the `fmt.Sprintf("/tmp/%d/%s.bin", userid, uuid)` (or equivalent) path construction.

Replace with:

```go
inputfile := fmt.Sprintf("/tmp/%s.bin", fileUUID)
```

(Name the UUID variable whatever Task 2's upload already named it — follow the existing style.)

Delete the `os.MkdirAll` call entirely. `/tmp` already exists; the UUID namespace is flat.

- [ ] **Step 2: Update `/scan/start` handler**

The `/scan/start` handler reads the uploaded file (around the `g3api.go:437-489` area referenced in the design). Find the line constructing:

```go
inputfile := fmt.Sprintf("/tmp/%d/%s.bin", userid, parsedImport.Path)
```

Replace with:

```go
inputfile := fmt.Sprintf("/tmp/%s.bin", parsedImport.Path)
```

- [ ] **Step 3: Verify build passes**

```
cd src && make ../bin/g3api
```

Expected: clean build.

---

## Task 5: Delete JWT and user/ACL helpers from `g3lib`

**Purpose.** Remove the now-dead identity machinery.

**Files:**
- Delete: `src/g3lib/jwt.go`
- Modify: `src/g3lib/sql.go`

- [ ] **Step 1: Confirm `g3lib/jwt.go` has no remaining callers**

```
cd /home/crapula/code/g3 && grep -rn "ValidateJwt\|GenerateJwt\|GenerateTemporaryJwt" src/ 2>/dev/null
```

Expected: no hits outside `src/g3lib/jwt.go` itself. If any hit, return to Task 2 or Task 3 and finish the removal there — do not proceed.

- [ ] **Step 2: Delete `src/g3lib/jwt.go`**

```
git rm src/g3lib/jwt.go
```

- [ ] **Step 3: Confirm no remaining callers of user/ACL helpers**

```
cd /home/crapula/code/g3 && grep -rn "IsUserAuthorized\|AddUserToScan\|RemoveUserFromScan\|GetScansForUser\|\\bLogin\\b\|GetUserID" src/ 2>/dev/null
```

Expected: no hits outside `src/g3lib/sql.go` (where the functions are defined and about to be deleted). `\bLogin\b` avoids matching substrings like `loginResp`.

- [ ] **Step 4: Delete the six functions in `src/g3lib/sql.go`**

Remove these function declarations (and only these — leave other helpers untouched):
- `IsUserAuthorized`
- `AddUserToScan`
- `RemoveUserFromScan`
- `GetScansForUser`
- `Login`
- `GetUserID`

If any of these functions share a private helper that is now unused (grep after deletion), remove the helper too.

- [ ] **Step 5: Verify build passes**

```
cd src && make all
```

Expected: every binary builds. `make all` is used here specifically to catch any downstream binary that imports `g3lib` and referenced a removed function.

- [ ] **Step 6: Run linter**

```
cd /home/crapula/code/g3 && golangci-lint run ./src/...
```

Expected: clean, except for lint issues that existed before this work. Any new `unused` warning means a helper got stranded — delete it.

---

## Task 6: Simplify SQL schema

**Purpose.** Drop the `users` table, the `scans` permissions table, and both seed `INSERT`s. The file shrinks to the `logs` and `progress` tables only.

**Files:**
- Modify: `volumes/mariadb/initdb.d/create_tables.sql`

- [ ] **Step 1: Rewrite `create_tables.sql`**

Replace the entire file content with:

```sql
-- SQL tables for Golismero3.

-- Tool execution logs.
CREATE TABLE `golismero`.`logs` (
    `id` INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
    `timestamp` INTEGER NOT NULL,
    `scanid` UUID NOT NULL,
    `taskid` UUID NOT NULL,
    `text` TEXT NOT NULL,
    INDEX (`scanid`, `taskid`)
) ENGINE = InnoDB;

-- Scan progress updates.
CREATE TABLE `golismero`.`progress` (
    `id` INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
    `scanid` UUID UNIQUE NOT NULL,
    `status` TEXT NOT NULL DEFAULT "WAITING",
    `progress` INTEGER NOT NULL DEFAULT 0,
    `message` TEXT NOT NULL DEFAULT ""
) ENGINE = InnoDB;
```

- [ ] **Step 2: Confirm no other schema artifacts reference `users` or `scans` (permissions)**

```
cd /home/crapula/code/g3 && grep -rn "users\b\|\\bscans\b" volumes/mariadb/ 2>/dev/null
```

Expected: only the edited file. If any `.sql` seed or migration file references `users` or `scans`, evaluate whether it's dead too and delete if so.

---

## Task 7: Update `.env`, `docker-compose.yml`, and nginx config

**Purpose.** Add `G3_API_TOKEN` plumbing, remove `G3_JWT_SECRET`/`G3_JWT_LIFETIME`, delete the `/api/auth` nginx location block.

**Files:**
- Modify: `.env`
- Modify: `docker-compose.yml`
- Modify: `volumes/nginx/app.conf`

- [ ] **Step 1: Update `.env`**

Remove the two lines:

```
G3_JWT_SECRET=putyourjwtsecrethere
G3_JWT_LIFETIME=10
```

Add in their place:

```
# Shared bearer token for g3api. Override in any real deployment; the
# default is for local dev only. Matches the posture of SQL_PASSWORD,
# REDIS_PASSWORD, etc. — hardcoded for docker-compose convenience.
G3_API_TOKEN=changeme
```

Keep the new lines within the `G3_API_*` grouping (before `G3_WS_ADDR`).

- [ ] **Step 2: Update `docker-compose.yml`**

Open `docker-compose.yml` and locate lines 219-220 (under the `g3api` service's `environment:` block):

```yaml
      - G3_JWT_SECRET
      - G3_JWT_LIFETIME
```

Replace those two lines with:

```yaml
      - G3_API_TOKEN
```

The bare-key form picks up the value from `.env` — matching how `REDIS_PORT`, `REDIS_PASSWORD`, `G3_WS_BUFFER`, etc. are passed through in this file.

- [ ] **Step 3: Delete the `/api/auth` location block in `volumes/nginx/app.conf`**

Open the file and delete lines 16-21:

```
    location /api/auth {
        proxy_pass          http://g3api/auth;
        proxy_set_header    Host                $http_host;
        proxy_set_header    X-Real-IP           $remote_addr;
        proxy_set_header    X-Forwarded-For     $proxy_add_x_forwarded_for;
    }
```

Leave the blank line separating it from `/api/file` for readability (or close up — cosmetic).

Leave `/api/file`, `/api/scan`, `/api/plugin`, and `/api/ws` blocks intact.

- [ ] **Step 4: Grep for any remaining `JWT` or `admin:admin` references**

```
cd /home/crapula/code/g3 && grep -rn "JWT_SECRET\|JWT_LIFETIME\|admin:admin\|user:user" --exclude-dir=.git 2>/dev/null
```

Expected: no hits. Any hit in `docs/` is a doc cleanup that should be folded into this commit. Any hit in actual config (`.env*`, `compose*`, `volumes/**/*.conf`) is a missed edit — fix before committing.
