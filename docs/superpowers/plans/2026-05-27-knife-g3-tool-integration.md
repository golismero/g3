# Knife g3 tool integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let knife's LLM agents invoke individual g3 security tools against a remote g3 deployment, via additive g3api extensions (managed scans) plus a standalone Python client library.

**Architecture:** Build on g3api (not the CLI, not direct-to-infra). Add a `MANAGED` scan status the orchestrator never touches, a handful of managed-only endpoints for seeding data / importing / dispatching / fetching results, a `/plugin/describe` tool-contract endpoint sourced from additive `.g3p` `llm` metadata, and a `/config/env` endpoint. Ship a Python library that wraps all of this in scan-scoped, data-only calls.

**Tech Stack:** Go 1.25 (g3lib + g3api + g3config, separate modules with `replace` directives), JSON5/Jsonnet (`.g3p`), Python 3 (client library), Docker.

**Spec:** `docs/superpowers/specs/2026-05-27-knife-g3-tool-integration-design.md`

---

## Project conventions (override default skill behavior)

These reflect standing user preferences and **override** the writing-plans skill's TDD/commit defaults:

- **Tests are user-owned.** Do **not** write tests, run binaries, or hit live servers. Verification for every task is strictly **build + lint**.
- **Git is user-owned.** Do **not** run any mutating git command (`add`/`commit`/`mv`/`rm`/`push`). The user commits at the **end of each tier** in one batch. Read-only git inspection is fine.
- **Tiered execution.** All tiers are outlined below; only **Tier 1 is detailed**. Stop at the end of each tier and revisit with the user before detailing/starting the next tier.
- **No formatting enforcement.** Lint is correctness-only (`golangci-lint`, `ruff`). Never add gofmt/goimports/gci/ruff-format steps.
- **Go version source of truth** is `src/*/go.mod`, not CLAUDE.md or Dockerfiles.

---

## Tier overview

- **Tier 1 — g3lib foundations (DETAILED below).** Additive shared types/helpers every later tier depends on: `STATUS_MANAGED`, the `.g3p` `llm` metadata struct, a task-filtered data query, and a `G3_ENV_*` accessor. Pure additions to `src/g3lib`; no behavior changes to existing code.
- **Tier 2 — g3api managed-scan endpoints (outline).** `/scan/create` (managed, no `SendNewScan`, `MkdirAll` scan dir), `/scan/target/add` (reuse `BuildTargets`), `/scan/data/insert` (reuse `IsValidData`), `/scan/import` (reuse `importOne`), and the `/scan/data` optional `taskid` filter. Shared managed-only gate helper. New request structs in `src/g3lib/api.go`.
- **Tier 3 — tool contract surface (outline).** `/plugin/describe` (response shaping + fallback when `llm` absent) and `/config/env` (returns `GetSharedEnv()`). Add example `llm:` blocks to a few representative `.g3p` files (e.g. nikto, nmap, hydra). Confirm `g3config` passes the field through unchanged.
- **Tier 4 — Python client library (outline).** New `clients/python/` package: transport (bearer auth, multipart upload, streaming artifact download + zip/tar.gz extraction to disk), scan-scoped data-only API, tool-contract discovery + cache, polling helper, and the `G3DATA_PRIMER` module constant.

---

## Tier 1 — g3lib foundations

All changes are additive and confined to `src/g3lib`. g3lib is a module consumed by g3api/g3scanner/g3worker/g3/g3cli/g3config via `replace` directives, so the tier-end build confirms nothing downstream broke.

### Task 1: Add the `MANAGED` scan status

**Files:**
- Modify: `src/g3lib/task.go:60-69`

- [ ] **Step 1: Add the constant and extend the valid-status list**

Replace the `G3SCANSTATUS` const block and `VALID_STATUS` (currently `src/g3lib/task.go:60-69`) with:

```go
type G3SCANSTATUS string
const (
	STATUS_WAITING  G3SCANSTATUS = "WAITING"
	STATUS_RUNNING  G3SCANSTATUS = "RUNNING"
	STATUS_ERROR    G3SCANSTATUS = "ERROR"
	STATUS_CANCELED G3SCANSTATUS = "CANCELED"
	STATUS_FINISHED G3SCANSTATUS = "FINISHED"
	STATUS_UNKNOWN  G3SCANSTATUS = "UNKNOWN"
	STATUS_MANAGED  G3SCANSTATUS = "MANAGED"  // Externally-managed scan; g3scanner never emits or overwrites this.
)
var VALID_STATUS = [...]G3SCANSTATUS{STATUS_WAITING, STATUS_RUNNING, STATUS_ERROR, STATUS_CANCELED, STATUS_FINISHED, STATUS_UNKNOWN, STATUS_MANAGED}
```

- [ ] **Step 2: Build g3lib to verify it compiles**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

- [ ] **Step 3: Lint g3lib**

Run: `cd src/g3lib && golangci-lint run ./...`
Expected: no issues reported.

### Task 2: Add the additive `.g3p` LLM metadata struct

**Files:**
- Modify: `src/g3lib/plugin.go` (add structs after `G3ReporterPhase`, currently ending at line 63; add a field to `G3Plugin`, currently lines 65-74)

- [ ] **Step 1: Define the LLM metadata structs**

Insert immediately after the `G3ReporterPhase` struct (after `src/g3lib/plugin.go:63`):

```go
// G3LLMCommandNote is an optional per-command note for LLM consumers. Its
// position in the slice corresponds to the same index in G3Plugin.Commands.
type G3LLMCommandNote struct {
	Description string `json:"description,omitempty"` // What this command variant does.
}

// G3LLMMetadata is optional, additive metadata describing a plugin's tool
// contract for LLM/MCP consumers (served by /plugin/describe). It is absent for
// plugins that have not been annotated; consumers fall back to other fields.
type G3LLMMetadata struct {
	Summary  string             `json:"summary,omitempty"`  // LLM-specific one-line explanation of the tool.
	Accepts  []string           `json:"accepts,omitempty"`  // G3Data _type(s) this plugin consumes.
	Produces string             `json:"produces,omitempty"` // Primary G3Data _type produced.
	Commands []G3LLMCommandNote `json:"commands,omitempty"` // (Optional) Per-command notes, indexed to Commands[].
}
```

- [ ] **Step 2: Add the optional field to `G3Plugin`**

In the `G3Plugin` struct (`src/g3lib/plugin.go:65-74`), add the `LLM` field after the existing `Reporter` field so the struct reads:

```go
type G3Plugin struct {
	Name        string              `json:"name"`                                           // Tool name. Must be unique.
	Description map[string]string   `json:"description"`                                    // Description for humans, translated.
	URL         string              `json:"url"                 validate:"url"`             // URL for humans.
	Image       string              `json:"image"`                                          // Docker image.
	Commands    []G3ToolCommand     `json:"commands,omitempty"  validate:"omitempty,dive"`  // (Optional) Array of commands and conditions.
	Importer    *G3ImporterCommand  `json:"importer,omitempty"  validate:"omitempty"`       // (Optional) Command for importing files.
	Merger      *G3MergerCommand    `json:"merger,omitempty"    validate:"omitempty"`       // (Optional) Command for merging issues.
	Reporter    *G3ReporterPhase    `json:"reporter,omitempty"  validate:"omitempty"`       // (Optional) Phase for generating downloadable reports.
	LLM         *G3LLMMetadata      `json:"llm,omitempty"       validate:"omitempty"`       // (Optional) Additive metadata for LLM/MCP consumers.
}
```

- [ ] **Step 3: Build g3lib to verify it compiles**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

- [ ] **Step 4: Lint g3lib**

Run: `cd src/g3lib && golangci-lint run ./...`
Expected: no issues reported.

### Task 3: Add a task-filtered data query helper

**Files:**
- Modify: `src/g3lib/datastore.go` (add a function next to `LoadFingerprintMatches`, currently at line 121)

- [ ] **Step 1: Add `LoadDataByTask`**

Insert after the `LoadFingerprintMatches` function (after `src/g3lib/datastore.go:129`):

```go
// Fetch all data objects produced by a specific task within a scan.
func LoadDataByTask(dbclient DatastoreClient, scanid, taskid string) ([]G3Data, error) {
	query := bson.M{"_taskid": taskid}
	var jsonArray []G3Data
	err := LoadDataWithCallback(dbclient, scanid, query, func(data G3Data)(error) {
		jsonArray = append(jsonArray, data)
		return nil
	})
	return jsonArray, err
}
```

- [ ] **Step 2: Build g3lib to verify it compiles**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

- [ ] **Step 3: Lint g3lib**

Run: `cd src/g3lib && golangci-lint run ./...`
Expected: no issues reported.

### Task 4: Add the shared-environment accessor

**Files:**
- Modify: `src/g3lib/common.go` (add a function after `GetEnvironmentMap`, currently at lines 88-96)

- [ ] **Step 1: Add `GetSharedEnv`**

Insert immediately after the `GetEnvironmentMap` function (after `src/g3lib/common.go:96`). `strings` is already imported in this file (used at line 91), so no import change is needed:

```go
// GetSharedEnv returns the subset of environment variables whose names begin
// with the "G3_ENV_" prefix. These are the deployment-wide capability flags
// g3worker injects into every plugin container (e.g. G3_ENV_IPV6_SUPPORTED).
// Exposed read-only via the g3api /config/env endpoint.
func GetSharedEnv() map[string]string {
	shared := make(map[string]string)
	for name, value := range GetEnvironmentMap() {
		if strings.HasPrefix(name, "G3_ENV_") {
			shared[name] = value
		}
	}
	return shared
}
```

- [ ] **Step 2: Build g3lib to verify it compiles**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

- [ ] **Step 3: Lint g3lib**

Run: `cd src/g3lib && golangci-lint run ./...`
Expected: no issues reported.

### Task 5: Tier-end full build

**Files:** none (verification only)

- [ ] **Step 1: Build every Go binary to confirm the additive g3lib changes break nothing downstream**

Run: `cd src && make bin`
Expected: all binaries (`g3`, `g3api`, `g3cli`, `g3config`, `g3scanner`, `g3worker`) build with exit code 0.

- [ ] **Step 2: Hand off to the user for commit**

Tier 1 is code-complete. Per project convention, the **user** reviews and commits the tier as one batch. Do not run git. Report what changed (the four g3lib additions) and stop for the tier checkpoint before Tier 2.

---

## Tier 2 — g3api managed-scan endpoints

**Resolved decisions for this tier:** managed-only gate returns **409 Conflict** ("Operation requires a managed scan"). `/scan/create` is a **separate handler** (not a flag on `/scan/start`).

All new endpoints live in `src/g3api/g3api.go` behind the existing `requireToken` wrapper. Tasks are sequenced so each step's dependencies are in place.

### Task 1: New request structs in `src/g3lib/api.go`

**Files:**
- Modify: `src/g3lib/api.go` — add four new request types + a `taskid` field on `ReqLoadData`.

- [ ] **Step 1: Add the new request types**

Insert these four types, plus their `Decode` methods, somewhere among the existing `Req*` definitions in `src/g3lib/api.go` (e.g. immediately after `ReqStartScan`'s Decode block at lines 178-186). Each `Decode` follows the existing pattern verbatim (validate request → decode body → validate struct).

```go
type ReqCreateScan struct {
}
func (req *ReqCreateScan) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqAddTargets struct {
	ScanID  string   `json:"scanid"              validate:"uuid"`
	Targets []string `json:"targets"             validate:"required,min=1,dive,required"`
}
func (req *ReqAddTargets) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqInsertData struct {
	ScanID string   `json:"scanid"              validate:"uuid"`
	Data   []G3Data `json:"data"                validate:"required,min=1"`
}
func (req *ReqInsertData) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqImport struct {
	ScanID string `json:"scanid"              validate:"uuid"`
	Tool   string `json:"tool"                validate:"required"`
	FileID string `json:"fileid"              validate:"required,uuid4"`
}
func (req *ReqImport) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}
```

- [ ] **Step 2: Extend `ReqLoadData` with an optional `TaskID`**

Replace the existing `ReqLoadData` struct (currently `src/g3lib/api.go:231-234`) with:

```go
type ReqLoadData struct {
	ScanID  string   `json:"scanid"              validate:"uuid"`
	DataIDs []string `json:"dataids"             validate:"omitempty,dive,mongodb"`
	TaskID  string   `json:"taskid,omitempty"    validate:"omitempty,uuid4"`
}
```

Its `Decode` method (lines 235-239) needs no changes.

- [ ] **Step 3: Build g3lib**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 4: Lint g3lib**

Run: `cd /home/crapula/code/g3/src/g3lib && golangci-lint run ./...`
Expected: 0 issues.

### Task 2: Add the managed-only gate helper in `src/g3api/g3api.go`

**Files:**
- Modify: `src/g3api/g3api.go` — add a private helper near the top of the file (after `requireToken` at lines 41-51).

- [ ] **Step 1: Add `requireManagedScan`**

Insert after the closing `}` of `requireToken` in `src/g3api/g3api.go` (after line 51):

```go
// requireManagedScan looks up the scan's progress row and returns nil when its
// status is STATUS_MANAGED. On any other state — including missing scan or
// non-managed scan — it writes the appropriate API error to w and returns a
// non-nil error so the caller can return early.
func requireManagedScan(w http.ResponseWriter, db g3lib.SQLDBClient, scanid string) error {
	entry, err := g3lib.GetScanStatus(db, scanid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			g3lib.SendApiError(w, http.StatusNotFound, "Scan does not exist.")
			return err
		}
		log.Error(err)
		g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
		return err
	}
	if entry.Status != g3lib.STATUS_MANAGED {
		g3lib.SendApiError(w, http.StatusConflict, "Operation requires a managed scan.")
		return errors.New("scan is not managed: " + scanid)
	}
	return nil
}
```

`errors`, `sql`, `http`, `g3lib`, and `log` are already imported in this file.

- [ ] **Step 2: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 3: `/scan/create` handler

**Files:**
- Modify: `src/g3api/g3api.go` — add a new `http.HandleFunc` registration alongside the others (a natural spot is right after `/scan/start`'s closing `}))` at line 532).

- [ ] **Step 1: Register the handler**

Insert immediately after the `/scan/start` handler's closing `}))` (after `src/g3api/g3api.go:532`):

```go
		///////////////////////////////////////////////////////////////////////////////////////////
		// Create a new externally-managed scan. The scan exists in the progress
		// table with STATUS_MANAGED so the orchestrator never claims it; no
		// G3Scan is published, no pipelines run. Used by external clients (e.g.
		// the Python g3client) to host on-demand task dispatch.
		http.HandleFunc(apiPath + "/scan/create", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/create")
			var request g3lib.ReqCreateScan
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			scanid := uuid.NewString()

			// Write the progress row first so subsequent managed-only calls find
			// the scan via GetScanStatus, then mark it MANAGED.
			if err := g3lib.InsertScanProgress(sql_db, scanid); err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}
			if err := g3lib.UpdateScanProgress(sql_db, scanid, g3lib.STATUS_MANAGED, nil, "Externally managed."); err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// g3api owns _uploads/, <scanid>/imports/, and <scanid> deletion;
			// owning <scanid> creation for managed scans is consistent.
			if err := os.MkdirAll(filepath.Join(artifactsRoot, scanid), 0o755); err != nil {
				log.Error("Cannot create scan dir: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			g3lib.SendApiResponse(w, scanid)
		}))
```

`uuid`, `os`, and `filepath` are already imported in `src/g3api/g3api.go`.

- [ ] **Step 2: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 4: `/scan/target/add` handler

**Files:**
- Modify: `src/g3api/g3api.go` — add another `http.HandleFunc` registration after the `/scan/create` handler from Task 3.

- [ ] **Step 1: Register the handler**

Insert immediately after the `/scan/create` handler's closing `}))`:

```go
		///////////////////////////////////////////////////////////////////////////////////////////
		// Add targets to a managed scan. Reuses BuildTargets so canonicalization
		// (URL parsing, loopback rejection, _type/_fp synthesis) stays identical
		// to the existing `target X` script directive. Returns the inserted
		// Mongo IDs so the caller can immediately dispatch tasks against them.
		http.HandleFunc(apiPath + "/scan/target/add", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/target/add")
			var request g3lib.ReqAddTargets
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			targetData, err := g3lib.BuildTargets(request.Targets)
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusBadRequest, "Invalid target: " + err.Error())
				return
			}

			ids, err := g3lib.SaveData(mdb_client, request.ScanID, g3lib.NIL_TASKID, targetData)
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			g3lib.SendApiResponse(w, ids)
		}))
```

- [ ] **Step 2: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 5: `/scan/data/insert` handler

**Files:**
- Modify: `src/g3api/g3api.go` — add another `http.HandleFunc` registration after Task 4.

- [ ] **Step 1: Register the handler**

Insert immediately after the `/scan/target/add` handler's closing `}))`:

```go
		///////////////////////////////////////////////////////////////////////////////////////////
		// Insert raw G3Data objects into a managed scan. Each object is validated
		// server-side via IsValidData; malformed objects are rejected with 400
		// before any write occurs. Returns the inserted Mongo IDs.
		http.HandleFunc(apiPath + "/scan/data/insert", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/data/insert")
			var request g3lib.ReqInsertData
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			for i, obj := range request.Data {
				if _, err := g3lib.IsValidData(obj); err != nil {
					log.Error(err)
					g3lib.SendApiError(w, http.StatusBadRequest, fmt.Sprintf("Invalid data at index %d: %s", i, err.Error()))
					return
				}
			}

			ids, err := g3lib.SaveData(mdb_client, request.ScanID, g3lib.NIL_TASKID, request.Data)
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			g3lib.SendApiResponse(w, ids)
		}))
```

`fmt` is already imported in `src/g3api/g3api.go`.

- [ ] **Step 2: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 6: Extract `importOne` into a reusable helper

**Files:**
- Modify: `src/g3api/g3api.go` — extract the importer body (currently the `importOne` closure at lines 442-513 inside `/scan/start`) into a free function `runImport`, and refactor `/scan/start` to call it.

**Why this task:** The new `/scan/import` endpoint (Task 7) needs the same import logic — running the plugin's importer container against an uploaded file and saving the results. Duplicating ~70 lines of Docker-spawning code is the wrong move; extracting once preserves a single source of truth.

- [ ] **Step 1: Add the `runImport` helper**

Add a new free function somewhere top-level in `src/g3api/g3api.go` (e.g. immediately before `func Main()` — pick a logical spot; a good location is right after `requireManagedScan` from Task 2).

```go
// runImport relocates an uploaded file (identified by fileid) into the scan's
// imports/ directory, runs the plugin's importer container, and saves the
// resulting data objects into the scan. Returns the inserted Mongo IDs.
//
// The returned httpStatus tells callers which HTTP code to send on error:
//   - 400 when the request is bad (unknown tool, no importer phase, missing file)
//   - 500 when setup/run/save fails for internal reasons
// httpStatus is meaningful only when err != nil; on success it is 0.
func runImport(plugins g3lib.G3PluginMetadata, mdb g3lib.DatastoreClient, artifactsRoot, scanid, tool, fileid string) (ids []string, httpStatus int, err error) {
	plugin, ok := plugins[tool]
	if !ok || plugin.Importer == nil {
		return nil, http.StatusBadRequest, errors.New("tool not found or has no importer: " + tool)
	}

	if !govalidator.IsUUIDv4(fileid) {
		return nil, http.StatusBadRequest, errors.New("invalid file ID: " + fileid)
	}

	importsDir := filepath.Join(artifactsRoot, scanid, "imports")
	if err := os.MkdirAll(importsDir, 0o755); err != nil {
		return nil, http.StatusInternalServerError, errors.New("cannot create imports dir " + importsDir + ": " + err.Error())
	}
	srcBin := filepath.Join(artifactsRoot, "_uploads", fileid+".bin")
	srcTxt := filepath.Join(artifactsRoot, "_uploads", fileid+".txt")
	inputfile := filepath.Join(importsDir, fileid+".bin")
	dstTxt := filepath.Join(importsDir, fileid+".txt")
	if err := os.Rename(srcBin, inputfile); err != nil {
		return nil, http.StatusBadRequest, errors.New("cannot relocate upload " + fileid + ": " + err.Error())
	}
	if err := os.Rename(srcTxt, dstTxt); err != nil {
		log.Error("Cannot relocate upload metadata " + fileid + ": " + err.Error())
	}
	stdin, openErr := os.Open(inputfile)
	if openErr != nil {
		return nil, http.StatusBadRequest, errors.New("cannot open file " + inputfile + ": " + openErr.Error())
	}
	defer stdin.Close()

	parsedCommand, errA := g3lib.BuildImporterCommand(plugin)
	if len(errA) > 0 {
		for _, e := range errA {
			log.Error(" - " + e.Error())
		}
		return nil, http.StatusInternalServerError, errors.New("error building importer command for " + plugin.Name)
	}
	ctx := context.Background() // FIXME this may have to be run as a task after all...
	stderr := os.Stderr         // FIXME send this log to the database
	targetData, runErr := g3lib.RunPluginImporter(ctx, plugin, parsedCommand, stdin, stderr)
	if runErr != nil {
		return nil, http.StatusInternalServerError, errors.New("error running importer " + plugin.Name + ": " + runErr.Error())
	}

	ids, saveErr := g3lib.SaveData(mdb, scanid, g3lib.NIL_TASKID, targetData)
	if saveErr != nil {
		return nil, http.StatusInternalServerError, errors.New("error saving imported data for " + plugin.Name + ": " + saveErr.Error())
	}
	log.Debug("Imported file: " + fileid)
	return ids, 0, nil
}
```

`context` and `govalidator` are already imported in this file.

- [ ] **Step 2: Refactor `/scan/start`'s `importOne` to call `runImport`**

Replace the entire `importOne := func(parsedImport g3lib.ParsedImport) bool { ... }` closure (currently `src/g3api/g3api.go:442-513`) with this much shorter version:

```go
			importOne := func(parsedImport g3lib.ParsedImport) bool {
				_, status, err := runImport(plugins, mdb_client, artifactsRoot, request.ScanID, parsedImport.Tool, parsedImport.Path)
				if err != nil {
					log.Error(err)
					if status == http.StatusBadRequest {
						g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script, " + err.Error())
					} else {
						g3lib.SendApiError(w, http.StatusInternalServerError, "Error while running importer: " + parsedImport.Tool)
					}
					return false
				}
				return true
			}
```

The surrounding `for _, parsedImport := range parsed.Imports { if !importOne(parsedImport) { return } }` loop and everything after it are unchanged.

- [ ] **Step 3: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 4: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 7: `/scan/import` handler

**Files:**
- Modify: `src/g3api/g3api.go` — add another `http.HandleFunc` registration after Task 5's handler.

- [ ] **Step 1: Register the handler**

Insert immediately after the `/scan/data/insert` handler's closing `}))`:

```go
		///////////////////////////////////////////////////////////////////////////////////////////
		// Import an uploaded file into a managed scan. The file must already
		// have been uploaded via /file/upload; the caller supplies its UUID.
		// Reuses the same runImport helper that drives /scan/start's imports.
		http.HandleFunc(apiPath + "/scan/import", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/import")
			var request g3lib.ReqImport
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			ids, status, err := runImport(plugins, mdb_client, artifactsRoot, request.ScanID, request.Tool, request.FileID)
			if err != nil {
				log.Error(err)
				if status == http.StatusBadRequest {
					g3lib.SendApiError(w, http.StatusBadRequest, err.Error())
				} else {
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				}
				return
			}

			g3lib.SendApiResponse(w, ids)
		}))
```

- [ ] **Step 2: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 8: Extend `/scan/data` to honour the optional `taskid`

**Files:**
- Modify: `src/g3api/g3api.go:1186-1211` — the existing `/scan/data` handler.

- [ ] **Step 1: Branch on `request.TaskID`**

The current handler body (after request decode + size check) reads:

```go
			// Get the requested data objects.
			data, err := g3lib.LoadData(mdb_client, request.ScanID, request.DataIDs)
			if err != nil {
				log.Errorf("Error fetching data for scan %s: %s", request.ScanID, err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Could not fetch data objects for scan.")
			} else {
				g3lib.SendApiResponse(w, data)
			}
```

Replace it with:

```go
			// Get the requested data objects. When taskid is set, the call is
			// "fetch the output of one specific task"; otherwise it's by ID
			// list (or all data when the list is empty).
			var data []g3lib.G3Data
			var err error
			if request.TaskID != "" {
				data, err = g3lib.LoadDataByTask(mdb_client, request.ScanID, request.TaskID)
			} else {
				data, err = g3lib.LoadData(mdb_client, request.ScanID, request.DataIDs)
			}
			if err != nil {
				log.Errorf("Error fetching data for scan %s: %s", request.ScanID, err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Could not fetch data objects for scan.")
			} else {
				g3lib.SendApiResponse(w, data)
			}
```

The 100-DataIDs cap (lines 1197-1201) is unchanged — when `taskid` is set, `DataIDs` is typically empty (caller wants everything for that task), so the cap is a non-issue.

- [ ] **Step 2: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 9: Tier-end full build

**Files:** none (verification only)

- [ ] **Step 1: Build every binary**

Run: `make bin` (from `/home/crapula/code/g3`)
Expected: every binary built successfully, exit 0.

- [ ] **Step 2: Hand off to user for commit**

Tier 2 is code-complete. Per project convention, the user reviews and commits the tier as one batch. Report what changed and stop for the tier checkpoint before Tier 3.

## Tier 3 — tool contract surface

**Resolved decisions:** `operations[i].produces` is sourced from `Commands[i].Returns` (per-command, always specific); top-level `Produces` comes from `LLM.Produces`. `g3config` requires no changes — `json.Unmarshal` populates the new `LLM` field automatically and `validate:"omitempty"` makes the field optional. Static review of the unmarshal/marshal flow is sufficient; the user verifies end-to-end pass-through when rebuilding the plugin config.

### Task 1: New types in `src/g3lib/api.go`

**Files:**
- Modify: `src/g3lib/api.go` — add the contract response types and a new empty request type.

- [ ] **Step 1: Add `PluginContractOperation`, `PluginContract`, and `ReqGetEnv`**

Insert this block immediately after the `ReqListPlugins` struct and its `Decode` method (which currently lives around `src/g3lib/api.go:315-321`). Use tab indentation matching the file's style:

```go
type ReqGetEnv struct {
}
func (req *ReqGetEnv) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

// PluginContractOperation describes one command variant a plugin exposes
// (`/scan/task/dispatch` selects a variant by Index).
type PluginContractOperation struct {
	Index       int    `json:"index"`
	Description string `json:"description,omitempty"` // From G3LLMMetadata.Commands[Index].Description, if any.
	Produces    string `json:"produces,omitempty"`    // From G3ToolCommand.Returns (per-command, always specific).
}

// PluginContract is the LLM-facing contract for one plugin. Served by
// /plugin/describe. Excludes Description/URL/Image (those stay on /plugin/list).
type PluginContract struct {
	Name       string                    `json:"name"`
	Summary    string                    `json:"summary,omitempty"`  // From G3LLMMetadata.Summary; falls back to Description["en"].
	Accepts    []string                  `json:"accepts,omitempty"`  // From G3LLMMetadata.Accepts.
	Produces   string                    `json:"produces,omitempty"` // From G3LLMMetadata.Produces (plugin-level).
	Operations []PluginContractOperation `json:"operations,omitempty"`
}
```

- [ ] **Step 2: Build g3lib**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint g3lib**

Run: `cd /home/crapula/code/g3/src/g3lib && golangci-lint run ./...`
Expected: 0 issues.

### Task 2: `/plugin/describe` handler

**Files:**
- Modify: `src/g3api/g3api.go` — add a private helper `buildPluginContract` and register the handler.

- [ ] **Step 1: Add the `buildPluginContract` helper**

A natural location is alongside the other top-level helpers in `src/g3api/g3api.go` (e.g. right after `runImport`, before the next `////////` divider). Insert:

```go
// buildPluginContract assembles the LLM-facing contract for one plugin,
// falling back gracefully when the optional LLM block is absent.
func buildPluginContract(plugin g3lib.G3Plugin) g3lib.PluginContract {
	contract := g3lib.PluginContract{Name: plugin.Name}

	if plugin.LLM != nil && plugin.LLM.Summary != "" {
		contract.Summary = plugin.LLM.Summary
	} else if desc, ok := plugin.Description["en"]; ok {
		contract.Summary = desc
	}

	if plugin.LLM != nil {
		contract.Accepts = plugin.LLM.Accepts
		contract.Produces = plugin.LLM.Produces
	}

	contract.Operations = make([]g3lib.PluginContractOperation, 0, len(plugin.Commands))
	for i, cmd := range plugin.Commands {
		op := g3lib.PluginContractOperation{
			Index:    i,
			Produces: cmd.Returns,
		}
		if plugin.LLM != nil && i < len(plugin.LLM.Commands) {
			op.Description = plugin.LLM.Commands[i].Description
		}
		contract.Operations = append(contract.Operations, op)
	}

	return contract
}
```

- [ ] **Step 2: Register the handler**

Locate the existing `/plugin/list` handler in `src/g3api/g3api.go` (registered with `http.HandleFunc(apiPath + "/plugin/list", …`). It ends with `}))` followed by a blank line and the next handler's `////////` divider.

Insert a blank line and then the following handler immediately AFTER `/plugin/list`'s closing `}))` and BEFORE the next divider:

```go
		///////////////////////////////////////////////////////////////////////////////////////////
		// LLM-facing tool contract: per-plugin Summary/Accepts/Produces/Operations
		// sourced from optional .g3p `llm:` metadata, with graceful fallback when
		// the block is absent. Excludes Description/URL/Image (those stay on
		// /plugin/list for humans and GUIs).
		http.HandleFunc(apiPath + "/plugin/describe", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: plugin/describe")
			var request g3lib.ReqListPlugins
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			pluginNames := make([]string, 0, len(plugins))
			for key := range plugins {
				pluginNames = append(pluginNames, key)
			}
			sort.Strings(pluginNames)

			contracts := make([]g3lib.PluginContract, 0, len(plugins))
			for _, name := range pluginNames {
				contracts = append(contracts, buildPluginContract(plugins[name]))
			}

			g3lib.SendApiResponse(w, contracts)
		}))
```

Tab-indent at the same level as surrounding `http.HandleFunc(...)` blocks.

`sort`, `http`, `g3lib`, `log` are already imported.

Note: we reuse `g3lib.ReqListPlugins` because both endpoints have an empty body and identical decode semantics — no need to duplicate the type.

- [ ] **Step 3: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 4: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 3: `/config/env` handler

**Files:**
- Modify: `src/g3api/g3api.go` — register the handler immediately after `/plugin/describe`.

- [ ] **Step 1: Register the handler**

Insert a blank line and then the following handler IMMEDIATELY after `/plugin/describe`'s closing `}))`:

```go
		///////////////////////////////////////////////////////////////////////////////////////////
		// Read-only deployment-wide capability flags: the subset of environment
		// variables prefixed G3_ENV_*, which g3worker injects into every plugin
		// container. The operator owns the values; this endpoint just surfaces
		// them so consumers can reason about capabilities (e.g. IPv6 support).
		http.HandleFunc(apiPath + "/config/env", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: config/env")
			var request g3lib.ReqGetEnv
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			g3lib.SendApiResponse(w, g3lib.GetSharedEnv())
		}))
```

Tab-indent at the same level as the surrounding handlers.

- [ ] **Step 2: Build g3api**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint g3api**

Run: `cd /home/crapula/code/g3/src/g3api && golangci-lint run ./...`
Expected: 0 issues.

### Task 4: Annotate `nikto.g3p` with an `llm:` block

**Files:**
- Modify: `plugins/attack/nikto/nikto.g3p`

- [ ] **Step 1: Insert the `llm:` block after `image:`**

The current file (read in full earlier) looks like:

```
{
    url: "https://github.com/sullo/nikto",
    description: {
        en: "Nikto is a free software command-line vulnerability scanner that scans webservers for dangerous files/CGIs, outdated server software and other problems.",
    },
    image: "ghcr.io/golismero/nikto",

    commands: [
        …
    ],

    importer: {
        returns: "issue",
    },

    merger: {},
}
```

Insert a blank line and then this `llm:` block immediately after the `image:` line and before the existing blank line preceding `commands:`:

```
    llm: {
        summary: "Web server vulnerability scanner.",
        accepts: ["url"],
        produces: "issue",
        commands: [
            { description: "Scan an HTTP URL." },
            { description: "Scan an HTTPS URL (TLS)." },
        ],
    },
```

Preserve 4-space indentation (matching the rest of this file — note: this is the one place where indentation differs from Go's tabs).

- [ ] **Step 2: Verify the file is syntactically valid JSON5/jsonnet**

No binary execution. Visually confirm:
- All keys are followed by `:`
- Trailing commas are present and consistent with the rest of the file (the existing file uses trailing commas — keep that convention).
- The new block has matching `{` `}` and `[` `]`.

No build/lint commands; this file is consumed at runtime by `g3config`. Build is exercised in Task 7.

### Task 5: Annotate `nmap.g3p` with an `llm:` block

**Files:**
- Modify: `plugins/recon/nmap/nmap.g3p`

- [ ] **Step 1: Insert the `llm:` block after `image:`**

The file has extensive comments. Locate the line:

```
    image: "ghcr.io/golismero/nmap",
```

…and the comment block that follows it before `commands:` (lines beginning with `// Command definitions for this tool.`).

Insert a blank line and then this `llm:` block IMMEDIATELY AFTER the `image:` line and BEFORE the `// Command definitions for this tool.` comment block:

```
    llm: {
        summary: "Network discovery and security auditing scanner.",
        accepts: ["host"],
        produces: "host",
        commands: [
            { description: "Scan an IPv4 host for open services and OS details." },
            { description: "Scan an IPv6 host for open services and OS details (requires G3_ENV_IPV6_SUPPORTED)." },
        ],
    },
```

Preserve 4-space indentation. Do NOT remove or reorder the existing comments — they document the schema for plugin authors.

- [ ] **Step 2: Visually verify JSON5/jsonnet validity**

Same checks as Task 4.

### Task 6: Annotate `hydra.g3p` with an `llm:` block

**Files:**
- Modify: `plugins/attack/hydra/hydra.g3p`

- [ ] **Step 1: Insert the `llm:` block after `description:`**

The current file:

```
{
    url: "https://github.com/vanhauser-thc/thc-hydra",
    description: {
        en: "Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add."
    },

    commands: [
        …
    ],
    …
}
```

Hydra has no `image:` field (it inherits the default from `g3config`). Insert the `llm:` block IMMEDIATELY AFTER the `description: { … },` block (which closes with `},` on its own line) and BEFORE the existing blank line preceding `commands:`:

```
    llm: {
        summary: "Parallelized network login cracker.",
        accepts: ["host"],
        produces: "issue",
        commands: [
            { description: "Brute-force logins on an IPv4 host's discovered services." },
            { description: "Brute-force logins on an IPv6 host's discovered services (requires G3_ENV_IPV6_SUPPORTED)." },
        ],
    },
```

Preserve 4-space indentation and trailing-comma style.

- [ ] **Step 2: Visually verify JSON5/jsonnet validity**

Same checks as Task 4.

### Task 7: Tier-end full build

**Files:** none (verification only)

- [ ] **Step 1: Build every binary**

Run: `make bin` (from `/home/crapula/code/g3`)
Expected: every binary built successfully, exit 0.

- [ ] **Step 2: Hand off to user for commit + config rebuild**

Tier 3 is code-complete. Per project convention, the **user** reviews and commits the tier as one batch. Report what changed and stop for the tier checkpoint before Tier 4.

When the user next runs `g3config` (or `make all`) to regenerate `config/g3plugins.json`, the new `llm:` blocks will flow through automatically — `g3config` uses `json.Unmarshal` into the `G3Plugin` struct (which now carries the `LLM` field from Tier 1), and the field is round-tripped via `json.Marshal` thanks to the `json:"llm,omitempty"` tag. No g3config code change is required.

## Tier 4 — Python client library (outline only)

To be detailed after the Tier 3 checkpoint. Anticipated work:

- **`clients/python/`** package (final name/layout decided at detail time), independent of `misc/requirements.txt`, own `pyproject.toml`.
- **Transport:** base URL + bearer token, JSON error mapping, multipart `/file/upload`, streaming `/scan/task/artifacts` download → write into `<dest_dir>/<task_id>/`, transparent zip/tar.gz extraction (single raw file passes through), return the directory path.
- **Scan-scoped API:** `create_managed_scan`, `delete_scan`, `add_targets`, `insert_data`, `import_file` (upload+import in one call), `run_tool`, `task_status`, `wait_for_task`, `task_results`, `task_artifacts`, `list_tools`, `describe_tool`, `get_env`.
- **`G3DATA_PRIMER`** module-level string constant describing the G3Data envelope + common `_type`s.
- Verification: `ruff check` + an import smoke (`python -c "import g3client"`); no pytest (tests are user-owned). User commits at tier end.

---

## Self-review notes

- **Spec coverage:** every spec §5 item maps to a tier — `MANAGED` status / data-by-task / `llm` struct / shared-env → Tier 1; `/scan/create`,`/scan/target/add`,`/scan/data/insert`,`/scan/import`,`/scan/data` filter → Tier 2; `/plugin/describe`,`/config/env`, `.g3p` annotations → Tier 3; §6 Python library → Tier 4.
- **Referenced symbols verified present:** `GetScanStatus` (sql.go:389), `InsertScanProgress` (sql.go:278), `UpdateScanProgress` (sql.go:289), `BuildTargets` (used at g3api.go:425), `SaveData` returns `[]string` (datastore.go:256), `IsValidData` (common.go:223), `LoadDataWithCallback` (datastore.go:210), `GetEnvironmentMap` (common.go:88), `importOne` (g3api.go:442), jsonnet unmarshal+validate (g3config.go:260-267).
- **No test/commit steps** by design (user-owned). **Tier 1 fully detailed; Tiers 2-4 intentionally outlined** per the tiered-plan convention.
```