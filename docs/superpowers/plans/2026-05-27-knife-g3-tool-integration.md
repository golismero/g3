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

## Tier 2 — g3api managed-scan endpoints (outline only)

To be detailed after the Tier 1 checkpoint. Anticipated work:

- **`src/g3lib/api.go`:** new request structs + `Decode` methods — `ReqCreateScan{}`, `ReqAddTargets{ScanID, Targets}`, `ReqInsertData{ScanID, Data}`, `ReqImport{ScanID, Tool, FileID}`; extend `ReqLoadData` with an optional `TaskID` (when set, route to `LoadDataByTask`).
- **`src/g3api/g3api.go`:** new handlers behind `requireToken`:
  - `/scan/create` — `uuid.NewString()`, `InsertScanProgress` + `UpdateScanProgress(..., STATUS_MANAGED, ...)`, `MkdirAll(<artifactsRoot>/<scanid>)`, **no** `SendNewScan`; return scan id.
  - `/scan/target/add` — managed-only gate → `BuildTargets` → `SaveData(NIL_TASKID)` → return the IDs `SaveData` already yields.
  - `/scan/data/insert` — managed-only gate → `IsValidData` per object (400 on failure) → `SaveData` → return IDs.
  - `/scan/import` — managed-only gate → reuse the existing `importOne` logic (extract it into a reusable helper) → return IDs.
  - `/scan/data` — when `TaskID` is set, call `LoadDataByTask`.
- **Shared managed-only gate:** a small helper that loads `GetScanStatus(scanid)` and rejects non-`MANAGED` scans (409 vs 400 — decide at detail time).
- Verification per task: build the g3api module (`cd src/g3api && go build ./...`) + lint; tier-end `cd src && make bin`. User commits at tier end.

## Tier 3 — tool contract surface (outline only)

To be detailed after the Tier 2 checkpoint. Anticipated work:

- **`/plugin/describe` handler** (`src/g3api/g3api.go`): build the per-plugin response `{name, summary, accepts, produces, operations[]}` from `plugin.LLM`, with fallback (`summary` ← `Description["en"]`; `operations[i].produces` ← `Commands[i].Returns`) when `LLM` is absent. Exclude `description`/`url`/`image`.
- **`/config/env` handler** (`src/g3api/g3api.go`): return `g3lib.GetSharedEnv()`.
- **Example `.g3p` annotations:** add `llm:` blocks to a few representative plugins (nikto, nmap, hydra) under `plugins/`.
- **Confirm `g3config` passthrough:** the jsonnet→JSON→`json.Unmarshal` path (`src/g3config/g3config.go:260-267`) ignores unknown fields and the new `validate:"omitempty"` field passes `validate.Struct`, so no g3config change is expected; rebuild the plugin registry to confirm `llm` survives into `config/g3plugins.json`.
- Verification: build + lint; rebuild plugin config; user commits at tier end.

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