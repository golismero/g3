# Reporter Plugins — Tier 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three g3api endpoints completing the "reporter tasks as first-class tasks" story: a generic disk-first task-artifacts download, an async opt-in for `/scan/reporter`, and a batch task-cancel endpoint.

**Architecture:** Purely additive g3api-side changes. No new MQTT messages, no new SQL/Redis schema, no new helpers in g3lib (every dependency was shipped in Tier 1 or earlier). One request struct gets a new optional bool field; two new request structs are added. Two new POST endpoints are added; one existing endpoint gets an early-return branch.

**Tech Stack:** Go 1.25, net/http, the existing g3lib request/response helpers, `bytes.Buffer` for the bundle response (Tier 1 compromise; streaming refactor is future work).

**Spec:** [docs/superpowers/specs/2026-05-18-reporter-tier2-design.md](../specs/2026-05-18-reporter-tier2-design.md)

**Tier scope:** Tier 2 only — three endpoints. Tier 1's sync `/scan/reporter` behavior stays unchanged unless `async: true` is explicitly set in the body.

---

## Notes for executors

Same project-level overrides as the Tier 1 plan:

- **Tests are user-owned.** Do not write tests, do not run tests, do not use the test-driven-development skill.
- **Git is user-owned.** Do not run mutating git commands (`add`, `commit`, `mv`, `rm`, `push`). Read-only inspection (`git status`, `git diff`) is fine. The user commits at the end of the tier in one batch.
- **No per-task STOP.** Run through end-to-end without checkpoint pauses.
- **Verification per task = `go build ./...`** in the affected module (`src/g3lib` and/or `src/g3api`). After all changes are in, the final task does a cross-binary build sweep.

---

## File structure

| File | Responsibility | Modified |
| --- | --- | --- |
| `src/g3lib/api.go` | Add `ReqTaskArtifacts` and `ReqTaskCancel` request structs with `Decode` methods. Add an `Async bool` field to the existing `ReqReporter` struct. | Modify |
| `src/g3api/g3api.go` | Add `POST /scan/task/artifacts` handler. Add `POST /scan/task/cancel` handler. Modify the existing `POST /scan/reporter` handler to branch on `request.Async` before entering the synchronous polling loop. | Modify |

No new helpers in g3lib are required — every dependency (`BundleTaskSlot`, `GetTaskState`, `ManifestFilename`, `SetTaskDispatched`, `SetTaskTerminal`, `SendReportTask`, `SendTaskCancel`, `G3_ARTIFACTS_ROOT`/`G3_ARTIFACTS_ROOT_DEFAULT`) was shipped in Tier 1 or earlier.

---

## Task 1: Request structs in `g3lib/api.go`

**Files:**
- Modify: `src/g3lib/api.go`

- [ ] **Step 1: Read the existing request struct patterns**

Open `src/g3lib/api.go` and read the `ReqReporter` struct + Decode method around lines 250-260 (added in Tier 1). The new structs follow the exact same pattern: a struct with `json` and `validate` tags, plus a `Decode(r *http.Request) error` method that calls `ValidateHttpRequest`, then `json.NewDecoder(r.Body).Decode(req)`, then `validator.New().Struct(req)`.

- [ ] **Step 2: Add the `Async` field to `ReqReporter`**

Locate the existing `ReqReporter` struct (around line 250). Add a new field at the end:

```go
type ReqReporter struct {
	ScanID string `json:"scanid" validate:"required,uuid"`
	Tool   string `json:"tool"   validate:"required"`
	Preset string `json:"preset"`
	Async  bool   `json:"async,omitempty"`
}
```

The `omitempty` tag means Tier 1 clients that don't send the field continue to get sync behavior (Go zero value for bool is `false`). No `Decode` change needed — the existing `Decode` method picks up the new field automatically.

- [ ] **Step 3: Add `ReqTaskArtifacts` struct + Decode method**

Insert immediately after `ReqReporter.Decode` ends (and after any sibling response types in the same block). Follow the exact `Decode` pattern used by other request types in the file:

```go
type ReqTaskArtifacts struct {
	ScanID string `json:"scanid" validate:"required,uuid"`
	TaskID string `json:"taskid" validate:"required,uuid"`
}

func (req *ReqTaskArtifacts) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}
```

- [ ] **Step 4: Add `ReqTaskCancel` struct + Decode method**

Insert immediately after `ReqTaskArtifacts.Decode`:

```go
type ReqTaskCancel struct {
	ScanID  string   `json:"scanid"  validate:"required,uuid"`
	TaskIDs []string `json:"taskids" validate:"required,min=1,dive,uuid"`
}

func (req *ReqTaskCancel) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}
```

`min=1,dive,uuid` enforces non-empty list + each entry is a uuid.

- [ ] **Step 5: Verify the module still builds**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`
Expected: no output, exit 0.

---

## Task 2: `POST /scan/task/artifacts` handler

**Files:**
- Modify: `src/g3api/g3api.go`

- [ ] **Step 1: Locate the insertion point**

Open `src/g3api/g3api.go`. The Tier 1 `/scan/reporter` handler is around line 917+. Insert the new `/scan/task/artifacts` handler block immediately after the `/scan/reporter` handler's closing `}))`, before the next handler in the file.

- [ ] **Step 2: Verify required imports are present**

The new handler uses: `bytes`, `encoding/json`, `errors`, `net/http`, `os`, `path/filepath`. All should already be imported by g3api.go from Tier 1's work. If any is missing, add it to the import block.

- [ ] **Step 3: Add the `/scan/task/artifacts` handler**

The handler implements the disk-first behavior from the spec: slot dir absent → 404; `manifest.json` present → 200 + bundle; `manifest.json` absent → 425 with the body shaped by Redis state.

```go
///////////////////////////////////////////////////////////////////////////////////////////
// Generic task-artifacts download. Disk-first: manifest.json presence in the slot is
// the authoritative durable terminal-state marker. Redis is consulted only to shape
// the 425 body message when the manifest is absent — Redis absence is NEVER a
// failure signal (Redis is transient by design; terminated scans have no entries).
//
// See docs/superpowers/specs/2026-05-18-reporter-tier2-design.md (Component 1).
//
http.HandleFunc(apiPath + "/scan/task/artifacts", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
	log.Debug("Handling: scan/task/artifacts")
	var request g3lib.ReqTaskArtifacts
	err := request.Decode(r)
	if err != nil {
		log.Error("Error decoding payload: " + err.Error())
		g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
		return
	}

	// Compute the slot path.
	artifactsRoot := os.Getenv(g3lib.G3_ARTIFACTS_ROOT)
	if artifactsRoot == "" {
		artifactsRoot = g3lib.G3_ARTIFACTS_ROOT_DEFAULT
	}
	slotDir := filepath.Join(artifactsRoot, request.ScanID, request.TaskID)

	// Step 1: slot dir absent → 404.
	if _, err := os.Stat(slotDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			g3lib.SendApiError(w, http.StatusNotFound, "task not found")
			return
		}
		log.Error("stat slot dir failed: " + err.Error())
		g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
		return
	}

	// Step 2: manifest.json present → terminal, serve bundle.
	manifestPath := filepath.Join(slotDir, g3lib.ManifestFilename)
	manifestBytes, err := os.ReadFile(manifestPath)
	if err == nil {
		// Decode the manifest to recover the tool name. BundleTaskSlot uses
		// `tool` to construct the multi-file zip filename (`<tool>-<taskid>.zip`);
		// reading from the manifest avoids the generic endpoint having to know
		// the tool out-of-band. Fall back to the task ID if the manifest field
		// is unexpectedly empty (shouldn't happen but defended against).
		var manifest g3lib.G3Manifest
		toolName := request.TaskID
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
			log.Error("parse manifest failed: " + err.Error())
			// Continue with the fallback; a malformed manifest shouldn't block
			// the download — better to ship the bundle with a less-descriptive
			// filename than to fail.
		} else if manifest.Tool != "" {
			toolName = manifest.Tool
		}

		var buf bytes.Buffer
		filename, contentType, bundleErr := g3lib.BundleTaskSlot(slotDir, toolName, request.TaskID, &buf)
		if bundleErr != nil {
			if errors.Is(bundleErr, os.ErrNotExist) {
				// Unreachable in practice (manifest counts as a file) but
				// defended against for safety.
				g3lib.SendApiError(w, http.StatusNotFound, "task produced no output")
				return
			}
			log.Error("BundleTaskSlot failed: " + bundleErr.Error())
			g3lib.SendApiError(w, http.StatusInternalServerError, "failed to bundle task artifacts")
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(buf.Bytes()); err != nil {
			log.Error("response write failed: " + err.Error())
		}
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Error("read manifest failed: " + err.Error())
		g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
		return
	}

	// Step 3: manifest absent — consult Redis only to shape the body.
	// Redis presence is a positive "still running" signal; Redis absence
	// is NOT a failure signal. Either way we return 425.
	state, _ := g3lib.GetTaskState(rdb_client, request.ScanID, request.TaskID)
	var msg string
	if state == "DISPATCHED" || state == "RUNNING" {
		msg = "task is still " + state
	} else {
		msg = "task is not yet complete"
	}
	w.Header().Set("Retry-After", "2")
	g3lib.SendApiError(w, http.StatusTooEarly, msg)
}))
```

- [ ] **Step 4: Verify the module still builds**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

---

## Task 3: Async branch in `POST /scan/reporter`

**Files:**
- Modify: `src/g3api/g3api.go`

- [ ] **Step 1: Locate the existing `/scan/reporter` handler**

Open `src/g3api/g3api.go`. The Tier 1 `/scan/reporter` handler begins around line 917. Find the spot where validation completes and the handler is about to call `g3lib.SetTaskDispatched` (after the preset-validation block). The async branch goes immediately after `SetTaskDispatched` succeeds and the `X-G3-Task-ID` header is set; if `request.Async` is true, the handler dispatches the task and returns 202 instead of entering the synchronous polling loop.

- [ ] **Step 2: Insert the async branch**

Find this existing block in the handler (the part right after `SetTaskDispatched` and setting the `X-G3-Task-ID` header, but before the `SendReportTask` call):

```go
	w.Header().Set("X-G3-Task-ID", reporterTaskID)

	if err := g3lib.SendReportTask(mq_client, request.ScanID, reporterTaskID, request.Tool, request.Preset); err != nil {
		log.Critical("SendReportTask failed: " + err.Error())
		// Best-effort: mark the task as ERROR so consumers see a terminal state.
		_ = g3lib.SetTaskTerminal(rdb_client, request.ScanID, reporterTaskID, "ERROR", time.Now().Unix(), "MQTT publish failed: "+err.Error())
		g3lib.SendApiError(w, http.StatusInternalServerError, "Failed to dispatch reporter task.")
		return
	}

	// Poll Redis for terminal state. The HTTP request context cancels on
	// client disconnect, which exits the loop cleanly.
```

Immediately after the `SendReportTask` block (after its closing brace, before the polling-loop comment), insert the async early-return:

```go
	// Async opt-in (Tier 2). Skip the synchronous polling/bundling loop;
	// return 202 + { task_id } immediately. The client polls
	// /scan/tasks/status and then GETs /scan/task/artifacts when ready.
	if request.Async {
		w.WriteHeader(http.StatusAccepted)
		response := g3lib.APIResponse{
			Status: "success",
			Data:   map[string]string{"task_id": reporterTaskID},
		}
		response.Write(w)
		return
	}

	// Poll Redis for terminal state. The HTTP request context cancels on
	// client disconnect, which exits the loop cleanly.
```

The `g3lib.APIResponse{...}` plus `.Write(w)` mirrors the inline pattern in `SendApiResponse` exactly — we open-code it here because `SendApiResponse` always emits 200, and async wants 202 Accepted.

- [ ] **Step 3: Verify the module still builds**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

---

## Task 4: `POST /scan/task/cancel` handler

**Files:**
- Modify: `src/g3api/g3api.go`

- [ ] **Step 1: Locate the insertion point**

Insert the new `/scan/task/cancel` handler immediately after the `/scan/task/artifacts` handler from Task 2 (keeping the `/scan/task/*` family together).

- [ ] **Step 2: Add the cancel handler**

```go
///////////////////////////////////////////////////////////////////////////////////////////
// Batch task cancellation. Publishes a single G3CancelTask MQTT message covering
// all task IDs in one publish. Fire-and-forget: the API doesn't wait for workers
// to acknowledge — task state transitions to CANCELED flow through the existing
// SetTaskTerminal / /scan/tasks/status / WebSocket task channel pipeline.
//
// See docs/superpowers/specs/2026-05-18-reporter-tier2-design.md (Component 3).
//
http.HandleFunc(apiPath + "/scan/task/cancel", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
	log.Debug("Handling: scan/task/cancel")
	var request g3lib.ReqTaskCancel
	err := request.Decode(r)
	if err != nil {
		log.Error("Error decoding payload: " + err.Error())
		g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
		return
	}

	if err := g3lib.SendTaskCancel(mq_client, request.ScanID, request.TaskIDs); err != nil {
		log.Error("SendTaskCancel failed: " + err.Error())
		g3lib.SendApiError(w, http.StatusInternalServerError, "failed to publish cancel")
		return
	}

	g3lib.SendApiResponse(w, nil)
}))
```

That's the entire handler. The validation work (min=1 list, uuid format) is done by the `Decode` method's validator tags — no inline checks needed.

- [ ] **Step 3: Verify the module still builds**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

---

## Task 5: Cross-binary build sweep

**Files:**
- No edits. Build verification only.

- [ ] **Step 1: Build every Go binary**

Run from the repo root:

```
make bin
```

Expected: every binary in `src/` builds successfully, producing artifacts in `bin/`. No errors, no warnings about unused imports or undefined identifiers.

If `make bin` is unavailable in the executor's environment, run each binary's build directly:

```
cd src/g3       && go build ./... && cd -
cd src/g3api    && go build ./... && cd -
cd src/g3cli    && go build ./... && cd -
cd src/g3config && go build ./... && cd -
cd src/g3scanner && go build ./... && cd -
cd src/g3worker && go build ./... && cd -
```

Expected: all builds succeed.

- [ ] **Step 2: Report completion**

The plan is complete when all builds in Step 1 succeed. The user will commit the result; do not run any git commands.

Summary of what now ships:

- `POST /scan/task/artifacts` — disk-first generic artifacts download for any task with a manifest, works on terminated scans, returns 425 + Retry-After for in-flight tasks.
- `POST /scan/reporter` with `async: true` body field — returns 202 + `{ task_id }` immediately and skips the synchronous polling loop. The sync default path is unchanged.
- `POST /scan/task/cancel` — batch cancel by `(scan_id, task_ids)`, single MQTT publish, fire-and-forget.

No new MQTT messages, no SQL/Redis schema changes, no new g3lib helpers. The Tier 2 surface is purely g3api-side.
