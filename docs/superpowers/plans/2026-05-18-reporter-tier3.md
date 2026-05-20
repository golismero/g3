# Reporter Plugins — Tier 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add scripted reporter dispatch to scan scripts (server-side); drop the now-pointless manifest write for reporter tasks; switch the artifacts endpoint from disk-first manifest check to Redis → SQL log fallback.

**Architecture:** Three independent components ship together. Scripted dispatch reuses the existing `dispatchTask` helper from the dispatcher refactor (no new MQTT topics, no new message types). Manifest drop is pure subtraction in the worker. Artifacts endpoint rework consults the same lifecycle source `/scan/tasks/status` already trusts (`GetTaskStates` + new single-task SQL helper).

**Tech Stack:** Go 1.25, existing g3lib helpers (`dispatchTask`, `ReconstructTaskStatesFromLogs`, `SetTaskDispatched`, `BundleTaskSlot`, `GetTaskState`), no new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-18-reporter-tier3-design.md](../specs/2026-05-18-reporter-tier3-design.md)

---

## Notes for executors

Same project-level overrides as prior tiers:

- **Tests are user-owned.** Do not write tests, do not run tests, do not use the test-driven-development skill.
- **Git is user-owned.** Do not run mutating git commands. Read-only inspection is fine. The user commits at the end of the tier in one batch.
- **No per-task STOP.** Run through end-to-end without checkpoint pauses.
- **Verification per task = `go build ./...`** in the affected module. The final task does a cross-binary build sweep.

---

## File structure

| File | Responsibility | Modified |
| --- | --- | --- |
| `src/g3lib/script.go` | Parser: add `ParsedReport` type, `Report` field on `ParsedScript`, `report` directive handling with last-line + uniqueness + plugin validation | Modify |
| `src/g3lib/task.go` | Wire: add `ReportTool` + `ReportPreset` fields to `G3Scan`; update `SendNewScan` signature | Modify |
| `src/g3api/g3api.go` | Forward parsed report into `SendNewScan` from `/scan/start`; rework `/scan/task/artifacts` to use Redis → SQL fallback | Modify |
| `src/g3scanner/g3scanner.go` | ScanRunner: after merger + `SaveReportInfo` succeed, dispatch script-declared reporter via `dispatchTask` | Modify |
| `src/g3worker/g3worker.go` | Drop `WriteManifest` (and surrounding `manifestWriteErr` plumbing) for reporter tasks | Modify |
| `src/g3lib/sql.go` | Add `ReconstructTaskStateFromLogs(db, scanID, taskID) (state, tool string, err error)` — single-task variant of the existing plural helper | Modify |
| `docs/superpowers/specs/2026-05-16-reporter-plugins-design.md` | Amend Component 3 to note reporter tasks don't write manifests | Modify |
| `docs/superpowers/specs/2026-05-18-reporter-tier2-design.md` | Amend Component 1 to reflect the Redis → SQL fallback (replaces disk-first manifest check) | Modify |

---

## Task 1: `ParsedReport` type + `Report` field on `ParsedScript`

**Files:**
- Modify: `src/g3lib/script.go`

- [ ] **Step 1: Read existing types and parser layout**

Open `src/g3lib/script.go` and read lines 18-58 (the `ParsedImport`, `ParsedScript` struct + `String()` method). New types and fields follow the same idiom.

- [ ] **Step 2: Add `ParsedReport` struct + `Report` field on `ParsedScript`**

Insert the `ParsedReport` struct definition immediately after `ParsedImport` (around line 21, before `ParsedScript`):

```go
type ParsedReport struct {
	Tool   string             `json:"tool"                validate:"required"`
	Preset string             `json:"preset,omitempty"`
}
```

Then add a `Report` field as the last entry of `ParsedScript`:

```go
type ParsedScript struct {
	Targets []string        `json:"targets,omitempty"   validate:"omitempty"`
	Imports []ParsedImport  `json:"imports,omitempty"   validate:"omitempty,dive"`
	Mode string             `json:"mode,omitempty"      validate:"omitempty"`
	Pipelines [][]string    `json:"pipelines,omitempty" validate:"omitempty"`
	Report *ParsedReport    `json:"report,omitempty"    validate:"omitempty"`
}
```

- [ ] **Step 3: Update `String()` method to emit the directive**

Find the `String()` method (around line 28). After the existing `Pipelines` clause and before `return text`, append:

```go
	if parsed.Report != nil {
		if text != "" {
			text = text + "\n"
		}
		if parsed.Report.Preset != "" {
			text = text + "report " + parsed.Report.Tool + ":" + parsed.Report.Preset + "\n"
		} else {
			text = text + "report " + parsed.Report.Tool + "\n"
		}
	}
```

- [ ] **Step 4: Verify build**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`
Expected: no output, exit 0.

---

## Task 2: Parse `report` directive in scan script

**Files:**
- Modify: `src/g3lib/script.go`

- [ ] **Step 1: Locate the directive-handling block**

The script parser has per-directive blocks (`target`, `import`, `mode`) starting around line 90+, followed by a fall-through that interprets remaining lines as pipelines. The new `report` directive handler goes before the fall-through, after the existing `mode` block.

- [ ] **Step 2: Add the `report` directive handler**

Find the `mode` directive block (around line 162-189, ending with `continue`). Immediately after its closing brace, insert:

```go
		// The "report" command declares a reporter plugin to invoke after the pipeline finishes.
		// Must be the LAST directive in the script. At most one per script.
		// Syntax: report <tool>[:<preset>]
		if commands[0] == "report" {
			if parsed.Report != nil {
				err = fmt.Errorf("syntax error on line %d: only one report directive per script is allowed", lineno+1)
				return ParsedScript{}, err
			}
			if len(commands) != 2 {
				err = fmt.Errorf("syntax error on line %d: report directive takes exactly one argument: <tool>[:<preset>]", lineno+1)
				return ParsedScript{}, err
			}
			// Split <tool>:<preset>
			toolArg := commands[1]
			tool := toolArg
			preset := ""
			if i := strings.Index(toolArg, ":"); i >= 0 {
				tool = toolArg[:i]
				preset = toolArg[i+1:]
				if tool == "" {
					err = fmt.Errorf("syntax error on line %d: missing tool name in report directive", lineno+1)
					return ParsedScript{}, err
				}
			}
			// Plugin validation (mirrors /scan/task/dispatch validation in g3api).
			if plugins != nil {
				plugin, ok := plugins[tool]
				if !ok {
					err = fmt.Errorf("runtime error on line %d: tool not found: %s", lineno+1, tool)
					return ParsedScript{}, err
				}
				if plugin.Reporter == nil {
					err = fmt.Errorf("runtime error on line %d: tool %s does not implement a reporter", lineno+1, tool)
					return ParsedScript{}, err
				}
				if preset != "" {
					if len(plugin.Reporter.Commands) == 0 {
						err = fmt.Errorf("runtime error on line %d: tool %s declares no reporter presets", lineno+1, tool)
						return ParsedScript{}, err
					}
					found := false
					for _, c := range plugin.Reporter.Commands {
						if c.Name == preset {
							found = true
							break
						}
					}
					if !found {
						err = fmt.Errorf("runtime error on line %d: unknown preset for tool %s: %s", lineno+1, tool, preset)
						return ParsedScript{}, err
					}
				}
			}
			parsed.Report = &ParsedReport{Tool: tool, Preset: preset}
			continue
		}
```

- [ ] **Step 3: Enforce "report must be the last directive"**

After the for-loop over script lines ends (just before the existing "If no `mode` command was used, set it to the default" block around line 222), the directive parsing is finished. To enforce last-line: this is already implicit if `report` always uses `continue` and any *later* line would itself fall through to a directive handler — but a later `target` / `import` / pipeline line wouldn't notice the existing `Report` field.

Add a guard at the TOP of every other directive handler (target, import, mode) — actually a cleaner approach: add a single guard at the start of each loop iteration that rejects any directive when `parsed.Report != nil`. Insert right after `if len(commands) == 0 { continue }` (around line 93):

```go
		// Once a report directive has been parsed, no further directives are allowed
		// — report must be the LAST line of the script.
		if parsed.Report != nil {
			err = fmt.Errorf("syntax error on line %d: report directive must be the last line of the script", lineno+1)
			return ParsedScript{}, err
		}
```

- [ ] **Step 4: Verify build**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`
Expected: no output, exit 0.

---

## Task 3: Wire `Report` through `G3Scan` MQTT message

**Files:**
- Modify: `src/g3lib/task.go`

- [ ] **Step 1: Add `ReportTool` and `ReportPreset` fields to `G3Scan`**

Find `type G3Scan struct` (around line 119). Add two fields after `Pipelines`:

```go
type G3Scan struct {            // MessageType: MSG_SCAN
	G3Message
	Mode string                 `json:"mode"        validate:"required"`
	Pipelines [][]string        `json:"pipelines"`  // can be empty
	ReportTool string           `json:"reporttool,omitempty"`
	ReportPreset string         `json:"reportpreset,omitempty"`
}
```

Flat fields rather than a nested `*ParsedReport`. Reasons: matches the existing `Mode` / `Pipelines` flattening convention, keeps the wire shape consistent with the dispatcher refactor's `G3Dispatch` (which is also flat).

- [ ] **Step 2: Update `SendNewScan` signature**

Find `SendNewScan` (around line 233). Add two parameters and forward them to the message:

```go
// Send a new scan message to the broker.
func SendNewScan(client MessageQueueClient, scanid, mode string, pipelines [][]string, reportTool, reportPreset string) error {
	msg := G3Scan{}
	msg.MessageType = MSG_SCAN
	msg.SenderID = GetClientID(client)
	msg.ScanID = scanid
	msg.Mode = mode
	msg.Pipelines = pipelines
	msg.ReportTool = reportTool
	msg.ReportPreset = reportPreset
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	return SendMQPayload(client, G3SCANNERPUBTOPIC, msg)
}
```

- [ ] **Step 3: Verify build**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`
Expected: no output, exit 0. (Other modules will fail until Task 4 updates their callers; that's fine — g3lib builds standalone.)

---

## Task 4: Forward parsed report from g3api `/scan/start`

**Files:**
- Modify: `src/g3api/g3api.go`

- [ ] **Step 1: Locate the `SendNewScan` call site**

Find the call to `g3lib.SendNewScan` in `/scan/start` (around line 522):

```go
err = g3lib.SendNewScan(mq_client, request.ScanID, parsed.Mode, parsed.Pipelines)
```

- [ ] **Step 2: Pass the report fields**

Replace the call with:

```go
reportTool := ""
reportPreset := ""
if parsed.Report != nil {
	reportTool = parsed.Report.Tool
	reportPreset = parsed.Report.Preset
}
err = g3lib.SendNewScan(mq_client, request.ScanID, parsed.Mode, parsed.Pipelines, reportTool, reportPreset)
```

Empty strings when the script doesn't declare a reporter — `SendNewScan` already JSON-encodes with `omitempty`, so old scanners would see no extra fields (relevant only for staged rollouts; for our case the scanner update lands in the same ship).

- [ ] **Step 3: Verify build**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

---

## Task 5: Dispatch script-declared reporter in ScanRunner

**Files:**
- Modify: `src/g3scanner/g3scanner.go`

- [ ] **Step 1: Locate the post-merger / pre-completion site**

Find the block in `ScanRunner` that runs after the merger phase and saves report info to Redis — around line 1142-1158. Look for:

```go
	// Save the report in the database.
	var info g3lib.G3Report
	info.ScanID = msg.ScanID
	info.Issues = reportIssues.ToArray()
	sort.Strings(info.Issues)
	err = g3lib.SaveReportInfo(rdb_client, info)
	if err != nil {
		log.Error("Error saving report info: " + err.Error())
		if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "Error saving report info: " + err.Error()); err != nil {
			log.Error(err.Error())
		}
		return
	}

	// Send a message to indicate the scan has finished.
	if err := g3lib.SendScanCompleted(mq_client, msg.ScanID); err != nil {
		log.Error(err.Error())
	}
}
```

The reporter dispatch goes between `SaveReportInfo` succeeding and the `SendScanCompleted` call.

- [ ] **Step 2: Insert the reporter dispatch block**

Immediately after the `SaveReportInfo` error-handling block ends (just before the `// Send a message to indicate the scan has finished.` comment), insert:

```go
	// If the scan script declared a reporter, dispatch it now via the
	// canonical helper. The reporter task runs independently of the scan
	// completion — the scan transitions to FINISHED regardless of reporter
	// state. Clients observe the reporter task in /scan/tasks/status with
	// its own DISPATCHED → RUNNING → DONE lifecycle.
	if msg.ReportTool != "" {
		reporterTaskID := uuid.NewString()
		if err := dispatchTask(
			mq_client, rdb_client, scan_sql_db,
			msg.ScanID, reporterTaskID, "report", msg.ReportTool,
			"", 0, msg.ReportPreset,
		); err != nil {
			// Non-fatal: scan still completes. Reporter dispatch failure
			// is logged but does not flip the scan to ERROR — pipeline
			// work succeeded; the reporter is a downstream artifact that
			// can be re-requested via /scan/task/dispatch.
			log.Error("Failed to dispatch script-declared reporter: " + err.Error())
		}
	}
```

- [ ] **Step 3: Verify imports**

The new code uses `uuid.NewString()`. Check the import block at the top of g3scanner.go — `github.com/google/uuid` should already be imported (the dispatch refactor added it for the dispatchHandler). If absent, add it.

`scan_sql_db` is the SQL connection in scope at this point in `ScanRunner` — confirm by reading the surrounding code; if it's named differently (e.g. `sql_db` per-scan, or shared at process level), use the actual identifier.

- [ ] **Step 4: Verify build**

Run: `cd /home/crapula/code/g3/src/g3scanner && go build ./...`
Expected: no output, exit 0.

---

## Task 6: Drop `WriteManifest` for reporter tasks in g3worker

**Files:**
- Modify: `src/g3worker/g3worker.go`

- [ ] **Step 1: Locate the reporter handler's manifest-write block**

Find the reporter callback in `g3worker.go` (around lines 944-1010). It contains a block that calls `g3lib.WriteManifest` and tracks the error in `manifestWriteErr`, then uses that error in the terminal-state decision. The block looks like:

```go
	files, enumErr := g3lib.EnumerateSlot(outSlot)
	if enumErr != nil {
		log.Error("Cannot enumerate reporter slot " + outSlot + ": " + enumErr.Error())
		files = []g3lib.G3ManifestFile{}
	}
	exitStatus := "success"
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) {
			exitStatus = "canceled"
		} else {
			exitStatus = runErr.Error()
		}
	}
	endTS := time.Now().Unix()
	manifestWriteErr := g3lib.WriteManifest(outSlot, g3lib.G3Manifest{
		ScanID:     task.ScanID,
		TaskID:     task.TaskID,
		Plugin:     plugin.Name,
		Tool:       plugin.Name,
		ExitStatus: exitStatus,
		StartedAt:  startTS,
		EndedAt:    endTS,
		Files:      files,
		Work: []g3lib.G3ManifestWork{{
			Cmd:       shellquote.Join(parsed.Command...),
			Artifacts: nil,
		}},
	})
	if manifestWriteErr != nil {
		log.Error("Cannot write reporter manifest for " + task.TaskID + ": " + manifestWriteErr.Error())
	}
```

Plus, further down in the terminal-state decision:

```go
	} else if manifestWriteErr != nil {
		terminal = "ERROR"
		terminalMsg = "manifest write failed: " + manifestWriteErr.Error()
	}
```

- [ ] **Step 2: Delete the manifest write + enumeration block**

Replace the entire block from `files, enumErr := g3lib.EnumerateSlot(outSlot)` through the `if manifestWriteErr != nil { log.Error(...) }` line with nothing. The reporter slot's contents speak for themselves; the worker writes no metadata about them.

- [ ] **Step 3: Remove the `manifestWriteErr` branch from terminal-state decision**

In the terminal-state decision block, remove the `else if manifestWriteErr != nil` branch. The terminal decision becomes:

```go
	terminal := "DONE"
	terminalMsg := ""
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) {
			terminal = "CANCELED"
		} else {
			terminal = "ERROR"
			terminalMsg = runErr.Error()
		}
	}
```

- [ ] **Step 4: Remove now-unused `shellquote` import (if applicable)**

The deleted block used `shellquote.Join(parsed.Command...)`. If `shellquote` is no longer referenced anywhere in `g3worker.go` after the deletion, remove it from the import block. Quick check: `grep -n "shellquote" /home/crapula/code/g3/src/g3worker/g3worker.go` — if the only matches are the import line and the deleted block, drop the import.

The tool-task handler (around line 738) still calls `WriteManifest` and may also use `shellquote` — confirm with grep before removing.

- [ ] **Step 5: Verify build**

Run: `cd /home/crapula/code/g3/src/g3worker && go build ./...`
Expected: no output, exit 0. The tool-task handler is untouched.

---

## Task 7: Add `ReconstructTaskStateFromLogs` single-task helper

**Files:**
- Modify: `src/g3lib/sql.go`

- [ ] **Step 1: Locate the plural function**

Find `ReconstructTaskStatesFromLogs` at around line 418 in `src/g3lib/sql.go`. The new single-task variant mirrors its parsing logic but with a narrower SQL query and returns a single result.

- [ ] **Step 2: Add the helper immediately after the plural function**

Append after the closing brace of `ReconstructTaskStatesFromLogs`:

```go
// ReconstructTaskStateFromLogs returns the lifecycle state and tool name
// for a single task, reconstructed from SQL log markers. Returns
// ("", "", nil) if no markers for this task exist (the task either was
// never dispatched or its log lines were never written).
//
// Mirrors ReconstructTaskStatesFromLogs's parsing logic but scoped to
// one task — useful for endpoints that need to look up a single task's
// state without paying for the per-scan full reconstruction.
//
// State precedence (matches the plural function):
//   [g3:done]   → state from marker's state= field
//   [g3:cancel] without [g3:done] → CANCELED
//   [g3:start]  without done/cancel → UNKNOWN (worker crashed mid-run)
//   [g3:dispatch] only → WAITING
func ReconstructTaskStateFromLogs(db SQLDBClient, scanid, taskid string) (string, string, error) {
	query := "SELECT `timestamp`, `text` FROM `logs` " +
		"WHERE `scanid` = ? AND `taskid` = ? AND `text` LIKE '[g3:%' " +
		"ORDER BY `timestamp`, `id` ASC"
	rows, err := db.db.Query(query, scanid, taskid)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	state := ""
	tool := ""
	dispatchSeen := false
	startSeen := false
	doneSeen := false
	cancelSeen := false

	for rows.Next() {
		var ts int64
		var text string
		if e := rows.Scan(&ts, &text); e != nil {
			return "", "", e
		}
		_ = ts // timestamp not currently used; reserved for future
		switch {
		case strings.HasPrefix(text, "[g3:dispatch]"):
			if dispatchSeen {
				continue // defensive: only first dispatch wins
			}
			dispatchSeen = true
			if t := parseMarkerField(text, "tool"); t != "" {
				tool = t
			}
			if state == "" {
				state = string(STATUS_WAITING)
			}
		case strings.HasPrefix(text, "[g3:start]"):
			startSeen = true
			state = string(STATUS_RUNNING)
		case strings.HasPrefix(text, "[g3:done]"):
			doneSeen = true
			if s := parseMarkerField(text, "state"); s != "" {
				state = s
			} else {
				state = string(STATUS_FINISHED)
			}
		case strings.HasPrefix(text, "[g3:cancel]"):
			cancelSeen = true
		}
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}

	// Resolve final state for tasks without a [g3:done] marker:
	//   - cancelSeen → CANCELED (worker killed before [g3:done])
	//   - startSeen without done/cancel → UNKNOWN (worker crashed mid-run)
	// Tasks whose [g3:done] arrived keep whatever state that marker set.
	if !doneSeen {
		if cancelSeen {
			state = string(STATUS_CANCELED)
		} else if startSeen {
			state = string(STATUS_UNKNOWN)
		}
	}

	return state, tool, nil
}
```

`parseMarkerField` and `STATUS_*` constants are already in scope (used by the plural function in the same file).

- [ ] **Step 3: Verify build**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`
Expected: no output, exit 0.

---

## Task 8: Rework `/scan/task/artifacts` to use Redis → SQL fallback

**Files:**
- Modify: `src/g3api/g3api.go`

- [ ] **Step 1: Locate the current handler**

Find the `/scan/task/artifacts` handler in `src/g3api/g3api.go` (around line 940+). The current logic stats the slot dir, then stats `manifest.json`, then reads + unmarshals the manifest to extract the tool name, then bundles. The replacement is a different decision flow that consults Redis first, then SQL, before touching the disk for bundling.

- [ ] **Step 2: Replace the handler body with the new decision flow**

Replace the entire handler body (everything between `http.HandleFunc(apiPath + "/scan/task/artifacts", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {` and the closing `}))`) with:

```go
		log.Debug("Handling: scan/task/artifacts")
		var request g3lib.ReqTaskArtifacts
		err := request.Decode(r)
		if err != nil {
			log.Error("Error decoding payload: " + err.Error())
			g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
			return
		}

		// Lifecycle lookup — Redis fast path, SQL log fallback. Filesystem
		// state never participates in the lifecycle decision. See
		// docs/superpowers/specs/2026-05-18-reporter-tier3-design.md Component 3.
		state, _ := g3lib.GetTaskState(rdb_client, request.ScanID, request.TaskID)
		toolName := ""

		switch state {
		case "DISPATCHED", "RUNNING":
			w.Header().Set("Retry-After", "2")
			g3lib.SendApiError(w, http.StatusTooEarly, "task is still "+state)
			return
		case "DONE", "ERROR", "CANCELED":
			// Terminal via Redis. Tool name lives in the same per-task hash
			// (populated by SetTaskDispatched). For simplicity we always
			// re-derive via SQL below so both paths share the same code —
			// SQL call is cheap relative to bundling and avoids a special
			// branch for the Redis-warm case.
			fallthrough
		default:
			// Either terminal via Redis (fallthrough) or Redis silent (state=="").
			// Consult SQL log markers for authoritative lifecycle and tool name.
			sqlState, sqlTool, qerr := g3lib.ReconstructTaskStateFromLogs(sql_db, request.ScanID, request.TaskID)
			if qerr != nil {
				log.Error("ReconstructTaskStateFromLogs failed: " + qerr.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			if sqlState == "" && state == "" {
				// No record anywhere: task never existed in this scan.
				g3lib.SendApiError(w, http.StatusNotFound, "task not found")
				return
			}
			// If Redis was terminal, use that; if SQL is more authoritative
			// (Redis silent), use that.
			effectiveState := state
			if effectiveState == "" {
				effectiveState = sqlState
			}
			switch effectiveState {
			case "DONE", "ERROR", "CANCELED":
				toolName = sqlTool
				// Proceed to bundling.
			case "WAITING", "RUNNING", "UNKNOWN":
				w.Header().Set("Retry-After", "2")
				g3lib.SendApiError(w, http.StatusTooEarly, "task is not yet complete")
				return
			default:
				log.Error("Unexpected effective task state: " + effectiveState)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
		}

		// Terminal — bundle and stream.
		artifactsRoot := os.Getenv(g3lib.G3_ARTIFACTS_ROOT)
		if artifactsRoot == "" {
			artifactsRoot = g3lib.G3_ARTIFACTS_ROOT_DEFAULT
		}
		slotDir := filepath.Join(artifactsRoot, request.ScanID, request.TaskID)
		if _, err := os.Stat(slotDir); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				g3lib.SendApiError(w, http.StatusNotFound, "task produced no output")
				return
			}
			log.Error("stat slot dir failed: " + err.Error())
			g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
			return
		}
		// Fallback tool name if SQL didn't have it (e.g. brand-new task that
		// somehow lost its dispatch marker — pathological but defended).
		if toolName == "" {
			toolName = request.TaskID
		}
		var buf bytes.Buffer
		filename, contentType, bundleErr := g3lib.BundleTaskSlot(slotDir, toolName, request.TaskID, &buf)
		if bundleErr != nil {
			if errors.Is(bundleErr, os.ErrNotExist) {
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
```

- [ ] **Step 3: Check for orphaned imports**

The replacement removes the manifest read + JSON unmarshal. `encoding/json` may no longer be used in g3api.go after this change. Quick check: `grep -n '"encoding/json"\|json\.' /home/crapula/code/g3/src/g3api/g3api.go`. If `json.` appears anywhere else (decoders, marshalers in other handlers), keep the import. Otherwise remove it.

Same check for any imports that were only used in the deleted manifest-read block (likely none other than `encoding/json`).

- [ ] **Step 4: Verify build**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./...`
Expected: no output, exit 0.

---

## Task 9: Amend Tier 1 and Tier 2 spec docs

**Files:**
- Modify: `docs/superpowers/specs/2026-05-16-reporter-plugins-design.md`
- Modify: `docs/superpowers/specs/2026-05-18-reporter-tier2-design.md`

- [ ] **Step 1: Amend the Tier 1 spec**

Open `docs/superpowers/specs/2026-05-16-reporter-plugins-design.md`. Find Component 3 ("Worker / MQTT integration"). At the end of the worker-flow pseudocode (around the WriteManifest line in the pseudocode block), update the worker-flow description to note:

Append a new short subsection at the end of Component 3:

```
### Manifests for reporter tasks

Reporter tasks do NOT write `manifest.json`. The manifest exists to encode
the useful-vs-forensic distinction (the `Work[].Artifacts` field), which
reporters have no need for — everything the reporter container writes to
`/output` is the report. The worker code path for reporter tasks skips
`WriteManifest` entirely; the slot contains only what the reporter wrote.

Tool tasks continue to write manifests as documented above. The
asymmetry is principled: tool tasks have a useful/forensic distinction
to encode, reporter tasks do not.
```

Also update the pseudocode in the worker-flow section to remove the `WriteManifest` step from the reporter branch (if the pseudocode mentions it for reporters).

- [ ] **Step 2: Amend the Tier 2 spec**

Open `docs/superpowers/specs/2026-05-18-reporter-tier2-design.md`. Find Component 1 ("POST /scan/task/artifacts"). Replace the "Behavior" subsection's disk-first framing with the new Redis → SQL fallback chain. The new text:

```
### Behavior (updated in Tier 3)

The endpoint is **lifecycle-first**: task state is read from Redis (fast
path) or reconstructed from SQL log markers (durable fallback). The
filesystem participates in the bundling step only, never in the lifecycle
decision. This mirrors how `/scan/tasks/status` already resolves state
across both stores.

Tool name comes from the SQL `[g3:dispatch]` marker (uniform across
task kinds). The endpoint no longer reads `manifest.json` — reporter
tasks don't write one (see Tier 3 design), and tool-task manifests
aren't needed at this layer either.

1. Decode + validate the request.
2. `GetTaskState(rdb, scan_id, task_id)`:
   - DISPATCHED/RUNNING → 425 + "task is still <STATE>" + Retry-After: 2.
   - DONE/ERROR/CANCELED → terminal; fall through to SQL for tool name.
   - "" or error → fall through to SQL.
3. `ReconstructTaskStateFromLogs(sql, scan_id, task_id)`:
   - No record AND Redis was silent → 404 "task not found".
   - WAITING/RUNNING/UNKNOWN → 425 + "task is not yet complete" + Retry-After: 2.
   - DONE/ERROR/CANCELED → terminal; tool name from same lookup.
4. Stat slot dir at <G3_ARTIFACTS_ROOT>/<scan_id>/<task_id>/:
   - Missing → 404 "task produced no output".
   - Present → BundleTaskSlot stream-to-response.
```

Also update the response matrix table in Component 1 to:

| Lifecycle lookup | Slot on disk | Status | Body / headers |
| --- | --- | --- | --- |
| Terminal (Redis or SQL) | Has ≥1 file | 200 | bundle per `BundleTaskSlot` rules |
| Terminal (Redis or SQL) | Empty or absent | 404 | `"task produced no output"` |
| DISPATCHED/RUNNING in Redis | n/a | 425 | `"task is still <STATE>"` + `Retry-After: 2` |
| WAITING/RUNNING/UNKNOWN via SQL only | n/a | 425 | `"task is not yet complete"` + `Retry-After: 2` |
| No record in Redis or SQL | n/a | 404 | `"task not found"` |
| Malformed request | n/a | 400 | `"Bad request."` |

Remove the prior "disk-first" framing throughout the section. The "Reused infrastructure" subsection's row about manifest reading is now obsolete — drop it. Add a row for `ReconstructTaskStateFromLogs`.

- [ ] **Step 3: No build verification (docs only)**

Spec doc changes don't affect the build. The Tier 3 spec doc itself (`2026-05-18-reporter-tier3-design.md`) already documents the new state; no edit needed there.

---

## Task 10: Cross-binary build sweep

**Files:**
- No edits. Build verification only.

- [ ] **Step 1: Build every Go binary**

Run from the repo root:

```
make bin
```

Expected: every binary in `src/` builds successfully. No errors, no warnings about unused imports or undefined identifiers.

If `make bin` is unavailable, run each binary's build directly:

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

- Scan scripts can declare `report <tool>[:<preset>]` as their last directive. Server-side, the scanner dispatches the reporter task via the canonical `dispatchTask` helper after pipeline completion. The reporter task is a first-class task observable via `/scan/tasks/status` and downloadable via `/scan/task/artifacts`.
- Reporter task slots no longer contain `manifest.json`. The `BundleTaskSlot` single-file branch fires naturally for the common case (clean `report.md` download instead of always-a-zip).
- `/scan/task/artifacts` reads task state from Redis → SQL log markers, never from the filesystem. The endpoint works uniformly for tool tasks (which still have manifests, irrelevant here) and reporter tasks (which don't). Tool name in the bundle filename comes from the SQL `[g3:dispatch]` marker.

Local CLI reporter integration remains deferred to a future tier.
