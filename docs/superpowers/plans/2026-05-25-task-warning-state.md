# Task WARNING State — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth task terminal state, **WARNING** ("produced usable results but something warrants reading the logs; pipeline continued"), derived in the worker from signals it already has, surfaced in the TUI, with worker diagnostics routed into the user-visible task log.

**Architecture:** Tier 1 is the whole behavioral change and lives in two files — `g3lib/plugin.go` (parse stdout regardless of exit code; single `error` return; unconditional nil placeholder) and `g3worker/g3worker.go` (decouple *fuel* from *state*; a hard-ERROR / no-fuel-ERROR / WARNING / DONE fork; `[g3:warn]` task-log lines). Task state and pipeline fuel are deliberately decoupled: the scanner advances on data alone and never reads task state. Tiers 2–4 (state plumbing, TUI, per-wrapper exit codes) are outlined here and detailed in their own plans when reached.

**Tech Stack:** Go 1.25, existing g3lib helpers (`IsValidData`, `ValidateArtifactClaims`, `SaveData`, `SendResponse`, `SendEmptyResponse`, `SaveLogLine`, `WriteManifest`, `markTerminal`), no new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-21-task-warning-state-design.md](../specs/2026-05-21-task-warning-state-design.md)

**Tier scope:** Tier 1 only is detailed and shippable. Tier 1 emits `"WARNING"` as a `markTerminal` string; it reaches Redis + the `[g3:done]` marker but is not *rendered* specially until Tier 3 and must be accepted as terminal by the artifacts endpoint in Tier 2 — so Tiers 1+2 should land together (see Rollout).

---

## Notes for executors

Same project-level overrides as every prior tier in this repo:

- **Tests are user-owned.** Do not write tests, do not run tests, do not use the test-driven-development skill.
- **Git is user-owned.** Do not run mutating git commands (`add`, `commit`, `mv`, `rm`, `push`). Read-only inspection (`git status`, `git diff`) is fine. The user commits at the end of the tier in one batch.
- **No per-task STOP.** Run through Tier 1 end-to-end without checkpoint pauses.
- **Verification per task = `go build ./...`** in the affected module (`src/g3lib` and/or `src/g3worker`). The final task does a cross-binary build sweep.

Key invariant to preserve (do not "optimize" away): **nils are counted-out of fuel but never dropped from persistence** — a non-canceled empty result persists exactly one `_type:"nil"` placeholder to seed the scanner's negative-result cache ([g3scanner.go:931](../../../src/g3scanner/g3scanner.go#L931)). CANCELED is the only state that neither saves nor seeds.

---

## Tier 1 — Worker classification (detailed)

### Task 1: `g3lib/plugin.go` — parse on failure, single error, unconditional nil

**Files:**
- Modify: `src/g3lib/plugin.go:617-668` (the tail of `runPluginInternal`)

- [ ] **Step 1: Parse stdout regardless of exit code; don't let parse clobber the exit error; inject the nil placeholder unconditionally**

Replace the current early-return + parse block:

```go
	if cancelled || err != nil {
		return outputArray, err
	}
	endTime := time.Now().Unix()

	// Parse the output JSON array and add some needed properties.
	// On error we will try to return the malformed data anyway.
	// If the output array is empty, add a dummy object to generate a valid fingerprint.
	raw := stdout.Bytes()
	//fmt.Println(string(raw))		// XXX DEBUG
	err = json.Unmarshal(raw, &outputArray)
	if err == nil && len(outputArray) == 0 {
		dummy := G3Data{}
		dummy["_type"] = "nil"
		outputArray = append(outputArray, dummy)
	}
```

with:

```go
	// Cancellation short-circuits: propagate ctx.Err() and discard any output.
	if cancelled {
		return outputArray, err
	}
	endTime := time.Now().Unix()

	// Parse stdout regardless of the container's exit code, so a tool that
	// failed but still produced data can be classified downstream (WARNING).
	// A parse error must not clobber a non-nil exit error: keep the exit error.
	raw := stdout.Bytes()
	//fmt.Println(string(raw))		// XXX DEBUG
	if perr := json.Unmarshal(raw, &outputArray); perr != nil && err == nil {
		err = perr
	}
	// Inject a nil placeholder for any empty result (success OR error) so the
	// worker can seed the negative-result cache. Cancellation already returned.
	if len(outputArray) == 0 {
		dummy := G3Data{}
		dummy["_type"] = "nil"
		outputArray = append(outputArray, dummy)
	}
```

- [ ] **Step 2: Preserve error precedence in the enrich loop**

The enrich loop reassigns `err` on a fingerprint-build failure. Guard it so it does not overwrite an exit/parse error already present. Change:

```go
				if len(errorArray) > 0 {
					err = errorArray[0]
					fingerprint = parsed.Fingerprint	// still better than nothing
				}
```

to:

```go
				if len(errorArray) > 0 {
					if err == nil {
						err = errorArray[0]
					}
					fingerprint = parsed.Fingerprint	// still better than nothing
				}
```

The function still returns `(outputArray, err)` — signature unchanged. All callers except the worker do `if err != nil { return }` and discard the output, so they are unaffected (parse-on-error output is consumed only by the worker, by design).

- [ ] **Step 3: Build**

Run: `cd src/g3lib && go build ./...`
Expected: clean build.

---

### Task 2: `g3worker/g3worker.go` — decouple fuel from state; WARNING fork; `[g3:warn]` logging

**Files:**
- Modify: `src/g3worker/g3worker.go:715-855` (the post-run block of the tool-task handler)
- Modify: `src/g3worker/g3worker.go` (add two package-level helpers)

- [ ] **Step 1: Add two helper functions at package scope**

Add near the other package-level helpers (e.g. just above `reporterLogWriter`, ~line 985). The `warnSummary` body uses `strconv.Itoa`; if `strconv` is not already imported in this file, add it to the import block (the build in Step 3 will flag it).

```go
// manifestExitStatus maps the terminal verdict to the manifest's
// exit_status string, preserving the artifact-claim detail when present so
// the forensic record names the exact violation.
func manifestExitStatus(state string, claimErr error) string {
	if claimErr != nil {
		return claimErr.Error()
	}
	switch state {
	case "WARNING":
		return "warning"
	case "ERROR":
		return "error"
	case "CANCELED":
		return "canceled"
	default:
		return "success"
	}
}

// warnSummary builds the single human-readable [g3:warn] verdict line for a
// WARNING/ERROR task. Returns "" when there is nothing to say.
func warnSummary(runErr error, droppedCount int, claimErr error) string {
	switch {
	case claimErr != nil:
		return "artifact claim violation: " + claimErr.Error()
	case runErr != nil:
		return runErr.Error()
	case droppedCount > 0:
		return "dropped " + strconv.Itoa(droppedCount) + " malformed object(s)"
	default:
		return ""
	}
}
```

- [ ] **Step 2: Replace the post-run block (manifest build through send response)**

Replace everything from the manifest-build comment (`// Build and write the per-task manifest...`, currently line 715) through the final `SendResponse` error check (currently line 855) with the block below. This restructures the handler to compute fuel and state separately.

```go
		// Remove the cancel context and acknowledge any pending cancel.
		cancelTracker.ForgetTask(task.TaskID)
		if e := g3lib.SendTaskCancelHandled(mq_client, task.ScanID, []string{task.TaskID}); e != nil {
			log.Error(e.Error())
		}

		// CANCELED (per-task cancel via context, or worker SIGINT mid-run) is
		// orthogonal to result quality and short-circuits everything: no save,
		// no cache seed, empty response.
		canceled := errors.Is(err, context.Canceled) || cancelled

		// Enumerate the slot for the manifest.
		manifestFiles, enumErr := g3lib.EnumerateSlot(slotDir)
		if enumErr != nil {
			log.Error("Cannot enumerate artifact slot " + slotDir + ": " + enumErr.Error())
			manifestFiles = []g3lib.G3ManifestFile{}
		}

		// Validate plugin output; drop invalid objects, mirroring each reject
		// into the user-visible task log as a [g3:warn] line (tagged by tool so
		// a user can grep one tool's warnings across tasks).
		sanitizedOutput := []g3lib.G3Data{}
		for _, d := range outputArray {
			ok, verr := g3lib.IsValidData(d)
			if !ok {
				reason := ""
				if verr != nil {
					reason = ": " + verr.Error()
				}
				log.Error("Malformed output data" + reason + "\n" + d.String())
				if e := g3lib.SaveLogLine(sql_db, task.ScanID, task.TaskID,
					"[g3:warn] tool="+task.Tool+" dropped malformed object"+reason); e != nil {
					log.Error(e.Error())
				}
			} else {
				sanitizedOutput = append(sanitizedOutput, d)
			}
		}
		droppedCount := len(outputArray) - len(sanitizedOutput)

		// Partition into actionable (non-nil) and nil placeholders. Nils never
		// count as pipeline fuel; a non-canceled empty result keeps exactly one
		// nil to seed the scanner's negative-result cache.
		actionable := []g3lib.G3Data{}
		nils := []g3lib.G3Data{}
		for _, d := range sanitizedOutput {
			if t, _ := d["_type"].(string); t == "nil" {
				nils = append(nils, d)
			} else {
				actionable = append(actionable, d)
			}
		}
		var toPersist []g3lib.G3Data
		switch {
		case len(actionable) > 0:
			if len(nils) > 0 {
				// Real data mixed with nils is a bug smell, not a normal empty result.
				if e := g3lib.SaveLogLine(sql_db, task.ScanID, task.TaskID,
					"[g3:warn] tool="+task.Tool+" emitted nil alongside actionable data"); e != nil {
					log.Error(e.Error())
				}
			}
			toPersist = actionable
		case len(nils) > 0:
			toPersist = nils[:1] // collapse 0/1/many nils → one cache seed
		}

		// Artifact-claim validation runs over the actionable objects (the ones
		// that make claims). A violation is a hard contract breach → ERROR, but
		// the data still flows to the scanner below (state ≠ fuel).
		var claimErr error
		if !canceled {
			claimErr = g3lib.ValidateArtifactClaims(actionable, manifestFiles)
		}

		// Compute the terminal verdict. State and fuel are decoupled (see spec).
		softSignal := err != nil || droppedCount > 0
		var state string
		switch {
		case canceled:
			state = "CANCELED"
		case claimErr != nil:
			state = "ERROR" // hard contract breach
		case softSignal && len(actionable) == 0:
			state = "ERROR" // signal, no fuel
		case softSignal:
			state = "WARNING" // signal, fuel present
		default:
			state = "DONE"
		}

		// Write the manifest; exit_status mirrors the verdict.
		manifestWriteErr := g3lib.WriteManifest(slotDir, g3lib.G3Manifest{
			ScanID:     task.ScanID,
			TaskID:     task.TaskID,
			Plugin:     plugin.Name,
			Tool:       g3lib.ManifestTool(actionable, plugin),
			ExitStatus: manifestExitStatus(state, claimErr),
			StartedAt:  pluginStartTS,
			EndedAt:    pluginEndTS,
			Files:      manifestFiles,
			Work:       g3lib.BuildManifestWork(actionable),
		})
		if manifestWriteErr != nil {
			log.Error("Cannot write task manifest for " + task.TaskID + ": " + manifestWriteErr.Error())
			state = "ERROR" // a task without a written manifest is incomplete
		}

		// CANCELED: no save, no cache seed, empty response.
		if canceled {
			markTerminal(task.ScanID, task.TaskID, "CANCELED")
			if e := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); e != nil {
				log.Error(e.Error())
			}
			return
		}

		// FUEL (state-independent): persist + send for every non-canceled task.
		// Seeds the cache (including ERROR); the pipeline advances iff actionable
		// data was produced — the scanner skips nils.
		if len(toPersist) > 0 {
			if _, e := g3lib.SaveData(mdb_client, task.ScanID, task.TaskID, toPersist); e != nil {
				log.Error("Error saving data to MongoDB: " + e.Error())
			}
		}
		persistentOutput := []g3lib.G3Data{}
		for _, d := range toPersist {
			if _, ok := d["_id"]; ok {
				persistentOutput = append(persistentOutput, d)
			}
		}

		// One summary [g3:warn] line for WARNING/ERROR (the authoritative verdict
		// is the [g3:done] state=... marker written by markTerminal below).
		if state == "WARNING" || state == "ERROR" {
			if summary := warnSummary(err, droppedCount, claimErr); summary != "" {
				if e := g3lib.SaveLogLine(sql_db, task.ScanID, task.TaskID,
					"[g3:warn] tool="+task.Tool+" "+summary); e != nil {
					log.Error(e.Error())
				}
			}
		}

		markTerminal(task.ScanID, task.TaskID, state)
		if len(persistentOutput) > 0 {
			if _, e := g3lib.SendResponse(client, task, persistentOutput); e != nil {
				log.Error("Error sending response to the broker: " + e.Error())
			}
		} else {
			if e := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); e != nil {
				log.Error(e.Error())
			}
		}
```

Notes for the executor:
- This **removes** the old standalone branches it supersedes: the `manifestStatus` switch, the early `if errors.Is(err, context.Canceled)`, the `if err != nil`, the `if validationErr != nil`, the `if manifestWriteErr != nil`, and the `if cancelled` (SIGINT-after-success) block. Their behavior is folded into the new `canceled` short-circuit and the state switch.
- `cancelled` (worker SIGINT, declared ~line 322) and `errors.Is(err, context.Canceled)` (per-task cancel) are both folded into `canceled`.
- A hard-ERROR task with actionable data now **still sends its data** (`persistentOutput` non-empty → `SendResponse`), unlike the old code which sent empty on every error. This is the intended decoupling.

- [ ] **Step 3: Build the module, then sweep all binaries**

Run: `cd src/g3worker && go build ./...`
Expected: clean build. If it complains about an unused/`strconv` import, fix the import block.

Then from `src/`, sweep every binary:
Run: `cd src && for m in g3 g3api g3cli g3config g3scanner g3worker g3lib; do (cd $m && go build ./...) || echo "FAILED: $m"; done`
Expected: no `FAILED` lines. (g3lib has no `main`; `go build ./...` still type-checks it.)

---

## Tier 2 — Terminal-state plumbing (outline)

Detailed in its own plan when reached. Make `"WARNING"` a first-class terminal state wherever a state string is matched, treated as a results-producing terminal outcome like DONE.

- `src/g3api/g3api.go` — add `"WARNING"` to the `/scan/task/artifacts` terminal switches ([:949](../../../src/g3api/g3api.go#L949), [:977](../../../src/g3api/g3api.go#L977)); otherwise a WARNING task hits `default:` → 500.
- `src/g3lib/sql.go` — confirm `ReconstructTaskStateFromLogs` / `ReconstructTaskStatesFromLogs` pass `state=WARNING` through verbatim (they read the marker's `state=` field; verify no whitelist filters it).
- One-time confirmation: g3api's scan-status handling derives from the `Send*` MQTT messages, not from task states (spec confirms `G3Response` carries no state field), so no scan-level rollup work is needed.

**Land Tiers 1 + 2 together** so no endpoint can encounter an unhandled WARNING state.

## Tier 3 — TUI surfacing (outline)

- `src/g3tui/internal/ui/scandetail.go` — add a `"WARNING"` case to the task-state switches ([:541](../../../src/g3tui/internal/ui/scandetail.go#L541), [:576-584](../../../src/g3tui/internal/ui/scandetail.go#L576), [:641-649](../../../src/g3tui/internal/ui/scandetail.go#L641)) with a distinct glyph/color (amber `⚠`), ordered between DONE and ERROR.
- `src/g3tui/internal/ui/styles.go` — a WARNING style token.

## Tier 4 — Per-wrapper exit-code normalization (outline)

Per-plugin authoring; its own plan when reached. A wrapper has two binary levers and chooses **neither the terminal state nor WARNING-vs-ERROR** (the worker derives those, Tier 1): the **exit code** (`0` = nothing to flag, non-zero = soft signal) and whether it emits data (normally just the importer's output; suppressed only for a deliberate hard stop). The worker maps `0` → DONE, `non-zero + data` → WARNING, `non-zero + no data` → ERROR. So the audit produces a per-wrapper **"native condition → {exit 0, non-zero}"** table — not a state table. Highlights: piped shell wrappers (`nmap`/`subfinder`/`wafw00f`) must recover the tool's real status instead of `tee`'s (`PIPESTATUS`/`pipefail`) — all three exit 0 on negative results, so any recovered non-zero is real; `dig` is already correct (0 incl. NXDOMAIN, 9/1/8/10 real) — leave as-is; Python (`testssl`/`hydra`) stop forcing `exit 0` and just propagate the tool's real code (fold the per-target loop as "any non-zero → non-zero") — both tools are well-behaved (0 = clean, non-zero = real failure), no per-code threshold. testssl exits 0 even when a sub-test like the CAA-DNS probe fails, so that case lands as DONE; hydra returns 0 whether or not creds were found.

**`nikto` is excluded from this Tier 4** — its exit-code regression was fixed only in nikto 2.6.0 (2026-02), so adopting it requires pinning ≥2.6.0 (a Dockerfile source-install refactor, since `apk add nikto` floats and likely ships 2.5.0) plus importer compatibility with 2.6.0's changed report format. That's a separate plan (see the spec's Future-work section), not a mechanical wrapper edit.
