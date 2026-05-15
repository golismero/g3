# Shared Artifacts Volume Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every plugin an isolated per-task directory to write raw tool artifacts into, recorded by a worker-written `manifest.json`, on a shared volume whose backend is a deployment decision.

**Architecture:** The worker materializes `<artifacts-root>/<scanid>/<taskid>/` before each plugin runs and bind-mounts *only that subdirectory* into the plugin container as `/artifacts`. After the plugin exits the worker writes `manifest.json` (plugin, canonical tool name, command, status, timestamps, file list) into the slot. g3 code only ever sees POSIX paths; what backs the volume (local disk, NFS, CephFS, s3fs…) is set by the operator's mount.

**Tech Stack:** Go 1.25 (g3lib, g3worker — separate modules linked via `replace`), Docker (`docker run` shelled out by the worker), docker-compose, `github.com/kballard/go-shellquote`.

**Spec:** [`docs/superpowers/specs/2026-05-14-shared-artifacts-volume-design.md`](../specs/2026-05-14-shared-artifacts-volume-design.md)

---

## Project constraints — overrides to the writing-plans defaults

These override the writing-plans skill's TDD/commit defaults, per this repository's established conventions:

- **Tests are maintainer-owned.** Tasks do **not** write tests, run test suites, run binaries, or hit live servers. No `go test` steps.
- **Git is maintainer-owned.** Tasks do **not** run `git add` / `git commit`. The maintainer commits at the end of each tier in one batch.
- **Per-task verification = build + lint only:** `go build ./...` and `golangci-lint run ./...` in the affected module.
- **Tiered delivery.** Only Tier 1 is detailed below. **STOP at the end of Tier 1** and revisit with the maintainer before detailing/starting Tier 2.
- **No formatting enforcement** — do not run `gofmt`/`goimports`; the build and `golangci-lint` are the gate.

---

## Tier overview

- **Tier 1 — Worker-side (detailed below).** Env config + startup writability check, per-task artifact slot creation, `/artifacts` bind-mount, `manifest.json` writing, and docker-compose/`.env` wiring for the worker services. Delivers: plugins can write artifacts; every executed task gets a manifest. Independently testable.
- **Tier 2 — g3api-side (outline only, see end of document).** `G3_UPLOAD_TTL`, relocating uploads from `/tmp` into `<root>/_uploads/`, moving them into `<root>/<scanid>/imports/` at import time, `/scan/delete` artifact cleanup, the `_uploads/` orphan-sweep goroutine, and docker-compose/`.env` wiring for g3api.

Between Tier 1 and Tier 2, artifacts accumulate with no cleanup (cleanup lands in Tier 2's `/scan/delete` change). This is expected for the tiered rollout.

---

## Tier 1 — Worker-side

### File structure

| File | Disposition | Responsibility |
|---|---|---|
| `src/g3lib/plugin.go` | Modify | Add the three artifacts env-var name constants next to `G3_DOCKER_NETWORK`. |
| `src/g3lib/manifest.go` | **Create** | The `G3Manifest` data model, `ManifestProvenance` (derive canonical `tool`/`cmd`), and `WriteTaskManifest` (enumerate slot, write `manifest.json`). One focused file — the manifest is its own concern. |
| `src/g3worker/g3worker.go` | Modify | `main()`: resolve the artifacts root + fail-fast writability check. Task closure: create the per-task slot, append the `/artifacts` bind-mount, write the manifest after the plugin exits. |
| `docker-compose.yml` | Modify | Mount `./volumes/artifacts` into all five worker services; set `G3_ARTIFACTS_ROOT` / `G3_ARTIFACTS_HOST_ROOT`. |
| `.env` | Modify | Document the two new artifacts env vars. |

---

### Task 1: g3lib — artifacts env-var constants

**Files:**
- Modify: `src/g3lib/plugin.go:22`

- [ ] **Step 1: Add the constants**

In `src/g3lib/plugin.go`, the line at 22 currently reads:

```go
const G3_DOCKER_NETWORK = "G3_DOCKER_NETWORK"
```

Replace it with:

```go
const G3_DOCKER_NETWORK = "G3_DOCKER_NETWORK"

// Environment variables for the shared artifacts volume.
//   G3_ARTIFACTS_ROOT      — path the worker process itself reads/writes (mkdir, manifest).
//   G3_ARTIFACTS_HOST_ROOT — path passed to `docker run -v` (the host daemon's view).
// They hold the same value when the artifacts root is mounted at an identical
// absolute path on the host and inside the worker container; G3_ARTIFACTS_HOST_ROOT
// is the escape hatch for deployments that cannot achieve that parity.
const G3_ARTIFACTS_ROOT = "G3_ARTIFACTS_ROOT"
const G3_ARTIFACTS_HOST_ROOT = "G3_ARTIFACTS_HOST_ROOT"
const G3_ARTIFACTS_ROOT_DEFAULT = "/app/artifacts"
```

- [ ] **Step 2: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.`

---

### Task 2: g3lib — manifest module

**Files:**
- Create: `src/g3lib/manifest.go`

- [ ] **Step 1: Create the manifest module**

Create `src/g3lib/manifest.go` with exactly this content:

```go
package g3lib

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/kballard/go-shellquote"
)

// ManifestFilename is the name of the per-task manifest the worker writes into
// each task's artifact slot directory.
const ManifestFilename = "manifest.json"

// G3ManifestFile describes one file a plugin left in its artifact slot.
type G3ManifestFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
}

// G3Manifest is the per-task record written into
// <artifacts-root>/<scanid>/<taskid>/manifest.json. It is the integration
// contract downstream consumers (e.g. magenta) read to map artifact files back
// to the tool that produced them.
type G3Manifest struct {
	ScanID     string           `json:"scan_id"`
	TaskID     string           `json:"task_id"`
	Plugin     string           `json:"plugin"`
	Tool       string           `json:"tool"`
	Cmd        string           `json:"cmd"`
	ExitStatus string           `json:"exit_status"`
	StartedAt  int64            `json:"started_at"`
	EndedAt    int64            `json:"ended_at"`
	Files      []G3ManifestFile `json:"files"`
}

// ManifestProvenance derives the canonical tool name and command line for a
// task's manifest. It prefers the _tool / _cmd the plugin stamped onto its
// emitted G3Data (guaranteed present and string-shaped by runPluginInternal),
// and falls back to the same defaults runPluginInternal would inject when the
// output array is empty (e.g. the plugin emitted unparseable JSON).
func ManifestProvenance(outputArray []G3Data, plugin G3Plugin, parsed ParsedPluginCommand) (string, string) {
	tool := plugin.Name
	cmd := shellquote.Join(parsed.Command...)
	if len(outputArray) > 0 {
		if t, ok := outputArray[0]["_tool"].(string); ok && t != "" {
			tool = t
		}
		if c, ok := outputArray[0]["_cmd"].(string); ok && c != "" {
			cmd = c
		}
	}
	return tool, cmd
}

// WriteTaskManifest enumerates the files in slotDir, fills m.Files, and writes m
// as JSON to slotDir/manifest.json. It is always called after a plugin runs —
// even when the plugin produced no files — so every executed task has a manifest.
func WriteTaskManifest(slotDir string, m G3Manifest) error {
	entries, err := os.ReadDir(slotDir)
	if err != nil {
		return err
	}
	m.Files = []G3ManifestFile{}
	for _, entry := range entries {
		// TODO: subdirectories a plugin creates are not recursed into; only
		// top-level files in the slot are listed. Revisit if a plugin ever
		// needs a nested artifact layout.
		if entry.IsDir() || entry.Name() == ManifestFilename {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		m.Files = append(m.Files, G3ManifestFile{
			Name:     entry.Name(),
			Size:     info.Size(),
			Modified: info.ModTime().Unix(),
		})
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(slotDir, ManifestFilename), data, 0o644)
}
```

- [ ] **Step 2: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.` (`ManifestProvenance` / `WriteTaskManifest` are exported, so `unused` will not flag them even though no caller exists yet.)

---

### Task 3: g3worker — startup artifacts-root resolution + writability check

**Files:**
- Modify: `src/g3worker/g3worker.go:288` (insert after the "Holding on to cancellation request messages" debug line, inside `main()`)

`os`, `time`, and `path/filepath` are already imported by `g3worker.go` — no import changes.

- [ ] **Step 1: Insert the resolution + fail-fast check**

In `src/g3worker/g3worker.go`, find this line inside `main()` (≈ line 288):

```go
	log.Debug("Holding on to cancellation request messages for " + holdCancel.String())
```

Insert immediately **after** it:

```go

	// Resolve the shared artifacts root and verify it is writable. Plugins
	// write raw tool outputs into per-task subdirectories here; a worker that
	// cannot write artifacts is broken, so fail fast rather than run with a
	// silently disabled subsystem.
	artifactsRoot := os.Getenv(g3lib.G3_ARTIFACTS_ROOT)
	if artifactsRoot == "" {
		artifactsRoot = g3lib.G3_ARTIFACTS_ROOT_DEFAULT
	}
	artifactsHostRoot := os.Getenv(g3lib.G3_ARTIFACTS_HOST_ROOT)
	if artifactsHostRoot == "" {
		artifactsHostRoot = artifactsRoot
	}
	if err := os.MkdirAll(artifactsRoot, 0o755); err != nil {
		log.Critical("Cannot create artifacts root " + artifactsRoot + ": " + err.Error())
		os.Exit(1)
	}
	probeFile := filepath.Join(artifactsRoot, ".g3-write-test")
	if err := os.WriteFile(probeFile, []byte{}, 0o644); err != nil {
		log.Critical("Artifacts root " + artifactsRoot + " is not writable: " + err.Error())
		os.Exit(1)
	}
	os.Remove(probeFile) //nolint:errcheck
	log.Debug("Artifacts root: " + artifactsRoot + " (host view: " + artifactsHostRoot + ")")
```

`artifactsRoot` and `artifactsHostRoot` are declared in `main()`'s scope; the task-handler closure (registered later via `SubscribeAsWorker`) captures them by closure — Task 4 relies on this.

- [ ] **Step 2: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3worker && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.` Note: `artifactsRoot` / `artifactsHostRoot` are declared-but-not-yet-used until Task 4 — Go tolerates unused *captured-by-later-closure* variables only if used; if `go build` reports "declared and not used", that is expected to disappear in Task 4. If it blocks here, proceed to Task 4 and verify both together.

> **Note for the executor:** Go *will* error on a truly unused local variable. Because the closure that uses these variables is added in Task 4, Tasks 3 and 4 both touch `g3worker.go` and should be treated as a pair — if Step 2 here reports "declared and not used", continue directly to Task 4 and run the verification at the end of Task 4 to cover both.

---

### Task 4: g3worker — per-task slot creation, `/artifacts` mount, manifest write

**Files:**
- Modify: `src/g3worker/g3worker.go:648-649` (inside the task-handler closure registered by `SubscribeAsWorker`)

- [ ] **Step 1: Replace the plugin-run call with slot setup + run + manifest write**

In `src/g3worker/g3worker.go`, find these two consecutive lines (≈ 648-649) inside the task-handler closure:

```go
		log.Info("Running plugin: " + task.Tool)
		outputArray, err := g3lib.RunPluginCommand(ctx, plugin, parsed, data, w)
```

Replace them with:

```go
		// Materialize this task's artifact slot and bind-mount it into the
		// plugin container as /artifacts. The plugin sees only its own slot —
		// the scanid/taskid layout above it is invisible and unreachable.
		slotDir := filepath.Join(artifactsRoot, task.ScanID, task.TaskID)
		if err := os.MkdirAll(slotDir, 0o755); err != nil {
			log.Error("Cannot create artifact slot " + slotDir + ": " + err.Error())
			markTerminal(task.ScanID, task.TaskID, "ERROR")
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			return
		}
		hostSlotDir := filepath.Join(artifactsHostRoot, task.ScanID, task.TaskID)
		parsed.DockerOpt = append(append([]string{}, parsed.DockerOpt...),
			"-v", hostSlotDir+":/artifacts:rw")

		log.Info("Running plugin: " + task.Tool)
		pluginStartTS := time.Now().Unix()
		outputArray, err := g3lib.RunPluginCommand(ctx, plugin, parsed, data, w)

		// Write the per-task manifest: a record of what ran and which files the
		// plugin left in its slot. Written for every outcome (success, error,
		// cancel) so every task that reached execution has a manifest.
		manifestTool, manifestCmd := g3lib.ManifestProvenance(outputArray, plugin, parsed)
		manifestStatus := "success"
		if err != nil {
			manifestStatus = err.Error()
		}
		if e := g3lib.WriteTaskManifest(slotDir, g3lib.G3Manifest{
			ScanID:     task.ScanID,
			TaskID:     task.TaskID,
			Plugin:     plugin.Name,
			Tool:       manifestTool,
			Cmd:        manifestCmd,
			ExitStatus: manifestStatus,
			StartedAt:  pluginStartTS,
			EndedAt:    time.Now().Unix(),
		}); e != nil {
			log.Error("Cannot write task manifest for " + task.TaskID + ": " + e.Error())
		}
```

Notes on the change:
- `append(append([]string{}, parsed.DockerOpt...), ...)` builds a *fresh* slice so the plugin-metadata's backing array is never mutated. `runPluginInternal` already does `commandLine = append(commandLine, parsed.DockerOpt...)`, so the `-v` lands among the docker options before the image name — correct placement. No g3lib function signature changes.
- The `MkdirAll`-failure branch mirrors the closure's existing error pattern (`markTerminal(..., "ERROR")` → `SendEmptyResponse` → `return`, as at the current lines ≈ 671-680).
- `ExitStatus` is `"success"` when `RunPluginCommand` returns `nil`, otherwise the error string. The CANCELED-vs-ERROR orchestration distinction is decided in the branches further down and lives in Redis/Mongo; the manifest records the tool-run outcome.
- `markTerminal`, `mq_client`, `artifactsRoot`, `artifactsHostRoot` are all in scope (captured from `main()`).

- [ ] **Step 2: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3worker && go build ./... && golangci-lint run ./...`
Expected: build exits 0 (this also clears any "declared and not used" from Task 3); lint prints `0 issues.`

---

### Task 5: docker-compose + .env wiring for the worker services

**Files:**
- Modify: `docker-compose.yml` (all five services with `entrypoint: /bin/g3worker` — the nmap-dedicated worker plus `g3worker1`–`g3worker4`)
- Modify: `.env`

- [ ] **Step 1: Mount the artifacts volume into each worker service**

For **each** of the five worker services, the `volumes:` block currently looks like:

```yaml
    volumes:
      - ./config:/app/config
      - ./resources:/app/resources
      - /var/run/docker.sock:/var/run/docker.sock
```

Add the artifacts mount so it becomes:

```yaml
    volumes:
      - ./config:/app/config
      - ./resources:/app/resources
      - ./volumes/artifacts:/app/artifacts
      - /var/run/docker.sock:/var/run/docker.sock
```

- [ ] **Step 2: Set the artifacts env vars on each worker service**

For **each** of the five worker services, in the `environment:` block, add these two lines (placement near the other `G3_` vars, e.g. after `G3_DOCKER_NETWORK`):

```yaml
      - G3_ARTIFACTS_ROOT=/app/artifacts
      - G3_ARTIFACTS_HOST_ROOT=${PWD}/volumes/artifacts
```

`G3_ARTIFACTS_ROOT=/app/artifacts` is the worker container's view (matches the bind-mount target). `G3_ARTIFACTS_HOST_ROOT=${PWD}/volumes/artifacts` is the **host daemon's** view — `docker compose` interpolates `${PWD}` to the directory `docker compose` is invoked from (the repo root), so the host path resolves correctly when the worker shells out `docker run -v`. The two values differ here because the compose demo cannot achieve host/container path parity with a relative bind-mount; `G3_ARTIFACTS_HOST_ROOT` is exactly the escape hatch for that.

- [ ] **Step 3: Document the new vars in `.env`**

In `.env`, find the worker configuration section:

```
# Golismero g3worker configuration.
G3_WORKER_ID=g3worker-debug
G3_HOLD_CANCEL=5m
```

Insert a new section immediately after it:

```
# Golismero shared artifacts volume.
# G3_ARTIFACTS_ROOT is the path the worker/g3api processes read and write.
# G3_ARTIFACTS_HOST_ROOT is what the worker passes to `docker run -v` (the host
# daemon's view); it equals G3_ARTIFACTS_ROOT when the volume is mounted at the
# same absolute path on host and container. In docker-compose these are set
# explicitly per-service; the entries here are for running the binaries directly.
#G3_ARTIFACTS_ROOT=/app/artifacts
#G3_ARTIFACTS_HOST_ROOT=/app/artifacts
```

- [ ] **Step 4: Verify**

This task changes only YAML/env config — there is no build step. Verify by review:
- All five `/bin/g3worker` services have the `./volumes/artifacts:/app/artifacts` volume line and both `G3_ARTIFACTS_*` env lines.
- `git diff docker-compose.yml .env` shows only the intended additions.

Running the compose stack to confirm end-to-end behavior is the maintainer's step (binaries/stack are maintainer-owned).

---

### Task 6: Full cross-module build + lint

**Files:** none (verification only)

- [ ] **Step 1: Build and lint both affected modules**

Run:
```
cd /home/crapula/code/g3/src/g3lib && go build ./... && golangci-lint run ./...
cd /home/crapula/code/g3/src/g3worker && go build ./... && golangci-lint run ./...
```
Expected: both `go build` invocations exit 0; both `golangci-lint` runs print `0 issues.`

- [ ] **Step 2: STOP — end of Tier 1**

Tier 1 is complete. Do **not** start Tier 2. Hand back to the maintainer to:
1. Commit Tier 1 in one batch.
2. Optionally smoke-test: run a scan, confirm `volumes/artifacts/<scanid>/<taskid>/manifest.json` appears with a `files` list, and that a plugin writing to `/artifacts/` lands files in that slot.
3. Revisit this plan with the maintainer to detail Tier 2.

---

## Tier 2 — g3api-side (outline only)

Detail to be filled in at Tier 2 kickoff, per the tiered-plan convention. Anticipated tasks:

- **`G3_UPLOAD_TTL` constant** — name constant + default (`0` = orphan sweep disabled) in g3lib or g3api.
- **`POST /upload` relocation** — change the upload handler ([`g3api.go` upload handler, ≈ line 917](../../../src/g3api/g3api.go)) to write `<root>/_uploads/<uuid>.bin` + `.txt` instead of `/tmp/<uuid>.*`. Return value (the bare uuid) unchanged — no API contract change.
- **Import-time move** — the `POST /scan` import loop ([`g3api.go` import loop, ≈ line 354](../../../src/g3api/g3api.go)) `os.Rename`s the `.bin`/`.txt` pair from `_uploads/` into `<root>/<scanid>/imports/` before opening it.
- **`/scan/delete` cleanup** — add `os.RemoveAll(<root>/<scanid>)` as one more best-effort step in the existing delete chain ([`g3api.go:635`](../../../src/g3api/g3api.go#L635)), contributing to `reterr` on failure like the steps around it.
- **`_uploads/` orphan sweep** — a goroutine ticker in g3api `main()` deleting `_uploads/` entries older than `G3_UPLOAD_TTL`; `G3_UPLOAD_TTL=0` disables it entirely.
- **docker-compose + `.env`** — mount `./volumes/artifacts` into the g3api service; document `G3_UPLOAD_TTL`; uncomment/clarify the `.env` artifacts entries as needed.

---

## Self-review

**1. Spec coverage (Tier 1 scope):**
- Component 1 "worker's per-task slot" — Tasks 3 (root resolution + writability) & 4 (slot mkdir + `/artifacts` bind-mount). ✅
- Component 1 "host-path parity" — `G3_ARTIFACTS_ROOT` / `G3_ARTIFACTS_HOST_ROOT` constants (Task 1), worker resolution (Task 3), compose wiring with `${PWD}` (Task 5). ✅
- Component 1 failure handling — fail-fast startup check (Task 3), `MkdirAll`-failure → `ERROR` (Task 4). ✅
- Component 2 "the manifest" — `manifest.go` model + writer (Task 2), worker invocation lifting `tool`/`cmd` from the output array (Task 4). ✅
- Component 2 "always written, even with no files" — `WriteTaskManifest` initializes `Files` to `[]` and writes regardless (Task 2); worker calls it unconditionally after the run (Task 4). ✅
- Component 2 "`_cmd` guaranteed a string" — relies on the already-landed `runPluginInternal` normalization; `ManifestProvenance` reads it with a safe type assertion + fallback (Task 2). ✅
- Components 3 & 4 (uploads, lifecycle) — **Tier 2**, intentionally not in this tier's tasks.
- Config & deployment (worker portion) — Task 5. g3api portion is Tier 2.

**2. Placeholder scan:** No "TBD"/"TODO" as plan content. The one `// TODO` inside `WriteTaskManifest` is an intentional in-code marker for a known, accepted limitation (no subdir recursion), per repo convention — not a plan placeholder. All code steps contain complete code.

**3. Type consistency:** `G3Manifest`, `G3ManifestFile`, `ManifestFilename`, `ManifestProvenance(outputArray []G3Data, plugin G3Plugin, parsed ParsedPluginCommand) (string, string)`, and `WriteTaskManifest(slotDir string, m G3Manifest) error` are defined in Task 2 and used with exactly those names/signatures in Task 4. `G3_ARTIFACTS_ROOT` / `G3_ARTIFACTS_HOST_ROOT` / `G3_ARTIFACTS_ROOT_DEFAULT` defined in Task 1, used in Task 3. `artifactsRoot` / `artifactsHostRoot` declared in Task 3, consumed in Task 4. Consistent.
