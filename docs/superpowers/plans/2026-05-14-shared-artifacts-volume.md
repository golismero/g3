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

- **Tier 1 — Worker-side ✅ COMPLETED 2026-05-15.** Env config + startup writability check, per-task artifact slot creation, `/artifacts` bind-mount, `manifest.json` writing, and docker-compose/`.env` wiring for the worker services. Delivered: plugins can write artifacts; every executed task gets a manifest. Smoke-tested by the maintainer.
- **Tier 1b — Manifest model refactor ✅ COMPLETED 2026-05-16.** Smoke-testing surfaced a design gap: the flat manifest assumes one command per task, but a plugin entrypoint script can run multiple sub-commands (testssl-per-port, vulners-per-CPE, etc.). Tier 1b reshapes the manifest to a per-command `work[]` array, introduces `G3Data._artifacts` for plugins to claim their files, makes the slot's actual file enumeration authoritative (`files[]` at root), and treats claimed-but-missing or malformed claims as loud task errors. Delivered: the manifest faithfully records multi-command plugin runs and surfaces plugin bugs as ERROR-state tasks.
- **Tier 2 — g3api-side (detailed below).** `G3_UPLOAD_TTL`, relocating uploads from `/tmp` into `<root>/_uploads/`, moving them into `<root>/<scanid>/imports/` at import time, `/scan/delete` artifact cleanup, the `_uploads/` orphan-sweep goroutine, and docker-compose/`.env` wiring for g3api.

Between Tier 1b and Tier 2, artifacts accumulate with no cleanup (cleanup lands in Tier 2's `/scan/delete` change). This is expected for the tiered rollout.

---

## Tier 1 — Worker-side ✅ COMPLETED 2026-05-15

> All six tasks landed and smoke-tested (manifest.json files observed in the artifacts tree). Checkboxes below preserved for the historical record.

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

## Tier 1b — Manifest model refactor ✅ COMPLETED 2026-05-16

> All Tier 1b tasks landed (uncommitted on the working tree at the time of writing). The manifest now carries `work[]` per-command groupings, validated `_artifacts` claims, and `files[]` enumeration; the `RunPluginCommand` signature gained an explicit `artifactsHostDir string` parameter (replacing the Tier-1 "mutate `parsed.DockerOpt`" approach). Checkboxes preserved for the historical record.
>
> Smoke-testing Tier 1 surfaced a design gap: the manifest's flat `cmd` + `files` assumes one command per task, but a plugin entrypoint script can run multiple sub-commands (testssl-per-port, vulners-per-CPE). Tier 1b reshapes the manifest to a per-command `work[]` array, adds `G3Data._artifacts` for plugins to claim their files, makes the slot's actual file enumeration authoritative for `files`, and treats claimed-but-missing or malformed claims as loud task errors. Spec changes are in [Component 2 of the design doc](../specs/2026-05-14-shared-artifacts-volume-design.md#component-2-the-manifest).
>
> Already-written `manifest.json` files from Tier 1 will be deleted by the maintainer — no migration code.

### File structure

| File | Disposition | Responsibility |
|---|---|---|
| `src/g3lib/common.go` | Modify | Document `_artifacts ([]string)` in the G3Data underscore-field comment block; add it to the known-underscore-field allowlist in `IsValidData`. **No shape check here** — that's the worker's loud-error responsibility, not silent rejection. |
| `src/g3lib/manifest.go` | Rewrite | New struct shapes (`G3Manifest` now has root `files` + root `work[]`; new `G3ManifestWork`). New helpers: `ManifestTool`, `EnumerateSlot`, `ValidateArtifactClaims`, `BuildManifestWork`, `WriteManifest`. The Tier-1 `ManifestProvenance` and `WriteTaskManifest` are removed. |
| `src/g3worker/g3worker.go` | Modify | Rework the post-`RunPluginCommand` block: enumerate slot, validate artifact claims, build work, write manifest unconditionally, override task outcome to `ERROR` on validation failure. |

---

### Task 1b.1: g3lib — `_artifacts` in the underscore-field allowlist

**Files:**
- Modify: `src/g3lib/common.go` — the data-model comment block (≈ lines 130-148) and the known-underscore-field switch in `IsValidData` (≈ lines 180-198).

- [ ] **Step 1: Document `_artifacts` in the data-model comment block**

In `src/g3lib/common.go`, the optional-fields comment currently reads:

```go
// The following are optional:
//
//   _id        (int): Database ID of the object (if stored in a database).
//   _scanid (string): Scan ID (used to correlate logs).
//   _taskid (string): Task ID (used to correlate logs).
//   _cmd    (string): Command line that was executed to generate this object.
//   _start     (int): Unix timestamp of the moment the command started.
//   _end       (int): Unix timestamp of the moment the command ended.
//
```

Replace it with:

```go
// The following are optional:
//
//   _id          (int): Database ID of the object (if stored in a database).
//   _scanid   (string): Scan ID (used to correlate logs).
//   _taskid   (string): Task ID (used to correlate logs).
//   _cmd      (string): Command line that was executed to generate this object.
//   _start       (int): Unix timestamp of the moment the command started.
//   _end         (int): Unix timestamp of the moment the command ended.
//   _artifacts ([]string): Relative filenames (under /artifacts/) the producing
//                          command wrote. Used by the worker to build the per-
//                          task manifest. Absent / empty / partial is allowed.
//                          Claimed-but-missing files cause a loud task ERROR.
//
```

- [ ] **Step 2: Add `_artifacts` to the known-underscore-field allowlist**

In `src/g3lib/common.go`, the `IsValidData` known-underscore switch currently reads (≈ lines 184-194):

```go
			switch field {								// add more here

			case "_type":
			case "_tool":
			case "_fp":

			case "_id":
			case "_taskid":
			case "_scanid":
			case "_cmd":
			case "_start":
			case "_end":

			default:
```

Replace it with:

```go
			switch field {								// add more here

			case "_type":
			case "_tool":
			case "_fp":

			case "_id":
			case "_taskid":
			case "_scanid":
			case "_cmd":
			case "_start":
			case "_end":
			case "_artifacts":

			default:
```

No shape check is added here. `IsValidData`'s policy is log-and-drop for malformed objects; the new "claimed-but-missing or malformed `_artifacts`" rule is a *loud task ERROR*, which lives in the worker (Task 1b.3).

- [ ] **Step 3: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.`

---

### Task 1b.2: g3lib/manifest.go — rewrite for the new schema

**Files:**
- Rewrite: `src/g3lib/manifest.go` (full replacement).

This task replaces the Tier-1 contents of `manifest.go` wholesale. The old exported symbols `G3Manifest` (flat-cmd shape), `ManifestProvenance`, and `WriteTaskManifest` go away. `G3ManifestFile` is retained with the same shape.

After this task, `g3lib` builds in isolation but **g3worker will not build** until Task 1b.3 updates its call sites. That is expected.

- [ ] **Step 1: Replace the file contents**

Replace the entire contents of `/home/crapula/code/g3/src/g3lib/manifest.go` with exactly:

```go
package g3lib

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ManifestFilename is the name of the per-task manifest the worker writes into
// each task's artifact slot directory.
const ManifestFilename = "manifest.json"

// G3ManifestFile describes one file in the task's artifact slot.
type G3ManifestFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
}

// G3ManifestWork describes one sub-command run within the task: a command line
// (the plugin entrypoint may run multiple sub-commands internally — testssl-
// per-port, vulners-per-CPE, etc.) and the filenames the plugin claimed for that
// command via _artifacts. The filenames reference entries in G3Manifest.Files.
type G3ManifestWork struct {
	Cmd       string   `json:"cmd"`
	Artifacts []string `json:"artifacts"`
}

// G3Manifest is the per-task record written into
// <artifacts-root>/<scanid>/<taskid>/manifest.json. It is the integration
// contract downstream consumers (e.g. magenta) read to map artifact files back
// to the tool that produced them.
//
// Files lists every regular file in the slot (worker-enumerated, authoritative).
// Work groups output objects by _cmd: one entry per unique command, with the
// union of _artifacts claims as that entry's Artifacts. Files present in Files
// but absent from every Work.Artifacts are intentional orphans (debug, forensic
// retention).
type G3Manifest struct {
	ScanID     string           `json:"scan_id"`
	TaskID     string           `json:"task_id"`
	Plugin     string           `json:"plugin"`
	Tool       string           `json:"tool"`
	ExitStatus string           `json:"exit_status"`
	StartedAt  int64            `json:"started_at"`
	EndedAt    int64            `json:"ended_at"`
	Files      []G3ManifestFile `json:"files"`
	Work       []G3ManifestWork `json:"work"`
}

// ManifestTool derives the canonical tool name for the manifest's root `tool`
// field. It prefers the _tool the plugin stamped onto its first emitted G3Data
// (g3lib's runPluginInternal injects this for every object, including the dummy
// object it appends when the plugin emitted nothing) and falls back to the g3
// plugin name when the output array is unexpectedly empty.
func ManifestTool(outputArray []G3Data, plugin G3Plugin) string {
	if len(outputArray) > 0 {
		if t, ok := outputArray[0]["_tool"].(string); ok && t != "" {
			return t
		}
	}
	return plugin.Name
}

// EnumerateSlot lists every regular file in slotDir, returning a G3ManifestFile
// per entry. Subdirectories and the manifest file itself are excluded.
func EnumerateSlot(slotDir string) ([]G3ManifestFile, error) {
	entries, err := os.ReadDir(slotDir)
	if err != nil {
		return nil, err
	}
	files := []G3ManifestFile{}
	for _, entry := range entries {
		// TODO: subdirectories a plugin creates are not recursed into; only
		// top-level files in the slot are listed. Revisit if a plugin ever
		// needs a nested artifact layout.
		if entry.IsDir() || entry.Name() == ManifestFilename {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		files = append(files, G3ManifestFile{
			Name:     entry.Name(),
			Size:     info.Size(),
			Modified: info.ModTime().Unix(),
		})
	}
	return files, nil
}

// ValidateArtifactClaims walks outputArray and verifies that every present
// _artifacts field is shaped as a list of strings AND that every claimed
// filename appears in files. Returns nil if every claim is well-formed and
// present on disk; returns an error whose message is suitable for the
// manifest's exit_status field otherwise. The first failure short-circuits the
// scan — once a plugin has emitted one bad claim, the diagnostic value of
// piling on more is limited.
func ValidateArtifactClaims(outputArray []G3Data, files []G3ManifestFile) error {
	present := make(map[string]struct{}, len(files))
	for _, f := range files {
		present[f.Name] = struct{}{}
	}
	for i, data := range outputArray {
		raw, ok := data["_artifacts"]
		if !ok {
			continue
		}
		list, ok := raw.([]interface{})
		if !ok {
			return fmt.Errorf("malformed _artifacts on output[%d]: expected list of strings, got %T", i, raw)
		}
		for j, item := range list {
			name, ok := item.(string)
			if !ok {
				return fmt.Errorf("malformed _artifacts on output[%d][%d]: expected string, got %T", i, j, item)
			}
			if _, exists := present[name]; !exists {
				cmd, _ := data["_cmd"].(string)
				return fmt.Errorf("missing artifact %q (claimed by cmd %q on output[%d])", name, cmd, i)
			}
		}
	}
	return nil
}

// BuildManifestWork groups outputArray by _cmd and unions per-group _artifacts
// into a single G3ManifestWork entry per unique command. Output order follows
// first-occurrence of each unique _cmd in outputArray. Callers are expected to
// have already run ValidateArtifactClaims (or otherwise accepted that malformed
// _artifacts shapes will be silently ignored here — ValidateArtifactClaims is
// the loud guard).
func BuildManifestWork(outputArray []G3Data) []G3ManifestWork {
	work := []G3ManifestWork{}
	indexByCmd := map[string]int{}
	for _, data := range outputArray {
		cmd, _ := data["_cmd"].(string)
		idx, exists := indexByCmd[cmd]
		if !exists {
			idx = len(work)
			work = append(work, G3ManifestWork{Cmd: cmd, Artifacts: []string{}})
			indexByCmd[cmd] = idx
		}
		raw, hasArtifacts := data["_artifacts"]
		if !hasArtifacts {
			continue
		}
		list, ok := raw.([]interface{})
		if !ok {
			continue
		}
		for _, item := range list {
			name, ok := item.(string)
			if !ok {
				continue
			}
			if !containsString(work[idx].Artifacts, name) {
				work[idx].Artifacts = append(work[idx].Artifacts, name)
			}
		}
	}
	return work
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// WriteManifest marshals m as indented JSON and writes it to slotDir/manifest.json.
// The caller is responsible for populating every field (including Files and
// Work). This function does no enumeration or validation.
func WriteManifest(slotDir string, m G3Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(slotDir, ManifestFilename), data, 0o644)
}
```

- [ ] **Step 2: Verify build + lint (g3lib in isolation)**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.` Note that `g3worker` is NOT expected to build at this point — its call sites still reference the removed `ManifestProvenance` / `WriteTaskManifest`. Task 1b.3 fixes that.

---

### Task 1b.3: g3worker — new manifest write flow

**Files:**
- Modify: `src/g3worker/g3worker.go` — the task-handler closure (≈ lines 672-711 hold the Tier-1 manifest block to replace; the new flow extends to a new validation branch).

- [ ] **Step 1: Replace the Tier-1 manifest block with the new flow**

In `src/g3worker/g3worker.go`, the current task-handler closure has this block (≈ lines 672-711, exact line numbers may differ — match by content):

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

Replace it with:

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
		pluginEndTS := time.Now().Unix()

		// Build and write the per-task manifest. Always written so every task
		// that reached execution has a record. Validation only runs on the
		// success path: a canceled or errored plugin run may have left
		// claimed artifacts unwritten, which is expected, not a defect.
		manifestFiles, enumErr := g3lib.EnumerateSlot(slotDir)
		if enumErr != nil {
			log.Error("Cannot enumerate artifact slot " + slotDir + ": " + enumErr.Error())
			manifestFiles = []g3lib.G3ManifestFile{}
		}
		var validationErr error
		manifestStatus := "success"
		switch {
		case errors.Is(err, context.Canceled):
			manifestStatus = "canceled"
		case err != nil:
			manifestStatus = err.Error()
		default:
			validationErr = g3lib.ValidateArtifactClaims(outputArray, manifestFiles)
			if validationErr != nil {
				manifestStatus = validationErr.Error()
			}
		}
		manifestWriteErr := g3lib.WriteManifest(slotDir, g3lib.G3Manifest{
			ScanID:     task.ScanID,
			TaskID:     task.TaskID,
			Plugin:     plugin.Name,
			Tool:       g3lib.ManifestTool(outputArray, plugin),
			ExitStatus: manifestStatus,
			StartedAt:  pluginStartTS,
			EndedAt:    pluginEndTS,
			Files:      manifestFiles,
			Work:       g3lib.BuildManifestWork(outputArray),
		})
		if manifestWriteErr != nil {
			log.Error("Cannot write task manifest for " + task.TaskID + ": " + manifestWriteErr.Error())
		}
```

Key behaviours of the new block:
- `manifestFiles` is built from the actual slot enumeration; if enumeration fails the field is empty (and the manifest still gets written if it can).
- `validationErr` is captured but does not yet override the task outcome — that happens in Step 2.
- `manifestWriteErr` is captured for the same reason — its corresponding outcome branch is added in Step 2.
- `pluginEndTS` is captured once (immediately after `RunPluginCommand` returns) and reused for `ended_at` so the manifest and any future per-stage timing measure the same moment.
- The dropped `manifestCmd` from Tier 1 is correct — `cmd` now lives per-work, populated by `BuildManifestWork` reading `_cmd` off each G3Data.

- [ ] **Step 2: Add the validation-failure outcome branch**

In `src/g3worker/g3worker.go`, locate the existing error-handling branches that follow the manifest block. The relevant fragment is roughly (line numbers will have shifted slightly after Step 1):

```go
		// Per-task cancel from the scanner: RunPluginCommand propagates
		// the cancelled context as context.Canceled. Treat as CANCELED
		// (not ERROR — the task didn't fail, it was stopped on request).
		// Worker-level SIGTERM also cancels the context, so this branch
		// covers both per-task cancel and shutdown-while-running.
		if errors.Is(err, context.Canceled) {
			markTerminal(task.ScanID, task.TaskID, "CANCELED")
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			return
		}

		// Detect errors when executing the plugin.
		if err != nil {
			log.Error("Error executing plugin " + plugin.Name + ": " + err.Error())
			markTerminal(task.ScanID, task.TaskID, "ERROR")
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			return
		}
```

Insert this new branch IMMEDIATELY AFTER the `if err != nil { ... }` block (i.e. between that block's closing `}` and the next existing block):

```go

		// Artifact-claim validation failed (plugin reported a file it didn't
		// write, or returned a malformed _artifacts shape). The manifest has
		// already been written with the validation error in its exit_status;
		// upgrade the task outcome to ERROR. By design, this branch is loud —
		// surfaces plugin bugs as task failures rather than as silent data loss.
		if validationErr != nil {
			log.Error("Artifact validation failed for " + plugin.Name + ": " + validationErr.Error())
			markTerminal(task.ScanID, task.TaskID, "ERROR")
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			return
		}

		// The manifest write itself failed (rare — disk full, permissions on
		// slotDir, etc). Per the spec, this also marks the task ERROR: a task
		// without a successfully-written manifest is incomplete.
		if manifestWriteErr != nil {
			markTerminal(task.ScanID, task.TaskID, "ERROR")
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			return
		}
```

- [ ] **Step 3: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3worker && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.`

---

### Task 1b.4: Full cross-module build + lint, and stop

**Files:** none (verification only)

- [ ] **Step 1: Build and lint both affected modules**

Run:
```
cd /home/crapula/code/g3/src/g3lib && go build ./... && golangci-lint run ./...
cd /home/crapula/code/g3/src/g3worker && go build ./... && golangci-lint run ./...
```
Expected: both `go build` invocations exit 0; both `golangci-lint` runs print `0 issues.`

- [ ] **Step 2: STOP — end of Tier 1b**

Tier 1b is complete. Hand back to the maintainer to:
1. Delete any leftover `manifest.json` files from Tier 1's old-shape runs (`rm -rf volumes/artifacts/*`).
2. Update plugin importers (`g3i.py` / `g3p.py`) to claim their artifacts via `_artifacts`. The user is updating these per plugin; not part of this plan.
3. Smoke-test: re-run a scan and confirm the new manifest shape — `files[]` lists everything in the slot, `work[]` has one entry per unique `_cmd`, claimed artifacts appear under the right entry.
4. Commit Tier 1b in one batch.
5. Optionally proceed to Tier 2 (detailed below).

---

### File structure

| File | Disposition | Responsibility |
|---|---|---|
| `src/g3api/g3api.go` | Modify | Add `G3_UPLOAD_TTL` constant, the `sweepOrphanUploads` helper, startup resolution + writability check + sweep-goroutine launch in `Main()`, upload-handler relocation, import-loop relocation, `/scan/delete` artifact cleanup. Plus `path/filepath` and `time` imports. |
| `docker-compose.yml` | Modify | Mount `./volumes/artifacts` into the g3api service; set `G3_ARTIFACTS_ROOT`; reference `G3_UPLOAD_TTL` by name. |
| `.env` | Modify | Document `G3_UPLOAD_TTL=24h` as the demo default. |

---

### Task 7: g3api — `G3_UPLOAD_TTL` constant, startup setup, orphan-sweep goroutine

**Files:**
- Modify: `src/g3api/g3api.go` — imports, constant block (≈ line 32), helper insertion before `Main()` (≈ line 101), `Main()` body (≈ lines 117 and 169).

- [ ] **Step 1: Add the `path/filepath` and `time` stdlib imports**

In `src/g3api/g3api.go`, the import block currently reads (lines ≈ 3-24):

```go
import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/asaskevich/govalidator"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)
```

Add `path/filepath` and `time` to the stdlib group (alphabetical order), so it becomes:

```go
import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)
```

- [ ] **Step 2: Add the `G3_UPLOAD_TTL` constant**

The existing constant line at ≈ 32 reads:

```go
const G3_FILE_UPLOAD_MAX = "G3_FILE_UPLOAD_MAX" // Maximum file size for uploads.
```

Add immediately after it:

```go
const G3_UPLOAD_TTL = "G3_UPLOAD_TTL"           // time.ParseDuration string. 0 (default) disables the _uploads/ orphan sweep.
```

- [ ] **Step 3: Add the `sweepOrphanUploads` helper**

Find this line near the top of the file (just before `func Main() int {`):

```go
func Main() int {
```

Insert IMMEDIATELY BEFORE it:

```go
// sweepOrphanUploads removes files in uploadsDir whose mtime is older than ttl.
// Used to garbage-collect uploads that were POSTed but never referenced by a
// scan-creation request. Subdirectories are skipped; if uploadsDir does not
// exist (no upload has happened yet) the call is a silent no-op.
func sweepOrphanUploads(uploadsDir string, ttl time.Duration) {
	entries, err := os.ReadDir(uploadsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Error("Upload sweep: ReadDir failed: " + err.Error())
		}
		return
	}
	threshold := time.Now().Add(-ttl)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(threshold) {
			path := filepath.Join(uploadsDir, entry.Name())
			if err := os.Remove(path); err != nil {
				log.Error("Upload sweep: remove " + path + " failed: " + err.Error())
			} else {
				log.Debug("Upload sweep: removed " + path)
			}
		}
	}
}

```

- [ ] **Step 4: Resolve the artifacts root + fail-fast writability check in `Main()`**

Find this block inside `Main()` (≈ lines 113-117):

```go
	// Load the shared API bearer token.
	apiToken := os.Getenv(G3_API_TOKEN)
	if apiToken == "" {
		log.Critical("Missing environment variable: " + G3_API_TOKEN)
		return 1
	}
```

Insert IMMEDIATELY AFTER the closing `}` of that block:

```go

	// Resolve the shared artifacts root and verify it is writable. g3api writes
	// uploaded files into <root>/_uploads/, relocates them into <root>/<scanid>/imports/
	// when a scan is created, and removes <root>/<scanid>/ on scan delete. A
	// missing/unwritable root is infrastructure misconfiguration — fail fast.
	artifactsRoot := os.Getenv(g3lib.G3_ARTIFACTS_ROOT)
	if artifactsRoot == "" {
		artifactsRoot = g3lib.G3_ARTIFACTS_ROOT_DEFAULT
	}
	if err := os.MkdirAll(artifactsRoot, 0o755); err != nil {
		log.Critical("Cannot create artifacts root " + artifactsRoot + ": " + err.Error())
		return 1
	}
	probeFile := filepath.Join(artifactsRoot, ".g3-write-test")
	if err := os.WriteFile(probeFile, []byte{}, 0o644); err != nil {
		log.Critical("Artifacts root " + artifactsRoot + " is not writable: " + err.Error())
		return 1
	}
	os.Remove(probeFile) //nolint:errcheck
	log.Debug("Artifacts root: " + artifactsRoot)

	// Parse G3_UPLOAD_TTL: empty or "0" disables the orphan sweep; anything else
	// must parse as a non-negative time.Duration. Invalid → fail fast (no fake fallbacks).
	uploadTTL := time.Duration(0)
	if s := os.Getenv(G3_UPLOAD_TTL); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			log.Critical("Invalid " + G3_UPLOAD_TTL + " (" + s + "): " + err.Error())
			return 1
		}
		if d < 0 {
			log.Critical(G3_UPLOAD_TTL + " cannot be negative: " + s)
			return 1
		}
		uploadTTL = d
	}
```

The variable `artifactsRoot` is captured by the web-handler closures registered later in this function and is consumed by Tasks 8, 9, 10. The variable `uploadTTL` is consumed by Step 5 below.

- [ ] **Step 5: Launch the orphan-sweep goroutine after the signal handler**

Find this block in `Main()` (≈ lines 156-169 — the signal-handler goroutine):

```go
	wg.Add(1)
	go func() {
		select {
		case <-signalChan: // first signal, cancel context
			log.Critical("\nSIGTERM received!")
			cancel()
			srv.Shutdown(context.Background())
			wg.Done()
		case <-ctx.Done():
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()
```

Insert IMMEDIATELY AFTER the closing `}()` of that goroutine:

```go

	// Launch the _uploads/ orphan-sweep goroutine when enabled (G3_UPLOAD_TTL > 0).
	// Sweeps once on startup, then every TTL/2 (with a 1m floor so very short TTLs
	// don't busy-loop). The goroutine exits cleanly when ctx is cancelled.
	if uploadTTL > 0 {
		uploadsDir := filepath.Join(artifactsRoot, "_uploads")
		sweepInterval := uploadTTL / 2
		if sweepInterval < time.Minute {
			sweepInterval = time.Minute
		}
		log.Debug("Upload orphan sweep enabled: TTL=" + uploadTTL.String() + ", interval=" + sweepInterval.String())
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(sweepInterval)
			defer ticker.Stop()
			sweepOrphanUploads(uploadsDir, uploadTTL)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					sweepOrphanUploads(uploadsDir, uploadTTL)
				}
			}
		}()
	}
```

- [ ] **Step 6: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.`

> **Note for the executor:** `artifactsRoot` is used multiple times within Step 4 itself (`os.MkdirAll`, the probe path, the log line), so the Go compiler will not flag it as unused even before Tasks 8/9/10 add their consumers. The `uploadTTL` variable is read by Step 5. Build should pass independently after this task.

---

### Task 8: g3api — upload handler relocates uploads into `_uploads/`

**Files:**
- Modify: `src/g3api/g3api.go:927-929` (inside the upload handler — search for `filename := uuid.NewString()` near the multipart upload code; lines shifted after the Tier-1b-era `notifyTracker` split + `scanremoved` WS handler)

- [ ] **Step 1: Change the upload destination paths**

Find these three consecutive lines inside the upload handler:

```go
			filename := uuid.NewString()
			binPath := "/tmp/" + filename + ".bin"
			txtPath := "/tmp/" + filename + ".txt"
```

Replace them with:

```go
			filename := uuid.NewString()
			uploadsDir := filepath.Join(artifactsRoot, "_uploads")
			if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
				log.Error("Cannot create uploads dir " + uploadsDir + ": " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			binPath := filepath.Join(uploadsDir, filename+".bin")
			txtPath := filepath.Join(uploadsDir, filename+".txt")
```

Everything else in the handler (the existing `os.OpenFile(binPath, ...)`, the `io.Copy`, the `os.WriteFile(txtPath, ...)`, the `os.Remove(binPath)` cleanup paths, the response writing the bare `filename`) stays exactly as-is — the only change is where the files land.

- [ ] **Step 2: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.`

---

### Task 9: g3api — import loop relocates uploads into `<scanid>/imports/`

**Files:**
- Modify: `src/g3api/g3api.go:358-365` (inside the `/scan/start` handler's import loop — search for `inputfile := fmt.Sprintf("/tmp/%s.bin"`)

- [ ] **Step 1: Replace the `/tmp` open with an `os.Rename` into the scan tree**

Find this block inside the import loop:

```go
				inputfile := fmt.Sprintf("/tmp/%s.bin", parsedImport.Path)
				stdin, err := os.Open(inputfile)
				if err != nil {
					log.Critical("Cannot open file " + inputfile + ": " + err.Error())
					g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script, imported file not found.")
					return
				}
				defer stdin.Close()
```

Replace it with:

```go
				importsDir := filepath.Join(artifactsRoot, request.ScanID, "imports")
				if err := os.MkdirAll(importsDir, 0o755); err != nil {
					log.Error("Cannot create imports dir " + importsDir + ": " + err.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
					return
				}
				srcBin := filepath.Join(artifactsRoot, "_uploads", parsedImport.Path+".bin")
				srcTxt := filepath.Join(artifactsRoot, "_uploads", parsedImport.Path+".txt")
				inputfile := filepath.Join(importsDir, parsedImport.Path+".bin")
				dstTxt := filepath.Join(importsDir, parsedImport.Path+".txt")
				if err := os.Rename(srcBin, inputfile); err != nil {
					log.Error("Cannot relocate upload " + parsedImport.Path + ": " + err.Error())
					g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script, imported file not found.")
					return
				}
				if err := os.Rename(srcTxt, dstTxt); err != nil {
					log.Error("Cannot relocate upload metadata " + parsedImport.Path + ": " + err.Error())
				}
				stdin, err := os.Open(inputfile)
				if err != nil {
					log.Critical("Cannot open file " + inputfile + ": " + err.Error())
					g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script, imported file not found.")
					return
				}
				defer stdin.Close()
```

Behavior notes (do not write into the code as comments):
- The `.bin` move is the hard failure path: if it fails (uuid not in `_uploads/`, permissions, etc.), return the same 400 the user already sees today.
- The `.txt` move is best-effort: the importer doesn't read it; failing the request because of a metadata-pair desync would be worse than logging and continuing.
- Once relocated, the imported file lives in `<scanid>/imports/<uuid>.bin` and dies with the scan via Task 10.

- [ ] **Step 2: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.`

---

### Task 10: g3api — `/scan/delete` removes the scan's artifact tree

**Files:**
- Modify: `src/g3api/g3api.go` — inside the `/scan/delete` handler (≈ line 639), insert a new best-effort step after the last existing step in the chain.

- [ ] **Step 1: Add `os.RemoveAll` to the delete chain**

Find this block in the `/scan/delete` handler (≈ lines 684-691 — it's the last step before the `if reterr != ""` check):

```go
			err = g3lib.DeleteScanProgress(sql_db, scanid)
			if err != nil {
				log.Critical("Error clearing scan progress: " + err.Error())
				reterr = reterr + "Error clearing scan progress: " + err.Error() + "\n"
			} else {
				log.Debug("Cleared scan progress.")
			}
```

Insert IMMEDIATELY AFTER its closing `}`:

```go
			err = os.RemoveAll(filepath.Join(artifactsRoot, scanid))
			if err != nil {
				log.Critical("Error removing scan artifacts: " + err.Error())
				reterr = reterr + "Error removing scan artifacts: " + err.Error() + "\n"
			} else {
				log.Debug("Removed scan artifacts.")
			}
```

This mirrors the existing best-effort-and-continue pattern verbatim — log Critical on failure, accumulate into `reterr`, never abort the rest of the chain.

> **Note on the `removeNotify` interaction.** The `/scan/delete` success branch (the `} else {` arm of `if reterr != ""`, ≈ line 702) fires `removeNotify.SendNotification(g3lib.G3ScanRemoved{ScanID: scanid})` to push a `scanremoved` event to WS subscribers. Because the new `os.RemoveAll` step contributes to `reterr` on failure, the WS notification only fires on **full** success (every step in the chain, including artifact removal, completed cleanly). A partial failure correctly suppresses the `scanremoved` event so subscribed clients don't see a "scan removed" signal while server-side state is still partially present.

- [ ] **Step 2: Verify build + lint**

Run: `cd /home/crapula/code/g3/src/g3api && go build ./... && golangci-lint run ./...`
Expected: build exits 0; lint prints `0 issues.`

---

### Task 11: docker-compose + `.env` wiring for g3api

**Files:**
- Modify: `docker-compose.yml` (the single g3api service)
- Modify: `.env`

- [ ] **Step 1: Mount the artifacts volume on g3api**

Find the g3api service's `volumes:` block in `docker-compose.yml` (it currently mounts `./config:/app/config`, `./volumes/tmp:/tmp`, and the Docker socket — the search anchor is `- ./volumes/tmp:/tmp`).

Add the artifacts mount line so the block reads (preserve any existing entries, just add the one new line — place it AFTER `./volumes/tmp:/tmp`):

```yaml
      - ./volumes/tmp:/tmp
      - ./volumes/artifacts:/app/artifacts
```

The legacy `./volumes/tmp:/tmp` mount stays for now per the spec's "out of scope" note — it can be removed in a later cleanup once nothing on the g3api side writes to `/tmp`.

- [ ] **Step 2: Set the artifacts env var and reference `G3_UPLOAD_TTL` on g3api**

In the same g3api service, find the `environment:` block (it contains entries like `- G3HOME=/app`, `- G3_FILE_UPLOAD_MAX`, etc.).

Add ONE explicit value line for the artifacts root and ONE pulled-by-name line for the upload TTL. Place them near the other `G3_*` vars (e.g. after `- G3_FILE_UPLOAD_MAX`):

```yaml
      - G3_ARTIFACTS_ROOT=/app/artifacts
      - G3_UPLOAD_TTL
```

Notes:
- g3api does **not** need `G3_ARTIFACTS_HOST_ROOT` — it never shells out to `docker run`. Only the worker passes paths to the host daemon.
- `G3_UPLOAD_TTL` is pulled from `.env` by name (matching the existing `G3_FILE_UPLOAD_MAX` pattern).

- [ ] **Step 3: Document `G3_UPLOAD_TTL=24h` in `.env`**

In `.env`, find the existing g3api configuration section:

```
# Golismero g3api configuration.
G3_API_ID=g3api-debug
G3_API_TOKEN=changeme
G3_WS_ADDR=127.0.0.1
G3_WS_PORT=8080
G3_WS_PATH=/g3api
G3_WS_BUFFER=65536
G3_FILE_UPLOAD_MAX=33554432
```

Add ONE line immediately after `G3_FILE_UPLOAD_MAX=33554432`:

```
G3_UPLOAD_TTL=24h
```

24h is the recommended demo default per the spec; `G3_UPLOAD_TTL=0` (or omitting it entirely) disables the sweep.

- [ ] **Step 4: Verify**

This task changes only YAML/env config — there is no build step. Verify by review:
- g3api has both the `./volumes/artifacts:/app/artifacts` volume line and both `G3_ARTIFACTS_ROOT=/app/artifacts` + `- G3_UPLOAD_TTL` env lines.
- `.env` has `G3_UPLOAD_TTL=24h` in the g3api section.
- `git diff docker-compose.yml .env` shows only the intended additions.

Running the compose stack is the maintainer's step.

---

### Task 12: Full cross-module build + lint

**Files:** none (verification only)

- [ ] **Step 1: Build and lint every affected module**

Run:
```
cd /home/crapula/code/g3/src/g3lib && go build ./... && golangci-lint run ./...
cd /home/crapula/code/g3/src/g3worker && go build ./... && golangci-lint run ./...
cd /home/crapula/code/g3/src/g3api && go build ./... && golangci-lint run ./...
```
Expected: all three `go build` invocations exit 0; all three `golangci-lint` runs print `0 issues.`

- [ ] **Step 2: STOP — end of Tier 2**

Tier 2 is complete. Hand back to the maintainer to:
1. Commit Tier 2 in one batch.
2. Smoke-test:
   - `POST /upload` lands files in `<root>/_uploads/<uuid>.{bin,txt}` (not `/tmp/`).
   - `POST /scan` that imports an upload moves the pair into `<root>/<scanid>/imports/<uuid>.{bin,txt}` and `_uploads/` no longer contains them.
   - `DELETE /scan/<id>` removes `<root>/<scanid>/` entirely.
   - With `G3_UPLOAD_TTL=24h` an old file in `_uploads/` is swept after the threshold; with `G3_UPLOAD_TTL=0` it is left alone.

---

## Self-review

### Tier 1 (✅ shipped)

> **Note: post-Tier-1b name changes.** Helper/field names below reflect the original Tier 1 plan. Tier 1b later renamed and reshaped several of them. Current shipped names: `ManifestProvenance` → `ManifestTool` (signature also changed — now returns just `tool`); `WriteTaskManifest` → `WriteManifest` (file enumeration moved out into `EnumerateSlot`, called separately by the worker); `G3Manifest.Cmd` → removed (replaced by per-command groupings in `G3Manifest.Work[]G3ManifestWork`); new helpers `ValidateArtifactClaims` and `BuildManifestWork`; `RunPluginCommand` now takes an explicit `artifactsHostDir string` parameter rather than the original "mutate `parsed.DockerOpt`" approach. The historical references below remain accurate for the Tier 1 plan as written.

**1. Spec coverage:**
- Component 1 "worker's per-task slot" — Tasks 3 (root resolution + writability) & 4 (slot mkdir + `/artifacts` bind-mount). ✅
- Component 1 "host-path parity" — `G3_ARTIFACTS_ROOT` / `G3_ARTIFACTS_HOST_ROOT` constants (Task 1), worker resolution (Task 3), compose wiring with `${PWD}` (Task 5). ✅
- Component 1 failure handling — fail-fast startup check (Task 3), `MkdirAll`-failure → `ERROR` (Task 4). ✅
- Component 2 "the manifest" — `manifest.go` model + writer (Task 2), worker invocation lifting `tool`/`cmd` from the output array (Task 4). ✅
- Component 2 "always written, even with no files" — `WriteTaskManifest` initializes `Files` to `[]` and writes regardless (Task 2); worker calls it unconditionally after the run (Task 4). ✅
- Component 2 "`_cmd` guaranteed a string" — relies on the already-landed `runPluginInternal` normalization; `ManifestProvenance` reads it with a safe type assertion + fallback (Task 2). ✅
- Config & deployment (worker portion) — Task 5.

**2. Placeholder scan:** No "TBD"/"TODO" as plan content. The one `// TODO` inside `WriteTaskManifest` is an intentional in-code marker for a known, accepted limitation (no subdir recursion), per repo convention — not a plan placeholder.

**3. Type consistency:** `G3Manifest`, `G3ManifestFile`, `ManifestFilename`, `ManifestProvenance(outputArray []G3Data, plugin G3Plugin, parsed ParsedPluginCommand) (string, string)`, and `WriteTaskManifest(slotDir string, m G3Manifest) error` are defined in Task 2 and used with exactly those names/signatures in Task 4. `G3_ARTIFACTS_ROOT` / `G3_ARTIFACTS_HOST_ROOT` / `G3_ARTIFACTS_ROOT_DEFAULT` defined in Task 1, used in Task 3. `artifactsRoot` / `artifactsHostRoot` declared in Task 3, consumed in Task 4. Consistent.

### Tier 2

**1. Spec coverage:**
- Component 3 "upload relocation — `POST /upload`" — Task 8 (`_uploads/<uuid>.{bin,txt}` instead of `/tmp/`; return value unchanged). ✅
- Component 3 "upload relocation — import-time `os.Rename`" — Task 9 (move pair into `<scanid>/imports/`, preserving the existing 400 message on failure of the `.bin` move; `.txt` move is best-effort). ✅
- Component 3 "orphan sweep" — Task 7 Steps 3+5 (helper + ticker, gated on `G3_UPLOAD_TTL > 0`; default `0` disables). ✅
- Component 4 "lifecycle / scan-delete cleanup" — Task 10 (`os.RemoveAll(<root>/<scanid>)` added to the existing best-effort chain, contributing to `reterr` on failure exactly like the surrounding steps). ✅
- Config & deployment (g3api portion) — Task 11 (mount volume, `G3_ARTIFACTS_ROOT=/app/artifacts`, `G3_UPLOAD_TTL` referenced by name, `G3_UPLOAD_TTL=24h` shipped in `.env`). ✅
- Error handling — Task 7 Step 4 fails fast on missing/unwritable root and on invalid/negative `G3_UPLOAD_TTL`; Task 9 preserves the user-facing 400 on import-time rename failure; Task 10 follows the log-and-continue convention. ✅
- Non-goals respected — no HTTP read endpoint added; no `g3p.sh` changes; legacy `./volumes/tmp` mount on g3api intentionally left in place (out of scope).

**2. Placeholder scan:** No "TBD"/"TODO" as plan content. No placeholder comments in the code blocks. All code steps contain complete code with full anchors.

**3. Type consistency across Tier 2 tasks:** `G3_UPLOAD_TTL` defined in Task 7 Step 2 and referenced in Task 7 Step 4 and in Task 11. `sweepOrphanUploads(uploadsDir string, ttl time.Duration)` defined in Task 7 Step 3 and called in Task 7 Step 5. `artifactsRoot` declared in Task 7 Step 4 and captured by the closures in Tasks 8, 9, 10. `uploadTTL` declared in Task 7 Step 4, consumed in Task 7 Step 5. `request.ScanID` and `scanid` (local vars in their respective handlers) match the existing closure scope at the insertion points. Consistent.

**4. Inter-tier consistency:** Tier 2 reuses Tier 1's `g3lib.G3_ARTIFACTS_ROOT` / `g3lib.G3_ARTIFACTS_ROOT_DEFAULT` constants (Task 1 deliverables). Tier 2 does NOT touch `G3_ARTIFACTS_HOST_ROOT` because g3api does not shell out to the host daemon. Compose g3api wiring (Task 11) deliberately omits `G3_ARTIFACTS_HOST_ROOT` for the same reason.
