# Reporter Plugins — Tier 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth plugin phase — `reporter` — that lets Dockerized tools (starting with magenta) consume a finished scan's full output and emit a downloadable report, dispatched through the worker MQTT pipeline and exposed via a new synchronous `POST /scan/reporter` endpoint.

**Architecture:** A new MQTT topic family `report/<tool>` mirrors the existing `tool/<tool>` family. The worker streams scan data to the reporter container as JSONL on stdin (G3Report header → deduped issue G3Data → everything else), bind-mounts `<scanid>/` as `/input:ro` and `<scanid>/<reportertaskid>/` as `/output:rw`, and writes a per-task manifest like any tool task. g3api blocks on the task reaching terminal state via Redis polling, then streams the slot's contents (single file or zip) back to the caller.

**Tech Stack:** Go 1.25, mqtt.paho.golang, mongo-driver v1, go-redis, gorilla mux already wired in g3api, archive/zip from the standard library, kong-validated request bodies.

**Spec:** [docs/superpowers/specs/2026-05-16-reporter-plugins-design.md](../specs/2026-05-16-reporter-plugins-design.md)

**Tier scope:** This plan ships **Tier 1 only**. Tier 2 (async API + generic `/scan/task/artifacts`), Tier 3 (local CLI integration), and Tier 4 (polish) are outlined in the spec and intentionally not implemented here.

---

## Notes for executors

These conventions override the default writing-plans skill template because of project-specific user preferences captured in agent memory:

- **Tests are user-owned.** Do not write tests, do not run tests, do not run binaries against live infrastructure. Verification per task is `go build ./...` in the affected module — nothing more.
- **Git is user-owned.** Do not run mutating git commands (`add`, `commit`, `mv`, `rm`, `push`, etc). Read-only inspection (`git status`, `git log`, `git diff`) is fine. The user will commit at the end of the tier in one batch.
- **No per-task STOP.** Run through the plan end-to-end without checkpoint pauses. The user reviews at the end.
- **Each binary is its own Go module.** Verify build by `cd src/<binary> && go build ./...` for the affected binary. After all g3lib changes are in place, every binary must build, so the final task does a cross-binary sweep.

---

## File structure

| File | Responsibility | Modified or Created |
| --- | --- | --- |
| `src/g3lib/plugin.go` | Reporter schema types + builder + container runner | Modify |
| `src/g3lib/task.go` | MQTT message types + topic constants + sub/pub helpers for reporter dispatch | Modify |
| `src/g3lib/kvstore.go` | Single-task state lookup helper for the g3api sync wait | Modify |
| `src/g3lib/datastore.go` | `ReporterStdinStream` — pipe-backed JSONL streamer over MongoDB cursor | Modify |
| `src/g3lib/manifest.go` | `BundleTaskSlot` — slot-to-writer bundler (single file or zip) | Modify |
| `src/g3config/g3config.go` | Validation pass for the reporter phase | Modify |
| `src/g3worker/g3worker.go` | New report-topic subscription + report-task handler that streams stdin and writes the per-task manifest | Modify |
| `src/g3api/g3api.go` | New `POST /scan/reporter` endpoint that publishes the task, polls Redis, and streams the bundle response | Modify |
| `plugins/report/magenta/magenta.g3p` | Verify `reporter: {}` declaration is registry-compatible — likely no edit | Read-only verify |

---

## Task 1: Plugin schema types

**Files:**
- Modify: `src/g3lib/plugin.go` (insert after `G3MergerCommand` struct definition, extend `G3Plugin`)

- [ ] **Step 1: Read the existing plugin type declarations**

Open `src/g3lib/plugin.go` and read lines 34-62 to understand the existing struct shape. `G3MergerCommand` is at lines 49-52; `G3Plugin` is at lines 54-62.

- [ ] **Step 2: Insert reporter schema types after `G3MergerCommand`**

Insert these two struct definitions immediately after the closing brace of `G3MergerCommand` (i.e. immediately before the existing `type G3Plugin struct` block):

```go
type G3ReporterCommand struct {
	Name      string   `json:"name"               validate:"required"`         // Preset name; uniqueness validated in g3config.
	Command   []string `json:"command,omitempty"`                              // (Optional) Command template, env-var expansion only.
	DockerOpt []string `json:"dockeropt,omitempty"`                            // (Optional) Docker options, env-var expansion only.
}

type G3ReporterPhase struct {
	Default  string              `json:"default,omitempty"`                            // (Optional) Name of the default preset; must reference an existing command.
	Commands []G3ReporterCommand `json:"commands,omitempty" validate:"omitempty,dive"` // (Optional) Named presets. Empty means "entrypoint runs with no args".
}
```

- [ ] **Step 3: Extend the `G3Plugin` struct with the `Reporter` field**

Edit the `G3Plugin` struct definition to add a `Reporter` field as the last entry. The resulting struct must look like:

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
}
```

- [ ] **Step 4: Verify the module still builds**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

---

## Task 2: `BuildReporterCommand`

**Files:**
- Modify: `src/g3lib/plugin.go` (add new function after `BuildMergerCommand`)

- [ ] **Step 1: Locate the insertion point**

`BuildMergerCommand` ends around line 275 in the current file. The new function goes immediately after it (before `BuildPluginFingerprint`).

- [ ] **Step 2: Add `BuildReporterCommand`**

Append this function:

```go
// Build the command line and Docker options for a reporter run. presetName is
// the caller-supplied preset; resolution order is:
//   1. presetName, if non-empty (must match a declared command name)
//   2. plugin.Reporter.Default, if non-empty
//   3. first command in plugin.Reporter.Commands
//   4. no command at all (the container entrypoint runs with no args)
// The default DockerOpt overrides the image entrypoint to /usr/bin/g3r,
// mirroring how importer/merger override to /usr/bin/g3i and /usr/bin/g3m.
func BuildReporterCommand(plugin G3Plugin, presetName string) (ParsedPluginCommand, []error) {
	var parsed ParsedPluginCommand
	var errorArray []error

	// Trivial case: plugin did not declare a reporter phase.
	if plugin.Reporter == nil {
		errorArray = append(errorArray, fmt.Errorf("plugin %s does not implement a reporter", plugin.Name))
		return parsed, errorArray
	}

	// Resolve which command (if any) the caller wants.
	var resolved *G3ReporterCommand
	if len(plugin.Reporter.Commands) > 0 {
		chosen := presetName
		if chosen == "" {
			chosen = plugin.Reporter.Default
		}
		if chosen == "" {
			resolved = &plugin.Reporter.Commands[0]
		} else {
			for i := range plugin.Reporter.Commands {
				if plugin.Reporter.Commands[i].Name == chosen {
					resolved = &plugin.Reporter.Commands[i]
					break
				}
			}
			if resolved == nil {
				errorArray = append(errorArray, fmt.Errorf("plugin %s has no reporter preset named %q", plugin.Name, chosen))
				return parsed, errorArray
			}
		}
	} else if presetName != "" {
		errorArray = append(errorArray, fmt.Errorf("plugin %s declares no reporter presets, but preset %q was requested", plugin.Name, presetName))
		return parsed, errorArray
	}

	// Build command and dockeropt arrays. Templates are expanded against the
	// environment only — reporters never see G3Data templates.
	environment := GetEnvironmentMap()
	command := []string{}
	dockerOpt := []string{"-i", "--rm", "--entrypoint", "/usr/bin/g3r"}
	if resolved != nil {
		var tmpErrA []error
		if len(resolved.Command) > 0 {
			command, tmpErrA = ExpandTemplateArray(resolved.Command, environment)
			errorArray = append(errorArray, tmpErrA...)
		}
		if len(resolved.DockerOpt) > 0 {
			dockerOpt, tmpErrA = ExpandTemplateArray(resolved.DockerOpt, environment)
			errorArray = append(errorArray, tmpErrA...)
		}
	}

	parsed.Command = command
	parsed.DockerOpt = dockerOpt
	return parsed, errorArray
}
```

- [ ] **Step 3: Verify the module still builds**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

---

## Task 3: `RunPluginReporter`

**Files:**
- Modify: `src/g3lib/plugin.go` (add new function after `RunPluginMerger`, before `runPluginInternal`)

- [ ] **Step 1: Locate the insertion point**

`RunPluginMerger` ends around line 341 in the current file. Insert the new function immediately after it, before `runPluginInternal` begins. Confirm imports: the new function uses `bytes`, `context`, `io`, `os`, `os/exec`, `time` — all already imported by `plugin.go`.

- [ ] **Step 2: Add `RunPluginReporter`**

```go
// Run a reporter plugin container. Differs from RunPluginCommand in three ways:
//   - binds two host directories (hostInDir → /input:ro, hostOutDir → /output:rw)
//     instead of a single /artifacts mount;
//   - pipes the caller-supplied stdin reader straight to the container (the
//     caller is responsible for closing the reader; see ReporterStdinStream);
//   - does NOT parse stdout as G3Data — reporters write files to /output, so
//     stdout/stderr are both routed to the task log writer.
//
// Returns nil on container exit 0, ctx.Err() on cancellation, or the underlying
// exec error otherwise.
func RunPluginReporter(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, hostInDir, hostOutDir string, stdin io.Reader, stderr io.Writer) error {
	network := os.Getenv(G3_DOCKER_NETWORK)

	tempfile, err := os.CreateTemp(os.TempDir(), "g3-")
	if err != nil {
		return err
	}
	os.Remove(tempfile.Name()) //nolint:errcheck
	defer os.Remove(tempfile.Name()) //nolint:errcheck

	commandLine := []string{"docker", "run", "-q", "--cidfile", tempfile.Name(), "-v", "./resources:/resources:ro"}
	if hostInDir != "" {
		commandLine = append(commandLine, "-v", hostInDir+":/input:ro")
	}
	if hostOutDir != "" {
		commandLine = append(commandLine, "-v", hostOutDir+":/output:rw")
	}
	if network != "" {
		commandLine = append(commandLine, "--network", network)
	}
	commandLine = append(commandLine, parsed.DockerOpt...)
	commandLine = append(commandLine, plugin.Image)
	commandLine = append(commandLine, parsed.Command...)

	process := exec.Command(commandLine[0], commandLine[1:]...)
	if stdin != nil {
		process.Stdin = stdin
	}
	if stderr != nil {
		process.Stdout = stderr
		process.Stderr = stderr
	} else {
		process.Stdout = io.Discard
		process.Stderr = io.Discard
	}

	c := make(chan error)
	if err := process.Start(); err != nil {
		return err
	}
	go func() { c <- process.Wait() }()

	select {
	case <-ctx.Done():
		log.Info("Cancellation requested, stopping reporter container...")
		if b, e := os.ReadFile(tempfile.Name()); e != nil {
			log.Error(e.Error())
		} else {
			log.Debug("Container ID: " + string(b))
			stop := exec.Command("docker", "stop", string(b))
			stop.Dir = GetHomeDirectory()
			if e := stop.Run(); e != nil {
				log.Error(e.Error())
			}
		}
		log.Info("Reporter container stopped.")
		return ctx.Err()
	case e := <-c:
		return e
	}
}
```

All imports referenced (`context`, `io`, `os`, `os/exec`) are already in `plugin.go`. No new imports required.

- [ ] **Step 3: Verify the module still builds**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

---

## Task 4: Reporter validation in `g3config`

**Files:**
- Modify: `src/g3config/g3config.go` (add a new validation block after the existing `for cmdidx, cmd := range metadata.Commands` loop)

- [ ] **Step 1: Locate the insertion point**

Open `src/g3config/g3config.go`. Find the existing for-loop that validates each `metadata.Commands` entry — it begins at `for cmdidx, cmd := range metadata.Commands {` (around line 282) and ends with its closing brace around line 302. Immediately after that closing brace, before the comment line `// If the name is missing, add it based on the filename.`, insert the reporter validation block.

The existing `re` regex (line 189, `^[a-zA-Z0-9_\-]*$`) is in scope — reuse it.

- [ ] **Step 2: Insert the reporter validation block**

```go
// Validate the reporter phase if present.
if metadata.Reporter != nil {
	seen := map[string]struct{}{}
	for cmdidx, cmd := range metadata.Reporter.Commands {
		if !re.MatchString(cmd.Name) {
			return fmt.Errorf("ERROR! Invalid reporter command name at index %d: %s", cmdidx, cmd.Name)
		}
		if _, dup := seen[cmd.Name]; dup {
			return fmt.Errorf("ERROR! Duplicated reporter command name: %s", cmd.Name)
		}
		seen[cmd.Name] = struct{}{}
	}
	if metadata.Reporter.Default != "" {
		if _, ok := seen[metadata.Reporter.Default]; !ok {
			return fmt.Errorf("ERROR! Reporter default %q does not match any command name", metadata.Reporter.Default)
		}
	}
}
```

The empty string is a valid `Name` value at the JSON level (`required` on the validator tag catches missing field, not empty string after JSONnet expansion — but `re.MatchString` with `^[a-zA-Z0-9_\-]*$` accepts the empty string too). If empty-name presets are a concern, change `*` to `+` in g3lib's intent later; for Tier 1 the user-facing constraint is the validator tag on the type.

- [ ] **Step 3: Verify the module still builds**

Run: `cd src/g3config && go build ./...`
Expected: no output, exit code 0.

---

## Task 5: MQTT message type, topics, sub/pub helpers

**Files:**
- Modify: `src/g3lib/task.go` (add topic constants, message constant, struct, handler type, subscriber, publisher)

- [ ] **Step 1: Add topic constants**

In the constants block near the top of `task.go` (around lines 35-42), append two new constants immediately after `G3RESPONSETOPIC`:

```go
const G3REPORTSUBTOPIC      = "$share/g3worker/report/"
const G3REPORTPUBTOPIC      = "report/"
```

- [ ] **Step 2: Add the message-type constant**

In the `G3MESSAGETYPE` const block (lines 45-52), add `MSG_REPORT`:

```go
const (
	MSG_TASK     G3MESSAGETYPE = "task"
	MSG_SCAN     G3MESSAGETYPE = "scan"
	MSG_STATUS   G3MESSAGETYPE = "status"
	MSG_CANCEL   G3MESSAGETYPE = "cancel"
	MSG_STOP     G3MESSAGETYPE = "stop"
	MSG_RESPONSE G3MESSAGETYPE = "response"
	MSG_REPORT   G3MESSAGETYPE = "report"
)
```

Also update the `VALID_MSG` array on the next line to include `MSG_REPORT`:

```go
var VALID_MSG = [...]G3MESSAGETYPE{MSG_TASK, MSG_SCAN, MSG_STATUS, MSG_CANCEL, MSG_RESPONSE, MSG_REPORT}
```

- [ ] **Step 3: Add the `G3ReportTask` struct and handler type**

Insert immediately after the existing `G3Task` struct (around line 84):

```go
type G3ReportTask struct {       // MessageType: MSG_REPORT
	G3TaskMessage
	Tool   string `json:"tool"   validate:"required"`
	Preset string `json:"preset"`                       // resolved name; "" only when plugin has reporter:{} with no commands
}
```

In the handler-type block (around line 130-135), append:

```go
type ReportTaskHandler func(MessageQueueClient, G3ReportTask)
```

- [ ] **Step 4: Add `SubscribeAsReporter`**

Add this function immediately after `SubscribeAsWorker` (which ends around line 480):

```go
// Subscribe to a series of reporter-topic shares — parallel to SubscribeAsWorker
// but routed through the report/<tool> topic family with G3ReportTask payloads.
func SubscribeAsReporter(client MessageQueueClient, tools []string, callback ReportTaskHandler) []string {

	// Build a map of topic strings and qos bytes.
	filters := map[string]byte{}
	for _, tool := range tools {
		log.Debug("Subscribing to: " + G3REPORTSUBTOPIC + tool)
		filters[G3REPORTSUBTOPIC + tool] = byte(MQTT_QOS)
	}

	// Subscribe to all of the topics.
	client.SubscribeMultiple(filters, func(client mqtt.Client, msg mqtt.Message) {

		// Decode the JSON payload.
		var task G3ReportTask
		err := json.Unmarshal(msg.Payload(), &task)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
			return
		}

		// Validate.
		err = validator.New().Struct(task)
		if err != nil || task.MessageType != MSG_REPORT {
			if err != nil {
				log.Error("Malformed report task received: " + err.Error())
			} else {
				log.Error("Malformed report task received: wrong MessageType")
			}
			return
		}

		// Call the report-task handler synchronously.
		// This prevents receiving more tasks while running this one.
		callback(client, task)
	})

	// Return the list of topics being subscribed to.
	topics := make([]string, 0, len(filters))
	for topic := range filters {
		topics = append(topics, topic)
	}
	return topics
}
```

- [ ] **Step 5: Add `SendReportTask`**

Add immediately after `SendTask` (around line 338):

```go
// Send a report task to the MQTT broker. Mirrors SendTask but uses the
// report/<tool> topic family and a G3ReportTask payload (no DataID/Index).
// The caller is responsible for generating the task ID and setting up
// out-of-band state (Redis, SQL logs) before publishing — same race
// concern as SendTask.
func SendReportTask(client MessageQueueClient, scanid, taskid, tool, preset string) error {
	msg := G3ReportTask{}
	msg.MessageType = MSG_REPORT
	msg.SenderID = GetClientID(client)
	msg.TaskID = taskid
	msg.ScanID = scanid
	msg.Tool = tool
	msg.Preset = preset
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	topic := G3REPORTPUBTOPIC + tool
	return SendMQPayload(client, topic, msg)
}
```

- [ ] **Step 6: Verify the module still builds**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

---

## Task 6: `GetTaskState` helper in `kvstore.go`

**Files:**
- Modify: `src/g3lib/kvstore.go` (add a single-task state lookup function)

- [ ] **Step 1: Locate the insertion point**

`GetTaskStates` (plural, returns all task states for a scan) is defined around line 190. Add the new single-task helper immediately after it. The function will use `taskHashKey` (line 128) and the package-level `redis.Client` accessor pattern visible in existing functions.

- [ ] **Step 2: Add `GetTaskState`**

```go
// Fetch the state field of a single task. Returns ("", nil) when the task
// hash has been cleaned up (scan terminal + state reaper ran). Returns the
// state string ("DISPATCHED", "RUNNING", "DONE", "ERROR", "CANCELED") otherwise.
// Used by the synchronous /scan/reporter wait loop to detect terminal state.
func GetTaskState(rdb KeyValueStoreClient, scanid, taskid string) (string, error) {
	ctx := context.Background()
	key := taskHashKey(scanid, taskid)
	exists, err := rdb.c.Exists(ctx, key).Result()
	if err != nil {
		return "", err
	}
	if exists == 0 {
		return "", nil
	}
	state, err := rdb.c.HGet(ctx, key, "state").Result()
	if err != nil {
		return "", err
	}
	return state, nil
}
```

- [ ] **Step 3: Verify the module still builds**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

---

## Task 7: `ReporterStdinStream` in `datastore.go`

**Files:**
- Modify: `src/g3lib/datastore.go` (add JSONL-streaming function + helper imports)

- [ ] **Step 1: Verify imports**

The new function uses `encoding/json` (already imported), `io` (NEW — add it), and the package-local `LoadDataWithCallback` / `LoadReportInfo` / `LoadData`. Add `"io"` to the import block.

- [ ] **Step 2: Add `ReporterStdinStream`**

Append at the end of `datastore.go`, after `DropScanData`:

```go
// ReporterStdinStream returns an io.ReadCloser that yields the scan's data
// as a JSON Lines stream, in the strict order documented by the reporter
// plugin contract:
//
//   Line 1:        the G3Report (deduped issue ID list)
//   Lines 2..K:    the issue G3Data objects, in G3Report.Issues order
//   Lines K+1..N:  every other G3Data object in the scan
//   EOF
//
// A goroutine writes to an io.Pipe; the worker passes the reader half to
// docker as the reporter container's stdin. If the reader closes early
// (e.g. magenta closes stdin because it doesn't consume the stream), the
// next Encode returns io.ErrClosedPipe and the goroutine exits — so the
// MongoDB cursor cost paid is exactly proportional to what the reporter
// actually consumed.
//
// The returned ReadCloser MUST be closed by the caller to release the pipe
// and unblock the goroutine in the case where the goroutine has already
// exited via an early return.
func ReporterStdinStream(mdb DatastoreClient, rdb KeyValueStoreClient, scanid string) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		// Closing the writer half delivers EOF to the reader (the container's stdin).
		// On panic, also close with the panic value as an error so the reader notices.
		var encodeErr error
		defer func() {
			if r := recover(); r != nil {
				pw.CloseWithError(fmt.Errorf("ReporterStdinStream panic: %v", r))
				return
			}
			if encodeErr != nil && encodeErr != io.ErrClosedPipe {
				pw.CloseWithError(encodeErr)
			} else {
				pw.Close()
			}
		}()

		enc := json.NewEncoder(pw)

		// Line 1: G3Report.
		report, err := LoadReportInfo(rdb, scanid)
		if err != nil {
			encodeErr = fmt.Errorf("ReporterStdinStream: load G3Report for %s: %w", scanid, err)
			return
		}
		if err := enc.Encode(report); err != nil {
			encodeErr = err
			return
		}

		// Lines 2..K: the deduped issue G3Data objects, in G3Report.Issues order.
		// LoadData batches by ID; the result preserves the input order.
		if len(report.Issues) > 0 {
			issues, err := LoadData(mdb, scanid, report.Issues)
			if err != nil {
				encodeErr = fmt.Errorf("ReporterStdinStream: load issues for %s: %w", scanid, err)
				return
			}
			for _, issue := range issues {
				if err := enc.Encode(issue); err != nil {
					encodeErr = err
					return
				}
			}
		}

		// Lines K+1..N: everything else.
		// Build a $nin filter from the deduped issue IDs.
		query := bson.M{}
		if len(report.Issues) > 0 {
			objectIds := make([]primitive.ObjectID, 0, len(report.Issues))
			for _, id := range report.Issues {
				objid, err := primitive.ObjectIDFromHex(id)
				if err != nil {
					continue // malformed ID — skip, don't poison the whole stream
				}
				objectIds = append(objectIds, objid)
			}
			if len(objectIds) > 0 {
				query = bson.M{"_id": bson.M{"$nin": objectIds}}
			}
		}

		// LoadDataWithCallback iterates a cursor. Callback returning a non-nil
		// error stops the iteration immediately — that's the EPIPE backpressure
		// channel for "reader closed stdin, stop streaming".
		err = LoadDataWithCallback(mdb, scanid, query, func(data G3Data) error {
			return enc.Encode(data)
		})
		if err != nil && err != io.ErrClosedPipe {
			encodeErr = err
		}
	}()
	return pr
}
```

This function uses `fmt.Errorf` — confirm `"fmt"` is already in `datastore.go`'s imports. If not, add it.

- [ ] **Step 3: Verify the module still builds**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

---

## Task 8: `BundleTaskSlot` in `manifest.go`

**Files:**
- Modify: `src/g3lib/manifest.go` (add bundling helper, expand imports)

- [ ] **Step 1: Add required imports**

The new function uses `archive/zip`, `io`, `mime`, `path/filepath`, `strings`. `filepath` is already imported by `manifest.go`. Add `archive/zip`, `io`, `mime`, and `strings` to the import block.

- [ ] **Step 2: Add `BundleTaskSlot`**

Append at the end of `manifest.go`, after `CreateEphemeralArtifactSlot`:

```go
// BundleTaskSlot enumerates slotDir (any task's artifact slot) and streams its
// contents to w, applying the 0/1/many discovery rule from the reporter plugin
// spec:
//
//   - 0 regular files → returns ("", "", os.ErrNotExist) so callers can render
//     a 404. (Impossible in practice: WriteManifest always lands manifest.json
//     in the slot. A 0 means the slot was reaped or the task_id is wrong.)
//   - Exactly 1 regular file, no subdirs → streams that file as-is to w.
//     Returned filename: <stem>-<taskID>.<ext> (stem/ext split on last dot).
//     Returned content-type: mime.TypeByExtension(.ext) or "application/octet-stream".
//   - Otherwise → streams a zip containing every regular file (recursing
//     subdirs). Returned filename: <tool>-<taskID>.zip; content-type:
//     "application/zip".
//
// The zip writer targets w directly — no in-memory buffering.
func BundleTaskSlot(slotDir, tool, taskID string, w io.Writer) (filename, contentType string, err error) {

	// First pass: walk the slot to classify it.
	var files []string                 // regular files, relative to slotDir
	var hasSubdir bool
	err = filepath.WalkDir(slotDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == slotDir {
			return nil
		}
		rel, _ := filepath.Rel(slotDir, path)
		if d.IsDir() {
			hasSubdir = true
			return nil
		}
		if d.Type().IsRegular() {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}

	// 0 files → not found.
	if len(files) == 0 {
		return "", "", os.ErrNotExist
	}

	// Exactly 1 file, no subdirs → stream as-is.
	if len(files) == 1 && !hasSubdir {
		name := files[0]
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		out := stem + "-" + taskID + ext
		ctype := mime.TypeByExtension(ext)
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		fp, err := os.Open(filepath.Join(slotDir, name))
		if err != nil {
			return "", "", err
		}
		defer fp.Close()
		if _, err := io.Copy(w, fp); err != nil {
			return "", "", err
		}
		return out, ctype, nil
	}

	// Otherwise → zip. Re-walk so we pick up files inside subdirs too.
	zw := zip.NewWriter(w)
	defer zw.Close()
	err = filepath.WalkDir(slotDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == slotDir || d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(slotDir, path)
		zf, err := zw.Create(rel)
		if err != nil {
			return err
		}
		fp, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fp.Close()
		_, err = io.Copy(zf, fp)
		return err
	})
	if err != nil {
		return "", "", err
	}
	return tool + "-" + taskID + ".zip", "application/zip", nil
}
```

- [ ] **Step 3: Verify the module still builds**

Run: `cd src/g3lib && go build ./...`
Expected: no output, exit code 0.

---

## Task 9: Worker handler

**Files:**
- Modify: `src/g3worker/g3worker.go` (subscribe to report topics; add the inline report-task handler in `main()` parallel to the existing tool-task closure)

The worker keeps its tool-handler logic inline in `main()` as a closure over `rdb_client`, `mq_client`, `sql_db`, `cancelTracker`, `workerid`, `plugins`, `selected`, `artifactsRoot`, `artifactsHostRoot`, `cancelled`, and the local `markTerminal` helper (defined at line 509 as a closure). The report handler follows the same shape so it captures the same vars — no parameter threading, no separate package-level function. This mirrors the existing pattern verbatim.

- [ ] **Step 1: Read the existing tool subscription block**

Read `src/g3worker/g3worker.go` lines 358-388 (plugin selection — the `selected` slice is built here) and lines 506-720 (the existing `markTerminal` closure at 509 + the `SubscribeAsWorker` callback at 520+). The new report handler will mirror this structure block-for-block.

- [ ] **Step 2: Build the reporter-plugin subset after `selected` is finalized**

Locate where `selected` is finalized (around line 388, after the if/else that populates it from either `slices.Sorted(maps.Keys(plugins))` or the env-var-supplied list). Immediately after `selected` is final, add:

```go
// Subset of selected plugins that declare a reporter phase. Used to subscribe
// to report/<name> topics in addition to the existing tool/<name> subscriptions.
var reporterSelected []string
for _, name := range selected {
	if plugin, ok := plugins[name]; ok && plugin.Reporter != nil {
		reporterSelected = append(reporterSelected, name)
	}
}
```

- [ ] **Step 3: Add a `markReportTerminal` closure next to the existing `markTerminal`**

Immediately after the existing `markTerminal := func(...) {...}` block (ending around line 517), add a parallel closure that accepts an error message:

```go
// markReportTerminal is the reporter-task counterpart of markTerminal. Unlike
// markTerminal, it accepts an optional error message that gets persisted into
// the per-task Redis hash via SetTaskTerminal's errMsg field. The audit log
// line still goes through SaveLogLine identically.
markReportTerminal := func(scanid, taskid, state, errMsg string) {
	completeTS := time.Now().Unix()
	if err := g3lib.SetTaskTerminal(rdb_client, scanid, taskid, state, completeTS, errMsg); err != nil {
		log.Error("Redis SetTaskTerminal (report) failed: " + err.Error())
	}
	if err := g3lib.SaveLogLine(sql_db, scanid, taskid, "[g3:done] report task="+taskid+" state="+state); err != nil {
		log.Error("SaveLogLine (report done) failed: " + err.Error())
	}
}
```

- [ ] **Step 4: Add the inline `SubscribeAsReporter` block after the existing `SubscribeAsWorker` block**

Find the closing brace of the `SubscribeAsWorker` callback (the block opening at line 520 — it closes with `})` after the tool handler ends, somewhere in the 700-720 range). The variable `topics` was assigned by `SubscribeAsWorker`; we want to append our reporter topics to it.

Immediately after the `SubscribeAsWorker` call returns (and its closing `})`), add:

```go
reporterTopics := g3lib.SubscribeAsReporter(mq_client, reporterSelected, func(client g3lib.MessageQueueClient, task g3lib.G3ReportTask) {

	// SIGTERM drain: matches the tool handler's first guard.
	if cancelled {
		markReportTerminal(task.ScanID, task.TaskID, "CANCELED", "")
		if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
			log.Error(err.Error())
		}
		return
	}

	// Cancellation context — same pattern as the tool handler.
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	switch cancelTracker.AddTaskIfNew(task.TaskID, cancel) {
	case 0:
		log.Notice("Duplicated report task request for ID: " + task.TaskID)
		return
	case 1:
		log.Debug("Rejected report task ID: " + task.TaskID)
		markReportTerminal(task.ScanID, task.TaskID, "CANCELED", "")
		if err := g3lib.SendTaskCancelHandled(mq_client, task.ScanID, []string{task.TaskID}); err != nil {
			log.Error(err.Error())
		}
		return
	case 2:
		log.Debug("Received new report task:\n" + g3lib.PrettyPrintJSON(task))
		startTS := time.Now().Unix()
		if err := g3lib.SetTaskRunning(rdb_client, task.ScanID, task.TaskID, workerid, startTS); err != nil {
			log.Error("Redis SetTaskRunning (report) failed: " + err.Error())
		}
		if err := g3lib.SaveLogLine(sql_db, task.ScanID, task.TaskID, "[g3:start] report task="+task.TaskID+" tool="+task.Tool+" worker="+workerid); err != nil {
			log.Error("SaveLogLine (report start) failed: " + err.Error())
		}
	default:
		log.Error("internal error")
		markReportTerminal(task.ScanID, task.TaskID, "ERROR", "internal error")
		if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
			log.Error(err.Error())
		}
		return
	}

	// Resolve the plugin and confirm it implements a reporter.
	plugin, ok := plugins[task.Tool]
	if !ok || plugin.Reporter == nil {
		log.Error("Report task for unknown or non-reporter plugin: " + task.Tool)
		markReportTerminal(task.ScanID, task.TaskID, "ERROR", "plugin not found or not a reporter")
		if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
			log.Error(err.Error())
		}
		return
	}

	// Materialize the per-task output slot.
	outSlot := filepath.Join(artifactsRoot, task.ScanID, task.TaskID)
	hostOut := filepath.Join(artifactsHostRoot, task.ScanID, task.TaskID)
	hostIn := filepath.Join(artifactsHostRoot, task.ScanID)
	if err := os.MkdirAll(outSlot, 0o755); err != nil {
		log.Error("Cannot create reporter slot " + outSlot + ": " + err.Error())
		markReportTerminal(task.ScanID, task.TaskID, "ERROR", err.Error())
		if e := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); e != nil {
			log.Error(e.Error())
		}
		return
	}

	// Build the parsed reporter command (preset resolution + env expansion).
	parsed, errA := g3lib.BuildReporterCommand(plugin, task.Preset)
	if len(errA) > 0 {
		msg := "reporter command build failed:"
		for _, e := range errA {
			msg += "\n - " + e.Error()
		}
		log.Error(msg)
		_ = g3lib.SaveLogLine(sql_db, task.ScanID, task.TaskID, msg)
		markReportTerminal(task.ScanID, task.TaskID, "ERROR", errA[0].Error())
		if e := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); e != nil {
			log.Error(e.Error())
		}
		return
	}

	// Open the JSONL stdin stream and dispatch the container.
	stdin := g3lib.ReporterStdinStream(mdb_client, rdb_client, task.ScanID)
	defer stdin.Close() //nolint:errcheck
	logWriter := &reporterLogWriter{scanid: task.ScanID, taskid: task.TaskID}
	runErr := g3lib.RunPluginReporter(ctx, plugin, parsed, hostIn, hostOut, stdin, logWriter)

	// Write the per-task manifest, same as today's tool tasks.
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
		StartedAt:  time.Now().Unix(), // placeholder; see note below
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

	// Decide terminal state and notify.
	terminal := "DONE"
	terminalMsg := ""
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) {
			terminal = "CANCELED"
		} else {
			terminal = "ERROR"
			terminalMsg = runErr.Error()
		}
	} else if manifestWriteErr != nil {
		terminal = "ERROR"
		terminalMsg = "manifest write failed: " + manifestWriteErr.Error()
	}
	markReportTerminal(task.ScanID, task.TaskID, terminal, terminalMsg)
	if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
		log.Error("SendEmptyResponse (report) failed: " + err.Error())
	}
})
topics = append(topics, reporterTopics...)
```

**Note on `StartedAt`:** the snippet above sets `StartedAt: time.Now().Unix()` at manifest-write time, which is incorrect — it should be the value captured in the switch's `case 2` branch when `startTS` was set. Refactor: hoist `var startTS int64` to the top of the callback (before the switch), assign it inside `case 2`, and reference it here. The placeholder is intentional in the plan so the executor must do the small lift — if you'd rather have me spell it out, see the executor note below.

Executor: do this refactor now. Add `var startTS int64` immediately after the `cancelled` guard returns (before the cancel-tracker switch). In `case 2`, replace `startTS := time.Now().Unix()` with `startTS = time.Now().Unix()`. Then change the manifest's `StartedAt:` line to `StartedAt: startTS,`.

- [ ] **Step 5: Add the `reporterLogWriter` type at package scope**

Outside of `main()` (at the bottom of `g3worker.go` is fine), add:

```go
// reporterLogWriter routes the reporter container's stdout/stderr to
// SaveLogLine, one line at a time. Partial trailing lines are buffered
// until the next Write; if the container exits without a trailing newline,
// the last partial fragment is lost (acceptable — the manifest's ExitStatus
// is the authoritative success/failure signal).
type reporterLogWriter struct {
	scanid string
	taskid string
	buf    []byte
}

func (w *reporterLogWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		idx := -1
		for i, b := range w.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]
		if line != "" {
			if err := g3lib.SaveLogLine(sql_db_for_logwriter, w.scanid, w.taskid, line); err != nil {
				log.Error("SaveLogLine (report stream) failed: " + err.Error())
			}
		}
	}
	return len(p), nil
}
```

There's a problem here: `sql_db_for_logwriter` is not defined. Two ways to resolve:

**Option A (recommended)**: capture `sql_db` from `main()` via a package-level variable set during initialization. Add at package scope:

```go
var sqlDBRef g3lib.DatastoreSQLClient // adjust type to match the actual SaveLogLine signature
```

In `main()`, immediately after `sql_db` is initialized (before the subscribe blocks), set `sqlDBRef = sql_db`. Then have `Write` use `sqlDBRef` instead of `sql_db_for_logwriter`. Module-global is ugly but matches the worker's existing reliance on outer-scope captures.

**Option B**: stash a reference to `sql_db` in `reporterLogWriter` itself. Change the struct to:

```go
type reporterLogWriter struct {
	sql    g3lib.DatastoreSQLClient // adjust type
	scanid string
	taskid string
	buf    []byte
}
```

…and pass it at construction: `logWriter := &reporterLogWriter{sql: sql_db, scanid: task.ScanID, taskid: task.TaskID}` in the subscribe callback. Then `Write` uses `w.sql`. This is cleaner.

**Use Option B.** Confirm the actual type of `sql_db` by reading where it's declared in `main()` (search for `sql_db :=` or `sql_db =`); use that exact type in the `sql` field. `g3lib.DatastoreSQLClient` is a placeholder — replace with the real type before building.

- [ ] **Step 6: Reconcile codebase-specific identifiers**

The cancel-tracker case constants (`0`/`1`/`2`) match the magic numbers in the existing tool handler (read `g3worker.go:541, 548, 558` to confirm). The functions `SetTaskRunning`, `SetTaskTerminal`, `SaveLogLine`, `SendEmptyResponse`, `SendTaskCancelHandled`, `EnumerateSlot`, `WriteManifest`, `PrettyPrintJSON`, and the `cancelled` flag / `cancelTracker.AddTaskIfNew` symbol all exist with these exact names — no rename needed; just confirm via grep before relying on them.

`shellquote.Join` requires `github.com/kballard/go-shellquote` in `g3worker`'s imports. If absent, add it.

New imports the file will likely need: `errors` (for `errors.Is`), `path/filepath` (for `filepath.Join`), `os` (for `MkdirAll`). Confirm and add as needed.

- [ ] **Step 7: Verify the module still builds**

Run: `cd src/g3worker && go build ./...`
Expected: no output, exit code 0. If the build fails because of a type mismatch on the SQL client field, replace `g3lib.DatastoreSQLClient` in the `reporterLogWriter` struct with whatever the actual `sql_db` type is.

---

## Task 10: `POST /scan/reporter` endpoint in `g3api`

**Files:**
- Modify: `src/g3api/g3api.go` (add new handler, add request struct, expand imports)

- [ ] **Step 1: Read existing endpoint patterns**

Read `src/g3api/g3api.go` lines 839-914 (the existing `/scan/report` handler) to understand the existing decoding, error helpers (`SendApiError`, `SendApiResponse`), and the `requireToken` wrapper. The new handler reuses all of these but produces a binary body instead of JSON.

Also check where MQTT publishing happens (look for `g3lib.SendTask` calls earlier in the file — there's one near the `/scan/start` handler) to see how the API publishes MQTT messages.

- [ ] **Step 2: Add the request struct in `src/g3lib/api.go`**

The existing `ReqReport` struct lives in `src/g3lib/api.go` (and is what the legacy `/scan/report` handler uses). Add a parallel struct for the new endpoint there:

```go
type ReqReporter struct {
	ScanID string `json:"scanid" validate:"required,uuid4"`
	Tool   string `json:"tool"   validate:"required"`
	Preset string `json:"preset"`
}

// Decode reads & validates the body the same way ReqReport.Decode does.
// Mirror that function's body verbatim, substituting the type name.
func (req *ReqReporter) Decode(r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close() //nolint:errcheck
	if err := json.Unmarshal(body, req); err != nil {
		return err
	}
	return validator.New().Struct(req)
}
```

If `ReqReport.Decode` uses a different shape (e.g. a generic helper), mirror that instead. The point is: same decoding contract as every other API endpoint.

- [ ] **Step 3: Add the `POST /scan/reporter` handler**

Add this `http.HandleFunc` block immediately after the existing `/scan/report` handler in `g3api.go` (around line 915, before `/scan/datalist`):

```go
///////////////////////////////////////////////////////////////////////////////////////////
// Run a reporter plugin and stream the result. Synchronous (Tier 1). Future Tier 2
// adds ?async=true and a separate generic /scan/task/artifacts download endpoint.
//
http.HandleFunc(apiPath + "/scan/reporter", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
	log.Debug("Handling: scan/reporter")
	var request g3lib.ReqReporter
	err := request.Decode(r)
	if err != nil {
		log.Error("Error decoding payload: " + err.Error())
		g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
		return
	}

	// Look up the plugin and validate the reporter phase + preset.
	plugin, ok := plugins[request.Tool]
	if !ok {
		g3lib.SendApiError(w, http.StatusBadRequest, "Unknown tool: "+request.Tool)
		return
	}
	if plugin.Reporter == nil {
		g3lib.SendApiError(w, http.StatusBadRequest, "Tool "+request.Tool+" does not implement a reporter")
		return
	}
	if request.Preset != "" {
		if len(plugin.Reporter.Commands) == 0 {
			g3lib.SendApiError(w, http.StatusBadRequest, "Tool "+request.Tool+" declares no reporter presets")
			return
		}
		found := false
		for _, cmd := range plugin.Reporter.Commands {
			if cmd.Name == request.Preset {
				found = true
				break
			}
		}
		if !found {
			g3lib.SendApiError(w, http.StatusBadRequest, "Unknown preset for tool "+request.Tool+": "+request.Preset)
			return
		}
	}

	// Generate the reporter task id, register dispatch in Redis, publish via MQTT.
	reporterTaskID := uuid.NewString()
	dispatchTS := time.Now().Unix()
	if err := g3lib.SetTaskDispatched(rdb_client, request.ScanID, reporterTaskID, request.Tool, dispatchTS); err != nil {
		log.Critical("Redis SetTaskDispatched (reporter) failed: " + err.Error())
		g3lib.SendApiError(w, http.StatusInternalServerError, "Failed to register reporter task.")
		return
	}
	// X-G3-Task-ID is set on every response from this path — forward-compat
	// for the Tier 2 async client that needs the task id even on errors.
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
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var terminalState string
WaitLoop:
	for {
		select {
		case <-r.Context().Done():
			// Client disconnected. The worker keeps running; the task is still
			// trackable via /scan/tasks/status?task_id=<reporterTaskID>.
			log.Debug("Client disconnected while waiting for reporter task " + reporterTaskID)
			return
		case <-ticker.C:
			state, err := g3lib.GetTaskState(rdb_client, request.ScanID, reporterTaskID)
			if err != nil {
				log.Error("GetTaskState (reporter) failed: " + err.Error())
				continue
			}
			switch state {
			case "DONE", "ERROR", "CANCELED":
				terminalState = state
				break WaitLoop
			default:
				// DISPATCHED, RUNNING, or "" (hash cleaned up) — keep polling.
			}
		}
	}

	// Handle terminal state.
	switch terminalState {
	case "ERROR":
		g3lib.SendApiError(w, http.StatusInternalServerError, "reporter task failed; see task logs")
		return
	case "CANCELED":
		g3lib.SendApiError(w, http.StatusServiceUnavailable, "reporter task was canceled")
		return
	case "DONE":
		// Stream the bundle. BundleTaskSlot writes the body during its
		// classify-and-stream walk, but Go's http.ResponseWriter wants headers
		// set before the body. Buffer the bundle to capture the filename +
		// content-type from BundleTaskSlot's return values, then set headers
		// and flush. Acceptable for Tier 1 — reports are bounded by individual
		// scan size; revisit if memory pressure shows up.
		artifactsRoot := os.Getenv(g3lib.G3_ARTIFACTS_ROOT)
		if artifactsRoot == "" {
			artifactsRoot = g3lib.G3_ARTIFACTS_ROOT_DEFAULT
		}
		slotDir := filepath.Join(artifactsRoot, request.ScanID, reporterTaskID)
		var buf bytes.Buffer
		filename, contentType, bundleErr := g3lib.BundleTaskSlot(slotDir, request.Tool, reporterTaskID, &buf)
		if bundleErr != nil {
			if errors.Is(bundleErr, os.ErrNotExist) {
				g3lib.SendApiError(w, http.StatusNotFound, "task produced no output")
				return
			}
			log.Error("BundleTaskSlot failed: " + bundleErr.Error())
			g3lib.SendApiError(w, http.StatusInternalServerError, "failed to bundle reporter output")
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(buf.Bytes()); err != nil {
			log.Error("response write failed: " + err.Error())
		}
		return
	default:
		// Shouldn't reach here.
		g3lib.SendApiError(w, http.StatusInternalServerError, "unexpected terminal state: "+terminalState)
		return
	}
}))
```

**One thing the executor must reconcile:** `plugins`, `rdb_client`, `mq_client`, `apiPath`, `apiToken` are placeholders matching the convention in the surrounding handler code. Read the existing `/scan/report` and `/scan/start` blocks to confirm the actual variable names in scope (the API uses Go's closure-over-outer-scope pattern for these dependencies) and adjust if any name differs.

- [ ] **Step 4: Ensure imports**

The new handler uses: `bytes`, `errors`, `filepath`, `os`, `time`, plus `github.com/google/uuid`. All except possibly `bytes` are likely already imported by g3api.go; check and add what's missing.

- [ ] **Step 5: Verify the module still builds**

Run: `cd src/g3api && go build ./...`
Expected: no output, exit code 0.

---

## Task 11: Verify `magenta.g3p` is registry-compatible

**Files:**
- Read-only: `plugins/report/magenta/magenta.g3p`

- [ ] **Step 1: Read the file and confirm it declares `reporter: {}`**

```
cat plugins/report/magenta/magenta.g3p
```

Expected content:

```jsonnet
{
    url: "https://github.com/golismero/magenta",
    description: {
        en: "Magenta Reporter takes the output files from commonly used penetration testing tools and generates a ready to use report in Markdown format.",
    },
    reporter: {},
}
```

If this matches, no change is required — `reporter: {}` parses to a non-nil `G3Plugin.Reporter` with empty `Commands` (per Task 1's schema), which is the explicitly-supported "no presets, entrypoint runs with no args" case.

- [ ] **Step 2: Confirm no edit is required**

If the file matches the expected content from Step 1, skip ahead to Task 12. If it differs (e.g. an executor accidentally edited it), restore to the expected content above.

The actual `g3r.sh` wrapper implementation (which calls magenta's real CLI) is **out of scope** for this Tier 1 plan per the spec — it requires knowledge of magenta's CLI flags and the user has flagged it as their responsibility to verify against the magenta repo.

---

## Task 12: Cross-binary build sweep

**Files:**
- No edits, build verification only.

- [ ] **Step 1: Build every Go binary**

Each binary in `src/` imports `g3lib` and `g3log`. Changes to `g3lib` must not break any consumer. Run:

```
make bin
```

(from the repo root). Expected: every binary in `src/` builds successfully, producing artifacts in `bin/`. No errors, no warnings about unused imports or undefined identifiers.

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

Summary of what's now shipping:

- A `reporter` phase declarable on any `.g3p` file (Tier 1 schema)
- `POST /scan/reporter` synchronous endpoint that dispatches a reporter task, polls for terminal state, and streams the slot's contents (single file or zip)
- The `magenta` plugin scaffold remains operational with `reporter: {}` — the actual `g3r.sh` wrapper is left as user work per the spec

Tier 2 (async API + `/scan/task/artifacts`), Tier 3 (local CLI), and Tier 4 (polish) are not implemented by this plan.
