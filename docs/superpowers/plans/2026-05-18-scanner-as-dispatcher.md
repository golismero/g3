# Scanner as Sole Task Dispatcher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make g3scanner the sole entity that publishes to MQTT worker topics; add `POST /scan/task/dispatch` for on-demand task dispatch (tool + reporter kinds); remove the Tier 1 reporter direct-dispatch path.

**Architecture:** Pure intra-process change across g3lib, g3scanner, g3api. New MQTT topic `dispatch`, new `G3Dispatch` message type, new scanner-side handler running at scanner-process level (outside any ScanRunner goroutine). g3api becomes a thin HTTP-to-MQTT proxy that publishes dispatch requests; scanner re-publishes to existing worker topics with full bookkeeping. ScanRunner's existing two dispatch sites refactor to share an internal helper with the new handler.

**Tech Stack:** Go 1.25, paho MQTT, existing g3lib types and helpers, Redis + SQL connections.

**Spec:** [docs/superpowers/specs/2026-05-18-scanner-as-dispatcher-design.md](../specs/2026-05-18-scanner-as-dispatcher-design.md)

---

## Notes for executors

Same project-level overrides used by every prior reporter-plugin tier:

- **Tests are user-owned.** Do not write tests, do not run tests, do not use the test-driven-development skill.
- **Git is user-owned.** Do not run mutating git commands (`add`, `commit`, `mv`, `rm`, `push`). Read-only inspection (`git status`, `git diff`) is fine. The user commits at the end of the plan in one batch.
- **No per-task STOP.** Run through end-to-end without checkpoint pauses.
- **Verification per task = `go build ./...`** in the affected module(s). Final task does a cross-binary build sweep.

---

## File structure

| File | Change |
| --- | --- |
| `src/g3lib/task.go` | Add `G3DISPATCHTOPIC` const, `MSG_DISPATCH` const + VALID_MSG entry, `G3Dispatch` struct, `DispatchHandler` type, `SendDispatch` helper, `SubscribeAsDispatcher` helper. Also change `SendTask` signature: takes `dataid string` instead of `data G3Data`. |
| `src/g3lib/api.go` | Add `ReqTaskDispatch` struct + `Decode` method. Later: remove `ReqReporter` struct + `Decode` method. |
| `src/g3scanner/g3scanner.go` | Add scanner-process-level Redis + SQL connections in `main()`. Add `SubscribeAsDispatcher` call. Add `dispatchHandler` function at package scope. Add `dispatchTask` helper at package scope. Refactor both ScanRunner pipeline-loop dispatch sites (lines 626-647 and 908-928) to call `dispatchTask`, extracting `data["_id"].(string)` for the new SendTask signature. |
| `src/g3api/g3api.go` | Remove the `/scan/reporter` handler entirely. Add `POST /scan/task/dispatch` handler. |

---

## Task 1: g3lib/task.go — new dispatch MQTT plumbing

**Files:**
- Modify: `src/g3lib/task.go`

Five inserts, all additive (no signature changes to existing functions). Step-by-step.

- [ ] **Step 1: Add topic constant**

Find the existing topic constants block (lines 35-42, ending with `G3RESPONSETOPIC`). Append after the last constant:

```go
const G3DISPATCHTOPIC       = "dispatch"
```

- [ ] **Step 2: Add message type constant + VALID_MSG entry**

Find the `G3MESSAGETYPE` const block (lines 47-55 area, ending with `MSG_REPORT`). Append `MSG_DISPATCH` to the block:

```go
const (
	MSG_TASK     G3MESSAGETYPE = "task"
	MSG_SCAN     G3MESSAGETYPE = "scan"
	MSG_STATUS   G3MESSAGETYPE = "status"
	MSG_CANCEL   G3MESSAGETYPE = "cancel"
	MSG_STOP     G3MESSAGETYPE = "stop"
	MSG_RESPONSE G3MESSAGETYPE = "response"
	MSG_REPORT   G3MESSAGETYPE = "report"
	MSG_DISPATCH G3MESSAGETYPE = "dispatch"
)
```

Append `MSG_DISPATCH` to the `VALID_MSG` array (one line below, preserving the existing entries — note `MSG_STOP` is intentionally absent from this array, that's pre-existing and stays absent):

```go
var VALID_MSG = [...]G3MESSAGETYPE{MSG_TASK, MSG_SCAN, MSG_STATUS, MSG_CANCEL, MSG_RESPONSE, MSG_REPORT, MSG_DISPATCH}
```

- [ ] **Step 3: Add `G3Dispatch` struct + `DispatchHandler` type**

Find `G3ReportTask` (around line 89, defined right after `G3Task`). Append `G3Dispatch` immediately after `G3ReportTask`:

```go
type G3Dispatch struct {        // MessageType: MSG_DISPATCH
	G3TaskMessage               // embeds ScanID + TaskID; TaskID is required,uuid4
	Kind   string `json:"kind"   validate:"required,oneof=tool report"`
	Tool   string `json:"tool"   validate:"required"`
	// kind=tool fields:
	DataID string `json:"dataid,omitempty" validate:"omitempty,mongodb"`
	Index  int    `json:"index,omitempty"  validate:"gte=0"`
	// kind=report fields:
	Preset string `json:"preset,omitempty"`
}
```

Find the existing handler-type block (around lines 142-145, with `NewScanHandler`, `ScanStatusHandler`, `ScanStopHandler`, `ReportTaskHandler`). Append:

```go
type DispatchHandler func(MessageQueueClient, G3Dispatch)
```

- [ ] **Step 4: Change `SendTask` signature**

Find the existing `SendTask` function (around line 319-338). Current signature:

```go
func SendTask(client MessageQueueClient, scanid, taskid, tool string, index int, data G3Data) error {
```

Change to take `dataid string` instead of `data G3Data`. The new body removes the `data["_id"]` extraction since the caller supplies the ID directly:

```go
// SendTask publishes a tool task to a worker via the tool/<name> topic.
// The caller is responsible for generating taskid (e.g. via uuid.NewString())
// and supplying dataid (the MongoDB id of the G3Data the worker will operate on).
// Generating the task ID outside this function lets out-of-band state (Redis,
// SQL logs) be set up before the message is published — otherwise a worker
// might pick up the task and race ahead of the scanner's own bookkeeping.
func SendTask(client MessageQueueClient, scanid, taskid, tool string, index int, dataid string) error {
	msg := G3Task{}
	msg.MessageType = MSG_TASK
	msg.SenderID = GetClientID(client)
	msg.TaskID = taskid
	msg.ScanID = scanid
	msg.Tool = tool
	msg.Index = index
	msg.DataID = dataid
	err := validator.New().Struct(msg)
	if err != nil {
		return err
	}
	topic := G3WORKERPUBTOPIC + tool
	return SendMQPayload(client, topic, msg)
}
```

This change breaks the two existing callers in `g3scanner.go` — Task 3 updates them in the same batch. After this step alone, `cd src/g3lib && go build ./...` will succeed (the file is self-consistent), but `cd src/g3scanner && go build ./...` will fail until Task 3 lands. That's expected; the cross-binary build sweep happens in Task 5.

- [ ] **Step 5: Add `SendDispatch` helper**

Append after `SendTask` (or wherever logically follows in the Send-helpers area):

```go
// SendDispatch publishes a G3Dispatch to the scanner's dispatch topic.
// The caller (g3api) is responsible for generating the TaskID, validating
// the request shape against plugin metadata, and populating kind-specific
// fields. The scanner re-validates kind-specific fields on receipt and
// publishes to the appropriate worker topic.
func SendDispatch(client MessageQueueClient, msg G3Dispatch) error {
	msg.MessageType = MSG_DISPATCH
	msg.SenderID = GetClientID(client)
	if err := validator.New().Struct(msg); err != nil {
		return err
	}
	return SendMQPayload(client, G3DISPATCHTOPIC, msg)
}
```

- [ ] **Step 6: Add `SubscribeAsDispatcher` helper**

Find `SubscribeAsScanner` (around line 578). Append `SubscribeAsDispatcher` after it:

```go
// SubscribeAsDispatcher registers the scanner as a dispatch consumer.
// Unlike SubscribeAsScanner (which spawns a per-scan ScanRunner goroutine
// to handle MSG_SCAN), this handler runs at the scanner-process level and
// handles dispatches for any scan — including ones with no active ScanRunner
// (e.g. dispatching a reporter for a terminated scan).
func SubscribeAsDispatcher(client MessageQueueClient, callback DispatchHandler) string {
	log.Debug("Subscribing to: " + G3DISPATCHTOPIC)
	client.Subscribe(G3DISPATCHTOPIC, MQTT_QOS, func(client mqtt.Client, msg mqtt.Message) {

		// Decode the JSON payload.
		var dispatch G3Dispatch
		err := json.Unmarshal(msg.Payload(), &dispatch)
		if err != nil {
			log.Error("Error parsing JSON payload from MQTT message: " + err.Error())
			return
		}

		// Validate.
		err = validator.New().Struct(dispatch)
		if err != nil || dispatch.MessageType != MSG_DISPATCH {
			if err != nil {
				log.Error("Malformed dispatch object received: " + err.Error())
			} else {
				log.Error("Malformed dispatch object received: wrong MessageType")
			}
			return
		}

		// Run the dispatch handler synchronously. The work is light (one
		// Redis write, one SQL write, one MQTT publish) so spawning a
		// goroutine per message would be premature.
		callback(client, dispatch)
	})
	return G3DISPATCHTOPIC
}
```

- [ ] **Step 7: Verify module builds**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`

Expected: no output, exit 0. (g3lib has no internal callers of `SendTask`, so the signature change is local-consistent within g3lib.)

---

## Task 2: g3lib/api.go — new `ReqTaskDispatch` struct

**Files:**
- Modify: `src/g3lib/api.go`

- [ ] **Step 1: Locate the request-struct area**

Open `src/g3lib/api.go`. The existing request structs (`ReqStartScan`, `ReqStopScan`, `ReqReport`, `ReqReporter`, `ReqTaskArtifacts`, `ReqTaskCancel`, etc.) live in the lower half of the file with their `Decode` methods immediately after each struct definition. Find a spot near the other task-related request structs (`ReqTaskArtifacts`, `ReqTaskCancel`) — append after them.

- [ ] **Step 2: Add `ReqTaskDispatch` struct + `Decode`**

Insert immediately after `ReqTaskCancel`'s `Decode` method:

```go
type ReqTaskDispatch struct {
	ScanID string `json:"scanid" validate:"required,uuid"`
	Kind   string `json:"kind"   validate:"required,oneof=tool report"`
	Tool   string `json:"tool"   validate:"required"`
	// kind=tool fields:
	DataID string `json:"dataid,omitempty" validate:"omitempty,mongodb"`
	Index  int    `json:"index,omitempty"  validate:"gte=0"`
	// kind=report fields:
	Preset string `json:"preset,omitempty"`
}

func (req *ReqTaskDispatch) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}
```

`ReqReporter` is **not** removed in this task — it's still used by the `/scan/reporter` handler that gets removed in Task 4. Removing it now would break the g3api build.

- [ ] **Step 3: Verify module builds**

Run: `cd /home/crapula/code/g3/src/g3lib && go build ./...`

Expected: no output, exit 0.

---

## Task 3: g3scanner — dispatch handler + scanner main additions + ScanRunner refactor

**Files:**
- Modify: `src/g3scanner/g3scanner.go`

This is the biggest task because the scanner work is tightly coupled: the SendTask signature change from Task 1 requires updating the two ScanRunner call sites in the same atomic change as adding the new dispatch helpers. All in one file.

- [ ] **Step 1: Add scanner-process-level Redis + SQL connections in `main()`**

Find `main()` in `g3scanner.go` (around line 65). The scanner currently establishes its MQTT connection at process level (for `SubscribeAsScanner`) and lets each `ScanRunner` goroutine make its own Redis/Mongo/SQL connections. We add process-level Redis and SQL connections for the new dispatch handler — these live for the entire scanner process lifetime.

Find the existing `mq_client, err := g3lib.ConnectToBroker(...)` call near the top of `main()`. After the `defer g3lib.DisconnectFromBroker(...)` immediately below it, add Redis and SQL connections:

```go
	// Process-level Redis connection for the dispatch handler. ScanRunner
	// goroutines still establish their own per-goroutine Redis connections.
	rdb_client, err := g3lib.ConnectToRedis()
	if err != nil {
		log.Critical("Cannot connect to Redis: " + err.Error())
		os.Exit(1)
	}
	defer func() {
		_ = g3lib.DisconnectFromRedis(rdb_client)
	}()
	log.Debug("Process connected to Redis (dispatch handler).")

	// Process-level SQL connection for the dispatch handler.
	sql_db, err := g3lib.ConnectToSQL()
	if err != nil {
		log.Critical("Cannot connect to SQL database: " + err.Error())
		os.Exit(1)
	}
	defer g3lib.DisconnectFromSQL(sql_db)
	log.Debug("Process connected to SQL database (dispatch handler).")
```

Imports needed: `os` is already imported. No new imports for this step.

- [ ] **Step 2: Add `SubscribeAsDispatcher` call in `main()`**

Find the existing `SubscribeAsScanner` call (around line 234). It looks like:

```go
topic = g3lib.SubscribeAsScanner(mq_client, func(client g3lib.MessageQueueClient, msg g3lib.G3Scan) {
    // ... ScanRunner spawn ...
})
```

Immediately after this block (after the closing `})` of `SubscribeAsScanner`), add a parallel `SubscribeAsDispatcher` registration:

```go
	// Subscribe to dispatch messages from g3api. Runs at scanner-process
	// level — handles dispatches for any scan, including terminated scans
	// with no active ScanRunner.
	dispatchTopic := g3lib.SubscribeAsDispatcher(mq_client, func(_ g3lib.MessageQueueClient, msg g3lib.G3Dispatch) {
		dispatchHandler(mq_client, rdb_client, sql_db, plugins, msg)
	})
	_ = dispatchTopic // returned for symmetry with SubscribeAsScanner; not stored anywhere
```

The `plugins` variable must be in scope at this point in `main()`. If the existing code loads plugins via `g3lib.LoadPlugins()` further down, move that call up so `plugins` is available before this subscription. Read the surrounding code to confirm the right insertion point.

- [ ] **Step 3: Add `dispatchTask` helper at package scope**

Append to the bottom of `g3scanner.go` (after all existing functions, or alongside `ScanRunner` — wherever feels right organizationally):

```go
// dispatchTask is the canonical "publish a task to its worker" function.
// Called by both ScanRunner (script-driven dispatches inside the pipeline
// execution loop) and the on-demand dispatch handler (API-driven dispatches).
// Writes the [g3:dispatch] log marker, sets Redis DISPATCHED state, then
// publishes to the appropriate worker topic. Returns the worker-publish
// error (or nil) — the SQL/Redis writes are best-effort logged but don't
// fail the dispatch (intentional: a transient SQL hiccup shouldn't block a
// task from running).
//
// Callers are responsible for upstream validation (plugin exists, kind/fields
// are valid). This helper assumes well-formed inputs.
func dispatchTask(
	mq  g3lib.MessageQueueClient,
	rdb g3lib.KeyValueStoreClient,
	sql g3lib.SQLDBClient,
	scanID, taskID, kind, tool string,
	dataID string, // tool kind only
	index  int,    // tool kind only
	preset string, // report kind only
) error {
	dispatchTS := time.Now().Unix()
	if err := g3lib.SetTaskDispatched(rdb, scanID, taskID, tool, dispatchTS); err != nil {
		log.Error("Redis SetTaskDispatched failed: " + err.Error())
	}
	if err := g3lib.SaveLogLine(sql, scanID, taskID, "[g3:dispatch] task="+taskID+" tool="+tool); err != nil {
		log.Error("SaveLogLine (dispatch) failed: " + err.Error())
	}
	switch kind {
	case "tool":
		return g3lib.SendTask(mq, scanID, taskID, tool, index, dataID)
	case "report":
		return g3lib.SendReportTask(mq, scanID, taskID, tool, preset)
	default:
		return fmt.Errorf("unknown dispatch kind: %s", kind)
	}
}
```

Imports needed: `fmt`, `time` should already be imported. `g3lib` is already imported.

- [ ] **Step 4: Add `dispatchHandler` function at package scope**

Append immediately after `dispatchTask`:

```go
// dispatchHandler is registered via SubscribeAsDispatcher. Runs at the
// scanner-process level — handles dispatches for any scan, regardless of
// whether it's actively running its script.
//
// Validation: the validator on G3Dispatch already enforced common required
// fields (TaskID format, Kind oneof, Tool non-empty, DataID format if set).
// Kind-specific required fields (DataID + Index in range for tool; preset
// existence for report) are validated here against plugin metadata.
//
// Bookkeeping order matters: SetTaskDispatched + [g3:dispatch] marker are
// written FIRST so SetTaskTerminal on validation failure has a Redis hash
// to update (SetTaskTerminal is a no-op if the hash is absent — see
// kvstore.go).
func dispatchHandler(
	mq  g3lib.MessageQueueClient,
	rdb g3lib.KeyValueStoreClient,
	sql g3lib.SQLDBClient,
	plugins g3lib.G3PluginMetadata,
	msg g3lib.G3Dispatch,
) {
	dispatchTS := time.Now().Unix()
	if err := g3lib.SetTaskDispatched(rdb, msg.ScanID, msg.TaskID, msg.Tool, dispatchTS); err != nil {
		log.Error("Redis SetTaskDispatched failed: " + err.Error())
	}
	if err := g3lib.SaveLogLine(sql, msg.ScanID, msg.TaskID, "[g3:dispatch] task="+msg.TaskID+" tool="+msg.Tool); err != nil {
		log.Error("SaveLogLine (dispatch) failed: " + err.Error())
	}

	markErr := func(reason string) {
		if err := g3lib.SetTaskTerminal(rdb, msg.ScanID, msg.TaskID, "ERROR", time.Now().Unix(), reason); err != nil {
			log.Error("Redis SetTaskTerminal failed: " + err.Error())
		}
		if err := g3lib.SaveLogLine(sql, msg.ScanID, msg.TaskID, "[g3:done] task="+msg.TaskID+" state=ERROR"); err != nil {
			log.Error("SaveLogLine (done/error) failed: " + err.Error())
		}
	}

	plugin, ok := plugins[msg.Tool]
	if !ok {
		markErr("unknown tool: " + msg.Tool)
		return
	}

	switch msg.Kind {
	case "tool":
		if len(plugin.Commands) == 0 {
			markErr("tool " + msg.Tool + " does not implement the tool phase")
			return
		}
		if msg.Index >= len(plugin.Commands) {
			markErr(fmt.Sprintf("index %d out of range for tool %s", msg.Index, msg.Tool))
			return
		}
		if msg.DataID == "" {
			markErr("kind=tool requires dataid")
			return
		}
		if err := g3lib.SendTask(mq, msg.ScanID, msg.TaskID, msg.Tool, msg.Index, msg.DataID); err != nil {
			markErr("MQTT publish failed: " + err.Error())
		}

	case "report":
		if plugin.Reporter == nil {
			markErr("tool " + msg.Tool + " does not implement a reporter")
			return
		}
		if msg.Preset != "" {
			if len(plugin.Reporter.Commands) == 0 {
				markErr("tool " + msg.Tool + " declares no reporter presets")
				return
			}
			found := false
			for _, c := range plugin.Reporter.Commands {
				if c.Name == msg.Preset {
					found = true
					break
				}
			}
			if !found {
				markErr("unknown preset for tool " + msg.Tool + ": " + msg.Preset)
				return
			}
		}
		if err := g3lib.SendReportTask(mq, msg.ScanID, msg.TaskID, msg.Tool, msg.Preset); err != nil {
			markErr("MQTT publish failed: " + err.Error())
		}

	default:
		markErr("unknown kind: " + msg.Kind)
	}
}
```

- [ ] **Step 5: Refactor ScanRunner pipeline-loop dispatch site (parallel mode, around line 626-647)**

Open `g3scanner.go` and find the current code at lines 626-647 (the parallel-mode dispatch). Current shape:

```go
		taskid := uuid.NewString()
		dispatchTS := time.Now().Unix()
		if err := g3lib.SetTaskDispatched(rdb_client, msg.ScanID, taskid, plugin.Name, dispatchTS); err != nil {
			log.Error("Redis SetTaskDispatched failed: " + err.Error())
		}
		if err := g3lib.SaveLogLine(scan_sql_db, msg.ScanID, taskid, "[g3:dispatch] task="+taskid+" tool="+plugin.Name); err != nil {
			log.Error("SaveLogLine (dispatch) failed: " + err.Error())
		}
		if err := g3lib.SendTask(mq_client, msg.ScanID, taskid, plugin.Name, index, data); err != nil {
			log.Error(err.Error())
			// Mark the task as errored since it was never dispatched.
			if e := g3lib.SetTaskTerminal(rdb_client, msg.ScanID, taskid, "ERROR", time.Now().Unix(), "dispatch failed: "+err.Error()); e != nil {
				log.Error("Redis SetTaskTerminal (dispatch-fail) failed: " + e.Error())
			}
			if e := g3lib.SaveLogLine(scan_sql_db, msg.ScanID, taskid, "[g3:done] task="+taskid+" state=ERROR"); e != nil {
				log.Error("SaveLogLine (dispatch-fail) failed: " + e.Error())
			}
			if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
				log.Error(err.Error())
			}
			return
		}
```

Replace with:

```go
		taskid := uuid.NewString()
		// Extract the MongoDB id of the input G3Data. SendTask (via dispatchTask)
		// now takes dataid as a string rather than the full G3Data — the caller
		// owns the extraction, which makes the worker-bound message shape
		// uniform between script-driven and API-driven dispatch.
		dataid, ok := data["_id"].(string)
		if !ok {
			err := errors.New("data missing _id, save to database first")
			log.Error(err.Error())
			if e := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); e != nil {
				log.Error(e.Error())
			}
			return
		}
		if err := dispatchTask(mq_client, rdb_client, scan_sql_db, msg.ScanID, taskid, "tool", plugin.Name, dataid, index, ""); err != nil {
			log.Error(err.Error())
			// Mark the task as errored since it was never dispatched.
			if e := g3lib.SetTaskTerminal(rdb_client, msg.ScanID, taskid, "ERROR", time.Now().Unix(), "dispatch failed: "+err.Error()); e != nil {
				log.Error("Redis SetTaskTerminal (dispatch-fail) failed: " + e.Error())
			}
			if e := g3lib.SaveLogLine(scan_sql_db, msg.ScanID, taskid, "[g3:done] task="+taskid+" state=ERROR"); e != nil {
				log.Error("SaveLogLine (dispatch-fail) failed: " + e.Error())
			}
			if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
				log.Error(err.Error())
			}
			return
		}
```

Imports needed: `errors` should already be imported in g3scanner.go. Verify.

The error-handling block (`SetTaskTerminal` + `[g3:done]` + `SendScanFailed`) intentionally stays inline because it does scan-runner-specific things (fails the entire scan via `SendScanFailed`) that the dispatch handler does NOT do. Two callers with different failure semantics share the same successful-dispatch helper.

- [ ] **Step 6: Refactor ScanRunner pipeline-loop dispatch site (sequential mode, around line 908-928)**

Find the second dispatch site at lines 908-928. The code is essentially identical to step 5. Apply the same transformation:

```go
		taskid := uuid.NewString()
		dataid, ok := data["_id"].(string)
		if !ok {
			err := errors.New("data missing _id, save to database first")
			log.Error(err.Error())
			if e := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); e != nil {
				log.Error(e.Error())
			}
			return
		}
		if err := dispatchTask(mq_client, rdb_client, scan_sql_db, msg.ScanID, taskid, "tool", plugin.Name, dataid, index, ""); err != nil {
			log.Error(err.Error())
			if e := g3lib.SetTaskTerminal(rdb_client, msg.ScanID, taskid, "ERROR", time.Now().Unix(), "dispatch failed: "+err.Error()); e != nil {
				log.Error("Redis SetTaskTerminal (dispatch-fail) failed: " + e.Error())
			}
			if e := g3lib.SaveLogLine(scan_sql_db, msg.ScanID, taskid, "[g3:done] task="+taskid+" state=ERROR"); e != nil {
				log.Error("SaveLogLine (dispatch-fail) failed: " + e.Error())
			}
			if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
				log.Error(err.Error())
			}
			return
		}
```

- [ ] **Step 7: Verify module builds**

Run: `cd /home/crapula/code/g3/src/g3scanner && go build ./...`

Expected: no output, exit 0.

If the build fails with "errors not imported" or similar, check the import block at the top of g3scanner.go and add what's missing. If it fails with "fmt not imported" (used by `dispatchHandler`'s `Sprintf`), add `"fmt"` to the imports.

---

## Task 4: g3api endpoint replacement + `ReqReporter` removal

**Files:**
- Modify: `src/g3api/g3api.go`
- Modify: `src/g3lib/api.go`

- [ ] **Step 1: Remove the `/scan/reporter` handler from g3api.go**

Open `src/g3api/g3api.go`. Find the entire `/scan/reporter` handler — it's roughly 100+ lines starting at the line where `http.HandleFunc(apiPath + "/scan/reporter", ...)` is registered (around line 922). The handler ends at the matching `}))` closing the requireToken+http.HandleFunc combination.

Delete the entire handler block from the `http.HandleFunc` line through its closing `}))`.

After deletion, g3api.go has no remaining references to `g3lib.ReqReporter`. Verify with: `grep ReqReporter /home/crapula/code/g3/src/g3api/g3api.go` — expected: no matches.

- [ ] **Step 2: Add the new `POST /scan/task/dispatch` handler**

Find a sensible insertion point near the other task-related handlers (`/scan/task/artifacts`, `/scan/task/cancel`). Append the new handler immediately after `/scan/task/cancel`:

```go
		///////////////////////////////////////////////////////////////////////////////////////////
		// Dispatch a task on demand. Generic across kinds (currently tool + report).
		// Replaces the Tier 1 /scan/reporter direct-dispatch path with a scanner-mediated
		// flow: g3api validates, generates the task_id, publishes to the scanner's
		// dispatch topic. Scanner re-validates kind-specific fields, sets Redis state,
		// writes log markers, and publishes to the worker topic.
		//
		// Async-only — returns 202 + {task_id} immediately. Clients poll
		// /scan/tasks/status for state and use /scan/task/artifacts to download
		// outputs (for reporter tasks). See
		// docs/superpowers/specs/2026-05-18-scanner-as-dispatcher-design.md.
		//
		http.HandleFunc(apiPath + "/scan/task/dispatch", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/task/dispatch")
			var request g3lib.ReqTaskDispatch
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Look up the plugin and validate kind/fields against plugin shape.
			plugin, ok := plugins[request.Tool]
			if !ok {
				g3lib.SendApiError(w, http.StatusBadRequest, "unknown tool: "+request.Tool)
				return
			}

			switch request.Kind {
			case "tool":
				if len(plugin.Commands) == 0 {
					g3lib.SendApiError(w, http.StatusBadRequest, "tool "+request.Tool+" does not implement the tool phase")
					return
				}
				if request.Index >= len(plugin.Commands) {
					g3lib.SendApiError(w, http.StatusBadRequest, "index out of range for tool "+request.Tool)
					return
				}
				if request.DataID == "" {
					g3lib.SendApiError(w, http.StatusBadRequest, "kind=tool requires dataid")
					return
				}
			case "report":
				if plugin.Reporter == nil {
					g3lib.SendApiError(w, http.StatusBadRequest, "tool "+request.Tool+" does not implement a reporter")
					return
				}
				if request.Preset != "" {
					if len(plugin.Reporter.Commands) == 0 {
						g3lib.SendApiError(w, http.StatusBadRequest, "tool "+request.Tool+" declares no reporter presets")
						return
					}
					found := false
					for _, c := range plugin.Reporter.Commands {
						if c.Name == request.Preset {
							found = true
							break
						}
					}
					if !found {
						g3lib.SendApiError(w, http.StatusBadRequest, "unknown preset for tool "+request.Tool+": "+request.Preset)
						return
					}
				}
			default:
				g3lib.SendApiError(w, http.StatusBadRequest, "unknown kind: "+request.Kind)
				return
			}

			// Generate the task_id and publish the dispatch to the scanner.
			taskid := uuid.NewString()
			dispatch := g3lib.G3Dispatch{
				G3TaskMessage: g3lib.G3TaskMessage{
					G3Message: g3lib.G3Message{
						ScanID: request.ScanID,
					},
					TaskID: taskid,
				},
				Kind:   request.Kind,
				Tool:   request.Tool,
				DataID: request.DataID,
				Index:  request.Index,
				Preset: request.Preset,
			}
			if err := g3lib.SendDispatch(mq_client, dispatch); err != nil {
				log.Error("SendDispatch failed: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "failed to publish dispatch")
				return
			}

			// Set the X-G3-Task-ID header so clients have two equivalent ways to
			// learn the task_id (parse JSON body or read header).
			w.Header().Set("X-G3-Task-ID", taskid)
			w.WriteHeader(http.StatusAccepted)
			response := g3lib.APIResponse{
				Status: "success",
				Data:   map[string]string{"task_id": taskid},
			}
			response.Write(w)
		}))
```

The `uuid.NewString()` call requires `"github.com/google/uuid"` in the import block — it should already be there from Tier 1's `/scan/reporter` handler that used the same pattern. Verify after deletion in Step 1: if removing the old handler left no other uuid users, add `"github.com/google/uuid"` back to imports.

- [ ] **Step 3: Remove `ReqReporter` from g3lib/api.go**

Open `src/g3lib/api.go`. Find the `ReqReporter` struct (around line 250) and its `Decode` method. Delete both.

- [ ] **Step 4: Verify both modules build**

Run sequentially:

```
cd /home/crapula/code/g3/src/g3lib && go build ./...
cd /home/crapula/code/g3/src/g3api && go build ./...
```

Expected: both produce no output, exit 0.

---

## Task 5: Cross-binary build sweep

**Files:**
- No edits. Build verification only.

- [ ] **Step 1: Build every Go binary**

Run from the repo root:

```
make bin
```

Expected: every binary in `src/` builds successfully, producing artifacts in `bin/`. No errors.

If `make bin` is unavailable in the executor's environment, build each directly:

```
cd src/g3       && go build ./... && cd -
cd src/g3api    && go build ./... && cd -
cd src/g3cli    && go build ./... && cd -
cd src/g3config && go build ./... && cd -
cd src/g3scanner && go build ./... && cd -
cd src/g3worker && go build ./... && cd -
```

Expected: all builds succeed.

- [ ] **Step 2: Confirm no stale references**

Quick sanity grep for anything still pointing at the removed surface:

```
grep -rn "/scan/reporter\|ReqReporter" src/ --include='*.go'
```

Expected: no matches in `src/`. (Doc references in `docs/` are fine — they're historical context.)

- [ ] **Step 3: Report completion**

The plan is complete when both checks pass. The user will commit; do not run any git commands.

Summary of what now ships:

- `POST /scan/task/dispatch { scan_id, kind, tool, ... }` async-only endpoint, 202 + `{ task_id }`.
- Scanner subscribes to new MQTT `dispatch` topic, processes dispatches at process level (independent of any ScanRunner), publishes to existing worker topics.
- ScanRunner's two pipeline-loop dispatch sites refactored to use `dispatchTask` — same canonical code path as the new dispatch handler.
- Tier 1's `/scan/reporter` handler and `ReqReporter` struct deleted entirely (no consumers exist).
- `g3lib.SendTask` signature change: now takes `dataid string` instead of `data G3Data`. All callers updated.

Architectural result: **g3scanner is the sole entity that publishes to MQTT worker topics.** g3api becomes a thin HTTP-to-MQTT proxy that publishes dispatch messages to the scanner.

Future-work items (deferred per the spec): re-run via fresh task_id + retry-marker, importer migration to worker dispatch, merger migration to worker dispatch (which together let g3scanner and g3api drop docker-socket access entirely), HA scanner deployment, the original Tier 3 local-CLI reporter integration, and convenience CLI for one-shot reporter UX.
