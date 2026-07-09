package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golismero/g3/src/g3lib"
	log "github.com/golismero/g3/src/g3/log"
	"github.com/golismero/g3/src/g3"
)

// Environment variable with the list of enabled plugins for a given worker.
const G3_WORKER_PLUGINS = "G3_WORKER_PLUGINS"

// Maximum amount of time to hold a task cancellation message, in time.ParseDuration() format.
const G3_HOLD_CANCEL = "G3_HOLD_CANCEL"
const G3_HOLD_CANCEL_DEFAULT = "5m"

// Helper function to read a whole line without buffer size limits.
// https://devmarkpro.com/working-big-files-golang
func read(r *bufio.Reader) ([]byte, error) {
	var (
		isPrefix = true
		err      error
		line, ln []byte
	)

	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}

	return ln, err
}

// This object tracks which currently running tasks can be cancelled,
// and which task IDs to reject on sight because they were cancelled
// while the task start message was still in the queue.
type CancelTracker struct {
	sync.RWMutex
	stateFile    string
	holdDuration time.Duration
	rejectTasks  map[string]time.Time          // Task ID -> time to hold
	cancelFunc   map[string]context.CancelFunc // Task ID -> cancel()
}

func NewCancelTracker(workerid string, duration time.Duration) *CancelTracker {
	stateFile := ""
	if workerid != "" {
		stateFile = filepath.Join(g3lib.GetHomeDirectory(), g3lib.G3CONFIG, workerid+"-state.json")
	}
	return &CancelTracker{
		stateFile:    stateFile,
		holdDuration: duration,
		rejectTasks:  make(map[string]time.Time),
		cancelFunc:   make(map[string]context.CancelFunc),
	}
}

// Save the state of the this when shutting down the worker.
func (tracker *CancelTracker) SaveState() {
	tracker.Lock()
	defer tracker.Unlock()

	// Ignore this call if we don't have a state file.
	if tracker.stateFile == "" {
		return
	}

	// Convert the map of rejected tasks into something easier to marshall.
	now := time.Now()
	rejectTasks := map[string]string{}
	for taskid, limit := range tracker.rejectTasks {
		delta := limit.Sub(now)
		if delta > 0 {
			rejectTasks[taskid] = delta.String()
		}
	}

	// Marshall the map into JSON.
	jsonBytes, err := json.Marshal(rejectTasks)
	if err != nil {
		log.Errorf("Cannot write file %s: %s", tracker.stateFile, err.Error())
		return
	}

	// Save the JSON file.
	err = os.WriteFile(tracker.stateFile, jsonBytes, 0644)
	if err != nil {
		log.Errorf("Cannot write file %s: %s", tracker.stateFile, err.Error())
		return
	}

	// Log the success of this call.
	log.Debug("Saved cancelled tasks state.")
}

// Load the state of the this when re-starting the worker.
func (tracker *CancelTracker) LoadState() {
	tracker.Lock()
	defer tracker.Unlock()

	// Ignore this call if we don't have a state file.
	if tracker.stateFile == "" {
		return
	}

	// Ignore if the state file hasn't been created yet.
	_, err := os.Stat(tracker.stateFile)
	if err != nil {
		log.Debugf("State file %v not found, ignoring.", tracker.stateFile)
		return
	}

	// Read the JSON file.
	jsonBytes, err := os.ReadFile(tracker.stateFile)
	if err != nil {
		log.Errorf("Cannot read file %s: %s", tracker.stateFile, err.Error())
		return
	}

	// Unmarshal the JSON data.
	var rejectTasks map[string]string
	err = json.Unmarshal(jsonBytes, &rejectTasks)
	if err != nil {
		log.Errorf("Cannot read file %s: %s", tracker.stateFile, err.Error())
		return
	}

	// Parse the Duration objects and populate the rejected tasks map.
	now := time.Now()
	for taskid, durationStr := range rejectTasks {
		duration, err := time.ParseDuration(durationStr)
		if err != nil {
			log.Errorf("Error parsing file %s: %s", tracker.stateFile, err.Error())
			duration, err = time.ParseDuration(G3_HOLD_CANCEL_DEFAULT)
			if err != nil {
				panic(err) // should not happen in production
			}
		}
		tracker.rejectTasks[taskid] = now.Add(duration)
	}

	// Check for expired task IDs in the state file.
	tracker.checkForExpiredCancellations()

	// Log the success of this call.
	log.Debug("Loaded cancelled tasks state.")
}

// Call this method when a new task request arrives.
func (tracker *CancelTracker) AddTaskIfNew(taskid string, cancel context.CancelFunc) int {
	tracker.Lock()
	defer tracker.Unlock()

	// Reject the task if it's currently running.
	if _, ok := tracker.cancelFunc[taskid]; ok {
		return 0 // means ignore
	}

	// Reject the task if it's pending cancellation.
	if _, ok := tracker.rejectTasks[taskid]; ok {
		delete(tracker.rejectTasks, taskid)
		return 1 // means rejected
	}

	// Save the cancel function.
	tracker.cancelFunc[taskid] = cancel

	// Return the context so it can be passed to the plugin runner.
	return 2 // means accepted
}

// Call this method when an unhandled task cancellation request arrives.
func (tracker *CancelTracker) CancelTaskIfRunning(taskid string) bool {
	tracker.Lock()
	defer tracker.Unlock()

	// If the task is currently running, call the cancel() function and forget it.
	// Return true to indicate the task cancellation request has been handled.
	if cancel, ok := tracker.cancelFunc[taskid]; ok {
		cancel()
		delete(tracker.cancelFunc, taskid)
		return true
	}

	// Get the current time.
	now := time.Now()

	// Take this opportunity to forget old task IDs.
	tracker.checkForExpiredCancellations()

	// If we see this task ID in the future, we will reject it.
	tracker.rejectTasks[taskid] = now.Add(tracker.holdDuration)

	// Return false to indicate the cancellation request has NOT been handled.
	return false
}

// Called internally to check for expired task IDs.
func (tracker *CancelTracker) checkForExpiredCancellations() {
	now := time.Now()
	tasksToForget := []string{}
	for taskid, limit := range tracker.rejectTasks {
		delta := limit.Sub(now)
		if delta <= 0 {
			tasksToForget = append(tasksToForget, taskid)
		}
	}
	for _, taskid := range tasksToForget {
		delete(tracker.rejectTasks, taskid)
	}
}

// Call this method when an handled task cancellation request arrives.
func (tracker *CancelTracker) ForgetTask(taskid string) {
	tracker.Lock()
	defer tracker.Unlock()

	// We shouldn't have this task since this message came from another worker,
	// but just in case...
	if cancel, ok := tracker.cancelFunc[taskid]; ok {
		cancel()
		delete(tracker.cancelFunc, taskid)
	}

	// Forget the task ID.
	delete(tracker.rejectTasks, taskid)
}

// Call this method when cancelling all tasks because the worker is shutting down.
func (tracker *CancelTracker) CancelAllTasks() []string {
	tracker.Lock()
	defer tracker.Unlock()

	// Call all of the cancel functions and keep the task IDs.
	canceledTasks := []string{}
	for taskid, cancel := range tracker.cancelFunc {
		cancel()
		canceledTasks = append(canceledTasks, taskid)
	}

	// Return the canceled task IDs.
	return canceledTasks
}

func main() {
	var wg sync.WaitGroup

	// Load the environment variables.
	g3lib.LoadDotEnvFile()

	// Initialize the logger.
	log.InitLogger()

	// Get the current worker ID.
	// If undefined, this will be chosen at random later on;
	// but it also means we cannot preserve state across invocations.
	workerid, err := g3lib.ResolveInstanceID("G3_WORKER_ID")
	if err != nil {
		log.Critical(err.Error())
		os.Exit(1)
	}

	// Find out how long we need to hold on to cancellation requests.
	holdCancelStr := os.Getenv(G3_HOLD_CANCEL)
	if holdCancelStr == "" {
		holdCancelStr = G3_HOLD_CANCEL_DEFAULT
	}
	holdCancel, err := time.ParseDuration(holdCancelStr)
	if err != nil {
		log.Critical(err)
		os.Exit(1)
	}
	if holdCancel < 0 {
		log.Critical("Cannot have a negative hold time in " + G3_HOLD_CANCEL)
		os.Exit(1)
	}
	log.Debug("Holding on to cancellation request messages for " + holdCancel.String())

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

	// Cancellation tracker for the worker.
	cancelTracker := NewCancelTracker(workerid, holdCancel)
	cancelTracker.LoadState()
	defer cancelTracker.SaveState()

	// Create the cancellation context for the worker.
	// Inspired by: https://pace.dev/blog/2020/02/17/repond-to-ctrl-c-interrupt-signals-gracefully-with-context-in-golang-by-mat-ryer.html
	cancelled := false
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()
	wg.Add(1)
	go func() {
		select {
		case <-signalChan: // first signal, cancel context
			log.Critical("\nSIGINT received!")
			cancelled = true
			cancelTracker.CancelAllTasks()
			cancel()
			wg.Done()
		case <-ctx.Done():
			cancelled = true
			cancelTracker.CancelAllTasks()
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()

	// Load the plugins.
	// TODO maybe do this every time we launch a scan?
	plugins := g3lib.LoadPlugins()
	if len(plugins) == 0 {
		log.Critical("No plugins found!")
		os.Exit(1)
	}
	log.Infof("Loaded %d plugins.", len(plugins))

	// Get the enabled plugins for this worker.
	// If the list begins with ! then it's a denylist, not an allowlist.
	var selected []string
	workerPluginsList := strings.TrimSpace(os.Getenv(G3_WORKER_PLUGINS))
	if workerPluginsList == "" {
		selected = slices.Sorted(maps.Keys(plugins))
	} else if workerPluginsList[0:1] != "!" { // allowlist
		selected = strings.Fields(strings.ReplaceAll(workerPluginsList, ",", " "))
		for _, name := range selected {
			if _, ok := plugins[name]; !ok {
				log.Critical("Missing plugin: " + name)
				os.Exit(1)
			}
		}
	} else { // denylist
		workerPluginsList = workerPluginsList[1:]
		denylist := strings.Fields(strings.ReplaceAll(workerPluginsList, ",", " "))
		for _, name := range denylist {
			if _, ok := plugins[name]; !ok {
				log.Critical("Unknown plugin: " + name)
				os.Exit(1)
			}
		}
		for name := range plugins {
			found := false
			for _, rejected := range denylist {
				if name == rejected {
					found = true
					break
				}
			}
			if !found {
				selected = append(selected, name)
			}
		}
	}
	if len(selected) == 0 {
		log.Critical("No plugins selected!")
		os.Exit(1)
	}
	log.Infof("Selected %d plugins.", len(selected))

	// Subset of selected plugins that declare a reporter phase. Used to subscribe
	// to report/<name> topics in addition to the existing tool/<name> subscriptions.
	var reporterSelected []string
	for _, name := range selected {
		if plugin, ok := plugins[name]; ok && plugin.Reporter != nil {
			reporterSelected = append(reporterSelected, name)
		}
	}

	// Connect to the Mongo database.
	mdb_client, err := g3lib.ConnectToDatastore()
	if err != nil {
		log.Critical(err)
		os.Exit(1)
	}
	defer func() {
		g3lib.DisconnectFromDatastore(mdb_client)
		log.Debug("Disconnected from MongoDB.")
	}()
	log.Debug("Connected to MongoDB.")

	// Connect to the SQL database.
	sql_db, err := g3lib.ConnectToSQL()
	if err != nil {
		log.Critical(err)
		os.Exit(1)
	}
	defer func() {
		sql_db.Close()
		log.Debug("Disconnected from SQL database.")
	}()
	log.Debug("Connected to SQL database.")

	// Connect to the Mosquitto broker.
	mq_client, err := g3lib.ConnectToBroker(workerid)
	if err != nil {
		log.Critical(err)
		os.Exit(1)
	}
	defer func() {
		g3lib.DisconnectFromBroker(mq_client)
		log.Debug("Disconnected from Mosquitto.")
	}()
	log.Debug("Connected to Mosquitto.")
	log.Info("Worker ID: " + g3lib.GetClientID(mq_client))

	// Launch a goroutine to process cancellation requests.
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Reconnect to the broker using a different client object.
		// This is done to avoid cancel messages being drowned by new task messages.
		// We cannot use the main client ID so we create a new one.
		workercancelid := ""
		if workerid != "" {
			workercancelid = workerid + "-cancel"
		}
		mq_client, err := g3lib.ConnectToBroker(workercancelid)
		if err != nil {
			log.Critical("Internal error: " + err.Error())
			cancel()
			return
		}
		defer g3lib.DisconnectFromBroker(mq_client)

		// Subscript to the topic for task cancellation.
		// Cancel requests are sent on broadcast to all workers,
		// since we don't know which one picked up our task.
		// When a worker does handle the request, it notifies the others.
		topic := g3lib.SubscribeToCancel(mq_client, func(client g3lib.MessageQueueClient, cancelRequest g3lib.G3CancelTask) {
			if cancelRequest.Handled && cancelRequest.SenderID != g3lib.GetClientID(client) {
				log.Debugf("Received notification of %d tasks handled by another worker.", len(cancelRequest.Tasks))
				for _, taskid := range cancelRequest.Tasks {
					cancelTracker.ForgetTask(taskid)
				}
			} else {
				log.Debugf("Received notification of %d tasks being cancelled.", len(cancelRequest.Tasks))
				canceled := []string{}
				for _, taskid := range cancelRequest.Tasks {
					if cancelTracker.CancelTaskIfRunning(taskid) {
						err := g3lib.SendEmptyResponse(mq_client, cancelRequest.ScanID, taskid)
						if err != nil {
							log.Error(err.Error())
						}
						canceled = append(canceled, taskid)
						log.Noticef("Cancelled task %s for scan %s", taskid, cancelRequest.ScanID)
					}
				}
				err = g3lib.SendTaskCancelHandled(mq_client, cancelRequest.ScanID, canceled)
				if err != nil {
					log.Error(err.Error())
				}
			}
		})
		defer g3lib.Unsubscribe(mq_client, topic)

		// Wait for the worker to be shut down.
		<-ctx.Done()

		// Wait for one second before quitting, to give paho time to finish sending messages.
		time.Sleep(time.Second)
	}()

	// markTerminal writes the per-task terminal state and emits the
	// [g3:done] audit log line. Called from every task-termination site below.
	markTerminal := func(scanid, taskid, status, errMsg string) {
		msg := "[g3:done] task="+taskid+" status="+status
		if errMsg != "" {
			msg += " error="+errMsg
			log.Error(errMsg)
		}
		if err := sql_db.SaveLogLine(scanid, taskid, msg); err != nil {
			log.Error("SaveLogLine (markTerminal) failed: " + err.Error())
		}
		if err := sql_db.UpdateTaskStatus(taskid, &status, nil, nil); err != nil {
			log.Error("UpdateTaskStatus (markTerminal) failed: " + err.Error())
		}
	}

	// Subscribe to the topics for the plugins we support.
	topics := g3lib.SubscribeAsWorker(mq_client, selected, func(client g3lib.MessageQueueClient, task g3lib.G3Task) {

		if cancelled {
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "canceled", "")
			return
		}

		// Prepare a cancel context for the plugin.
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)

		// Determine how to handle the new task request.
		switch cancelTracker.AddTaskIfNew(task.TaskID, cancel) {

		// The task is currently running. We can ignore this request.
		case 0:
			log.Notice("Duplicated new task request for ID: " + task.TaskID)
			return

		// The task has been rejected. Notify the other workers.
		// This branch fires when the task was cancelled before this worker picked
		// it up (CancelTracker.rejectTasks held it). State transitions to CANCELED.
		case 1:
			log.Debug("Rejected task ID: " + task.TaskID)
			err := g3lib.SendTaskCancelHandled(mq_client, task.ScanID, []string{task.TaskID})
			if err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "canceled", "")
			return

		// The task has been accepted. We can continue.
		case 2:
			log.Debug("Received new task:\n" + g3lib.PrettyPrintJSON(task))
			if err := sql_db.SaveLogLine(task.ScanID, task.TaskID, "[g3:start] task="+task.TaskID+" worker="+workerid); err != nil {
				log.Error("SaveLogLine (start) failed: " + err.Error())
			}
			if err := sql_db.UpdateTaskStatus(task.TaskID, g3.STATUS_RUNNING, &task.Tool, &workerid); err != nil {
				log.Error("UpdateTaskStatus (start) failed: " + err.Error())
			}

		// This should not happen.
		default:
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "INTERNAL ERROR")
			return
		}

		// Make sure the plugin is one of our selected plugins.
		// This should not fail.
		if !slices.Contains(selected, task.Tool) {
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "Tool is not supported by this worker: " + task.Tool)
			return
		}

		// Get the plugin for the tool we are going to run.
		// This should not fail.
		plugin, ok := plugins[task.Tool]
		if !ok {
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "Tool is not supported by this worker: " + task.Tool)
			return
		}
		if len(plugin.Commands) <= task.Index {
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", fmt.Sprintf("Tool does not have command #%d", task.Index))
			return
		}

		// Fetch the G3 object from the database.
		data, err := g3lib.LoadOne(mdb_client, task.ScanID, task.DataID)
		if err != nil {
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "Error fetching data object: " + task.DataID)
			return
		}

		// Calculate the command that's going to be run.
		parsed, buildErrs := g3lib.BuildToolCommand(plugin, task.Index, data)
		if len(buildErrs) > 0 {
			log.Errorf("Error executing plugin %s:", plugin.Name)
			for i, err := range buildErrs {
				log.Errorf("%d) %s", i, err.Error())
			}
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "Tool " + plugin.Name + " failed to run.")
			return
		}

		// Run the plugin and send the log lines to the SQL database.
		r, w := io.Pipe()
		defer r.Close()
		defer w.Close()
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader := bufio.NewReader(r)
			for {
				line, err := read(reader)
				text := string(line)
				if err == nil || text != "" {
					err := sql_db.SaveLogLine(task.ScanID, task.TaskID, text)
					if err != nil {
						log.Error(err.Error())
						return
					}
				}
				if err != nil {
					if err == io.EOF {
						break
					}
					if err.Error() != "io: read/write on closed pipe" {
						log.Error(err.Error())
					}
					return
				}
			}
		}()

		// Materialize this task's artifact slot and bind-mount it into the
		// plugin container as /artifacts. The plugin sees only its own slot —
		// the scanid/taskid layout above it is invisible and unreachable.
		slotDir := filepath.Join(artifactsRoot, task.ScanID, task.TaskID)
		if err := os.MkdirAll(slotDir, 0o755); err != nil {
			log.Error("Cannot create artifact slot " + slotDir + ": " + err.Error())
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "Cannot create artifact slot for task")
			return
		}
		hostSlotDir := filepath.Join(artifactsHostRoot, task.ScanID, task.TaskID)

		log.Info("Running plugin: " + task.Tool)
		pluginStartTS := time.Now().Unix()
		outputArray, err := g3lib.RunPluginCommand(ctx, plugin, parsed, data, hostSlotDir, w)
		pluginEndTS := time.Now().Unix()
		if err != nil {
			log.Errorf("Plugin failed to run, reason: %v", err)
		} else {
			log.Info("Plugin finished running.")
		}

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
			markTerminal(task.ScanID, task.TaskID, "error", "Cannot enumerate artifact slot")
			return
		}

		// Validate plugin output; drop invalid objects, mirroring each reject
		// into the user-visible task log as a [g3:warn] line (tagged by tool so
		// a user can grep one tool's warnings across tasks).
		sanitizedOutput := []g3.Data{}
		for _, d := range outputArray {
			verr := d.Validate()
			if verr != nil {
				log.Error("Malformed output data: " + verr.Error() + "\n" + d.String())
				if e := sql_db.SaveLogLine(task.ScanID, task.TaskID,
					"[g3:warn] tool="+task.Tool+" dropped malformed object: "+ verr.Error()); e != nil {
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
		actionable := []g3.Data{}
		nils := []g3.Data{}
		for _, d := range sanitizedOutput {
			if t, _ := d["_type"].(string); t == "nil" {
				nils = append(nils, d)
			} else {
				actionable = append(actionable, d)
			}
		}

		// Objects that make artifact claims: every actionable object, plus any
		// nil placeholder that nonetheless carries an _artifacts field. A pure
		// artifact-producing tool (e.g. nikto) returns nil for pipeline purposes
		// — it adds no fuel — but still owns the files it dropped into its slot,
		// so those are claimed (validated + recorded in the manifest's work[]),
		// not treated as orphans. Fuel/persistence below still keys off
		// actionable alone; a nil stays a nil for the scanner.
		claimants := make([]g3.Data, 0, len(actionable)+len(nils))
		claimants = append(claimants, actionable...)
		for _, d := range nils {
			if _, ok := d["_artifacts"]; ok {
				claimants = append(claimants, d)
			}
		}

		var toPersist []g3.Data
		switch {
		case len(actionable) > 0:
			toPersist = actionable
		case len(nils) > 0:
			toPersist = nils
		}

		// Artifact-claim validation runs over the claimants (actionable objects
		// plus artifact-bearing nils). A violation is a hard contract breach →
		// ERROR, but the data still flows to the scanner below (state ≠ fuel).
		var claimErr error
		if !canceled {
			claimErr = g3lib.ValidateArtifactClaims(claimants, manifestFiles)
		}

		// Compute the terminal verdict. State and fuel are decoupled (see spec).
		softSignal := err != nil || droppedCount > 0
		var state string
		switch {
		case canceled:
			state = "canceled"
		case claimErr != nil:
			state = "error" // hard contract breach
		case softSignal && len(actionable) == 0:
			state = "error" // signal, no fuel
		case softSignal:
			state = "warning" // signal, fuel present
		default:
			state = "done"
		}

		// Write the manifest; exit_status mirrors the verdict.
		manifestWriteErr := g3lib.WriteManifest(slotDir, g3.Manifest{
			ScanID:     task.ScanID,
			TaskID:     task.TaskID,
			Plugin:     plugin.Name,
			Tool:       g3lib.ManifestTool(actionable, plugin),
			ExitStatus: manifestExitStatus(state, claimErr),
			StartedAt:  pluginStartTS,
			EndedAt:    pluginEndTS,
			Files:      manifestFiles,
			Work:       g3lib.BuildManifestWork(claimants),
		})
		if manifestWriteErr != nil {
			log.Error("Cannot write task manifest for " + task.TaskID + ": " + manifestWriteErr.Error())
			state = "error" // a task without a written manifest is incomplete
		}

		// FUEL (state-independent): persist + send for every non-canceled task.
		// Seeds the cache (including ERROR); the pipeline advances if actionable
		// data was produced — the scanner skips nils.
		//
		// Orchestrated scans follow this convention: an object that already carries
		// an _id is an existing DB object re-emitted to indicate it must persist as
		// input for the next step in the pipeline; an object without an _id is a new
		// one, which needs to be persisted in the database in addition to making it
		// to the next step; an input object not re-emitted is thus dropped from the
		// pipeline intentionally.
		//
		// Managed scans are trickier - there is no scanner to read the response from
		// the task, so the list of object IDs is lost. This will be fixed soon. For
		// now, the managed scan's response is partially reconstructed from db queries,
		// so re-emitted objects are dropped - a known gap.
		newobjs := make([]g3.Data, 0, len(toPersist))
		for _, d := range toPersist {
			if _, ok := d["_id"]; !ok {
				newobjs = append(newobjs, d)
			}
		}
		if len(newobjs) > 0 {
			if _, e := g3lib.SaveData(mdb_client, task.ScanID, task.TaskID, newobjs); e != nil {
				log.Error("Error saving data to MongoDB: " + e.Error())
			}
		}
		persistentOutput := []g3.Data{}
		for _, d := range toPersist {
			if _, ok := d["_id"]; ok {
				persistentOutput = append(persistentOutput, d)
			}
		}

		// One summary [g3:warn] line for WARNING/ERROR (the authoritative verdict
		// is the [g3:done] state=... marker written by markTerminal below).
		if state == "warning" || state == "error" {
			if summary := warnSummary(err, droppedCount, claimErr); summary != "" {
				if e := sql_db.SaveLogLine(task.ScanID, task.TaskID,
					"[g3:warn] tool="+task.Tool+" "+summary); e != nil {
					log.Error(e.Error())
				}
			}
		}

		if len(persistentOutput) > 0 {
			if _, e := g3lib.SendResponse(client, task, persistentOutput); e != nil {
				log.Error("Error sending response to the broker: " + e.Error())
			}
		} else {
			if e := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); e != nil {
				log.Error(e.Error())
			}
		}
		markTerminal(task.ScanID, task.TaskID, state, "")
	})

	reporterTopics := g3lib.SubscribeAsReporter(mq_client, reporterSelected, func(client g3lib.MessageQueueClient, task g3lib.G3ReportTask) {

		// SIGINT drain: matches the tool handler's first guard.
		if cancelled {
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "canceled", "")
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
			if err := g3lib.SendTaskCancelHandled(mq_client, task.ScanID, []string{task.TaskID}); err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "canceled", "")
			return
		case 2:
			log.Debug("Received new report task:\n" + g3lib.PrettyPrintJSON(task))
			if err := sql_db.SaveLogLine(task.ScanID, task.TaskID, "[g3:start] task="+task.TaskID+" tool="+task.Tool+" worker="+workerid); err != nil {
				log.Error("SaveLogLine (report start) failed: " + err.Error())
			}
			if err := sql_db.UpdateTaskStatus(task.TaskID, g3.STATUS_RUNNING, &task.Tool, &workerid); err != nil {
				log.Error("UpdateTaskStatus (report start) failed: " + err.Error())
			}
		default:
			log.Error("internal error")
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "internal error")
			return
		}

		// Resolve the plugin and confirm it implements a reporter.
		plugin, ok := plugins[task.Tool]
		if !ok || plugin.Reporter == nil {
			log.Error("Report task for unknown or non-reporter plugin: " + task.Tool)
			if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
				log.Error(err.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "plugin not found or not a reporter")
			return
		}

		// Materialize the per-task output slot.
		outSlot := filepath.Join(artifactsRoot, task.ScanID, task.TaskID)
		hostOut := filepath.Join(artifactsHostRoot, task.ScanID, task.TaskID)
		hostIn := filepath.Join(artifactsHostRoot, task.ScanID)
		if err := os.MkdirAll(outSlot, 0o755); err != nil {
			log.Error("Cannot create reporter slot " + outSlot + ": " + err.Error())
			if e := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); e != nil {
				log.Error(e.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "cannot create reporter slot")
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
			_ = sql_db.SaveLogLine(task.ScanID, task.TaskID, msg)
			if e := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); e != nil {
				log.Error(e.Error())
			}
			markTerminal(task.ScanID, task.TaskID, "error", "reporter command build failed")
			return
		}

		// Open the JSONL stdin stream and dispatch the container.
		stdin := g3lib.ReporterStdinStream(mdb_client, task.ScanID)
		defer stdin.Close() //nolint:errcheck
		logWriter := &reporterLogWriter{sql: sql_db, scanid: task.ScanID, taskid: task.TaskID}
		runErr := g3lib.RunPluginReporter(ctx, plugin, parsed, hostIn, hostOut, stdin, logWriter)

		// Remove the cancel context; mirror the tool handler exactly.
		cancelTracker.ForgetTask(task.TaskID)
		if e := g3lib.SendTaskCancelHandled(mq_client, task.ScanID, []string{task.TaskID}); e != nil {
			log.Error(e.Error())
		}

		// Decide terminal state and notify.
		terminal := "done"
		terminalMsg := ""
		if runErr != nil {
			if errors.Is(runErr, context.Canceled) {
				terminal = "canceled"
			} else {
				terminal = "error"
				terminalMsg = runErr.Error()
			}
		}
		if err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID); err != nil {
			log.Error("SendEmptyResponse (report) failed: " + err.Error())
		}
		markTerminal(task.ScanID, task.TaskID, terminal, terminalMsg)
	})
	topics = append(topics, reporterTopics...)
	defer g3lib.Unsubscribe(mq_client, topics...)

	// Listen for incoming tasks until we get a SIGINT.
	log.Info("Waiting for incoming tasks...")
	wg.Wait()
	log.Info("Quitting...")
}

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

// reporterLogWriter routes the reporter container's stdout/stderr to
// SaveLogLine, one line at a time. Partial trailing lines are buffered
// until the next Write; if the container exits without a trailing newline,
// the last partial fragment is lost (acceptable — partial trailing output is
// cosmetic; the terminal state is determined by the container exit code).
type reporterLogWriter struct {
	sql    g3lib.SQLDBClient
	scanid string
	taskid string
	mu     sync.Mutex
	buf    []byte
}

func (w *reporterLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
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
			if err := w.sql.SaveLogLine(w.scanid, w.taskid, line); err != nil {
				log.Error("SaveLogLine (report stream) failed: " + err.Error())
			}
		}
	}
	return len(p), nil
}
