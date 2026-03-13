package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)

// Environment variable with the client ID for this worker.
const G3_WORKER_ID = "G3_WORKER_ID"

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
	stateFile string
	holdDuration time.Duration
	rejectTasks map[string]time.Time			// Task ID -> time to hold
	cancelFunc map[string]context.CancelFunc	// Task ID -> cancel()
}

func NewCancelTracker(workerid string, duration time.Duration) *CancelTracker {
	stateFile := ""
	if workerid != "" {
		stateFile = filepath.Join(g3lib.GetHomeDirectory(), g3lib.G3CONFIG, workerid + "-state.json")
	}
	return &CancelTracker{
		stateFile: stateFile,
		holdDuration: duration,
		rejectTasks: make(map[string]time.Time),
		cancelFunc: make(map[string]context.CancelFunc),
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
		duration, err :=time.ParseDuration(durationStr)
		if err != nil {
			log.Errorf("Error parsing file %s: %s", tracker.stateFile, err.Error())
			duration, err = time.ParseDuration(G3_HOLD_CANCEL_DEFAULT)
			if err != nil {
				panic(err)		// should not happen in production
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
		return 0		// means ignore
	}

	// Reject the task if it's pending cancellation.
	if _, ok := tracker.rejectTasks[taskid]; ok {
		delete(tracker.rejectTasks, taskid)
		return 1		// means rejected
	}

	// Save the cancel function.
	tracker.cancelFunc[taskid] = cancel

	// Return the context so it can be passed to the plugin runner.
	return 2			// means accepted
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
	for taskid, cancel := range tracker.cancelFunc{
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
	workerid := os.Getenv(G3_WORKER_ID)

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
			log.Critical("\nSIGTERM received!")
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
		selected = maps.Keys(plugins)
	} else if workerPluginsList[0:1] != "!" {			// allowlist
		selected = strings.Fields(strings.Replace(workerPluginsList, ",", " ", -1))
		for _, name := range selected {
			if _, ok := plugins[name]; !ok {
				log.Critical("Missing plugin: " + name)
				os.Exit(1)
			}
		}
	} else {											// denylist
		workerPluginsList = workerPluginsList[1:]
		denylist := strings.Fields(strings.Replace(workerPluginsList, ",", " ", -1))
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
		g3lib.DisconnectFromSQL(sql_db)
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
		topic := g3lib.SubscribeToCancel(mq_client, func (client g3lib.MessageQueueClient, cancelRequest g3lib.G3CancelTask) {
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

	// Subscribe to the topics for the plugins we support.
	topics := g3lib.SubscribeAsWorker(mq_client, selected, func (client g3lib.MessageQueueClient, task g3lib.G3Task) {

		// If we received SIGTERM, just drop incoming messages.
		if cancelled {
			g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
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
		case 1:
			log.Debug("Rejected task ID: " + task.TaskID)
			err := g3lib.SendTaskCancelHandled(mq_client, task.ScanID, []string{task.TaskID})
			if err != nil {
				log.Error(err.Error())
			}
			return

		// The task has been accepted. We can continue.
		case 2:
			log.Debug("Received new task:\n" + g3lib.PrettyPrintJSON(task))

		// This should not happen.
		default:
			log.Error("internal error")
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			return
		}

		// Make sure the plugin is one of our selected plugins.
		// This should not fail.
		if !slices.Contains(selected, task.Tool) {
			log.Error("Tool is not supported by this worker: " + task.Tool)
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			return
		}

		// Get the plugin for the tool we are going to run.
		plugin, ok := plugins[task.Tool]
		if !ok {
			log.Error("Tool is not supported by this worker: " + task.Tool)
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			return
		}
		if len(plugin.Commands) <= task.Index {
			log.Errorf("Tool does not have command #%d", task.Index)
			g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			return
		}

		// Fetch the G3 object from the database.
		data, err := g3lib.LoadOne(mdb_client, task.ScanID, task.DataID)
		if err != nil {
			log.Error("Error fetching data object: " + err.Error())
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			return
		}

		// Calculate the command that's going to be run.
		parsed, errors := g3lib.BuildToolCommand(plugin, task.Index, data)
		if len(errors) > 0 {
			log.Errorf("Error executing plugin %s:", plugin.Name)
			for i, err := range errors {
				log.Errorf("%d) %s", i, err.Error())
			}
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			return
		}

		// Run the plugin and send the log lines to the SQL database.
		// text := fmt.Sprintf("Task %s started at %s", task.TaskID, time.Now().Format(time.RFC850))
		// err = g3lib.SaveLogLine(sql_db, task.ScanID, task.TaskID, text)
		// if err != nil {
		// 	log.Error(err.Error())
		// }
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
					err := g3lib.SaveLogLine(sql_db, task.ScanID, task.TaskID, text)
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
		log.Info("Running plugin: " + task.Tool)
		outputArray, err := g3lib.RunPluginCommand(ctx, plugin, parsed, data, w)

		// Remove the cancel context.
		cancelTracker.ForgetTask(task.TaskID)
		e := g3lib.SendTaskCancelHandled(mq_client, task.ScanID, []string{task.TaskID})
		if e != nil {
			log.Error(e.Error())
		}

		// Detect errors when executing the plugin.
		if err != nil {
			log.Error("Error executing plugin " + plugin.Name + ": " + err.Error())
			err := g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			return
		}

		// If we received SIGTERM, drop the output.
		if cancelled {
			err = g3lib.SendEmptyResponse(mq_client, task.ScanID, task.TaskID)
			if err != nil {
				log.Error(err.Error())
			}
			return
		}

		// Validate the plugin output. Drop any objects that don't pass the test.
		sanitizedOutput := []g3lib.G3Data{}
		for _, data := range outputArray {
			if ok, err := g3lib.IsValidData(data); !ok {
				if err != nil {
					log.Error("Malformed output data: " + err.Error() + "\n" + data.String())
				} else {
					log.Error("Malformed output data:\n" + data.String())
				}
			} else {
				sanitizedOutput = append(sanitizedOutput, data)
			}
		}

		// Save the G3 objects into the database.
		if len(sanitizedOutput) > 0 {
			_, err = g3lib.SaveData(mdb_client, task.ScanID, task.TaskID, sanitizedOutput)
			if err != nil {
				log.Error("Error saving data to MongoDB: " + err.Error())
			}
		}

		// Send the response.
		persistentOutput := []g3lib.G3Data{}
		for _, data := range sanitizedOutput {
			if _, ok := data["_id"]; ok {
				persistentOutput = append(persistentOutput, data)
			}
		}
		_, err = g3lib.SendResponse(client, task, persistentOutput)
		if err != nil {
			log.Error("Error sending response to the broker: " + err.Error())
		}
	})
	defer g3lib.Unsubscribe(mq_client, topics...)

	// Listen for incoming tasks until we get a SIGTERM.
	log.Info("Waiting for incoming tasks...")
	wg.Wait()
	log.Info("Quitting...")
}
