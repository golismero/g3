package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/golismero/g3/src/g3lib"
	log "github.com/golismero/g3/src/g3/log"
	"github.com/golismero/g3/src/g3"
)

// Environment variables with the scanner configuration.
const G3_SCANNER_PARALLEL_MODE = "G3_SCANNER_PARALLEL_MODE" // Set this always to true unless you've got concurrency issues and are desperate.
const G3_SCANNER_MAX_PIPELINES = "G3_SCANNER_MAX_PIPELINES" // Defaults to 0 for no limit (danger!) or set to a reasonable value like, say, 20.
const G3_SCANNER_MAX_DEPTH = "G3_SCANNER_MAX_DEPTH"         // Defaults to 0 for no limit (danger!) or set to a reasonable value like, say, 20.

// This structure preserves the state of a single pipeline. Stored in an array.
type PipelineState struct {
	StepIndex    int               // Current step in the pipeline.
	CommandIndex int               // Current subcommand in the plugin.
	PendingTasks g3.StringSet // Task IDs we are waiting for in this step. Could be from another pipeline.
	CurrentData  g3.StringSet // Currently held data in the pipeline that's been saved to the database.
	NewData      g3.StringSet // Data being collected in this step that's been saved to the database.
}

// This structure correlates the pending task IDs and the fingerprints for the data we are waiting for.
type FPToPendingTasks map[string]g3.StringSet

func (pending FPToPendingTasks) Add(taskid string, fingerprint []string) {
	for _, fp := range fingerprint {
		if _, ok := pending[fp]; !ok {
			pending[fp] = make(g3.StringSet)
		}
		pending[fp].Add(taskid)
	}
}
func (pending FPToPendingTasks) Find(fingerprint []string) []string {
	found := make(g3.StringSet)
	for _, fp := range fingerprint {
		if pending, ok := pending[fp]; ok && len(pending) > 0 {
			found.AddMulti(pending.ToArray())
		}
	}
	return found.ToArray()
}
func (pending FPToPendingTasks) Remove(taskid string) {
	for fp := range pending {
		if tasklist, ok := pending[fp]; ok && tasklist.Exists(taskid) {
			tasklist.Delete(taskid)
		}
	}
}

// Global variables for the current scan information.
var currentScanID = ""
var runningTasks *g3.SyncStringSet

func main() {
	var wg sync.WaitGroup

	runningTasks = g3.NewSyncStringSet()

	// Load the environment variables.
	g3lib.LoadDotEnvFile()

	// Initialize the logger.
	log.InitLogger()

	// Create the cancellation context for the scanner.
	// Inspired by: https://pace.dev/blog/2020/02/17/repond-to-ctrl-c-interrupt-signals-gracefully-with-context-in-golang-by-mat-ryer.html
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
			cancel()
			wg.Done()
		case <-ctx.Done():
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()

	// Load the plugins.
	// TODO maybe do this every time we launch a scan?
	plugins := g3lib.LoadPlugins()
	if len(plugins) == 0 {
		log.Error("No plugins found!")
		os.Exit(1)
	}
	log.Debugf("Loaded %d plugins.", len(plugins))

	// Resolve the scanner ID.
	scannerID, err := g3lib.ResolveInstanceID("G3_SCANNER_ID")
	if err != nil {
		log.Critical(err.Error())
		os.Exit(1)
	}

	// Get the maximum number of pipelines.
	maxPipelines := 0 // 0 means no limit
	if maxPipelinesStr := os.Getenv(G3_SCANNER_MAX_PIPELINES); maxPipelinesStr != "" {
		if i, err := strconv.Atoi(maxPipelinesStr); err == nil && i >= 0 {
			maxPipelines = i
			if i > 0 {
				log.Debugf("Maximum number of pipelines set to: %d", maxPipelines)
			}
		} else {
			log.Errorf("Invalid value set for %s, ignoring.", G3_SCANNER_MAX_PIPELINES)
		}
	}

	// Get the maximum depth for the pipelines.
	maxPipeDepth := 0 // 0 means no limit
	if maxPipeDepthStr := os.Getenv(G3_SCANNER_MAX_DEPTH); maxPipeDepthStr != "" {
		if i, err := strconv.Atoi(maxPipeDepthStr); err == nil && i >= 0 {
			maxPipeDepth = i
			if i > 0 {
				log.Debugf("Maximum depth for pipelines set to: %d", maxPipeDepth)
			}
		} else {
			log.Errorf("Invalid value set for %s, ignoring.", G3_SCANNER_MAX_DEPTH)
		}
	}

	// Launch the scan runner goroutine.
	scanChannel := make(chan g3lib.G3Scan)
	responseChannel := make(chan g3lib.G3Response)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-scanChannel:
				currentScanID = msg.ScanID
				runningTasks.Clear()
				ScanRunner(responseChannel, plugins, msg, scannerID)
				currentScanID = ""
				runningTasks.Clear()
			}
		}
	}()

	// Connect to the Mosquitto broker.
	mq_client, err := g3lib.ConnectToBroker(scannerID)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	defer func() {
		g3lib.DisconnectFromBroker(mq_client)
		log.Debug("Disconnected from Mosquitto.")
	}()
	log.Debug("Connected to Mosquitto.")
	log.Info("Scanner ID: " + g3lib.GetClientID(mq_client))

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

	// Handle the responses for the tools run by the new scans.
	// We cannot easily subscribe to single scan responses, it's easier to
	// subscribe to all and filter out the ones that do not belong to us.
	topic := g3lib.SubscribeToResponses(mq_client, "#", func(client g3lib.MessageQueueClient, msg g3lib.G3Response) {
		if msg.ScanID == currentScanID {
			responseChannel <- msg
		}
	})
	defer g3lib.Unsubscribe(mq_client, topic)

	// Handle the scan stop requests.
	topic = g3lib.SubscribeToStop(mq_client, func(client g3lib.MessageQueueClient, msg g3lib.G3ScanStop) {

		// Check that we are already running that scan.
		// We can get duplicate stop messages if we have more than one g3scanner,
		// so we are going to log this as only in the debug log.
		// TODO subscribe to a different topic so we don't need to duplicate this one!
		if msg.ScanID != currentScanID {
			log.Debug("Ignoring duplicate scan stop message: " + msg.ScanID)
			return
		}

		// Log the cancel request.
		log.Notice("Canceling scan: " + msg.ScanID)

		// Remove the scan ID to let the scanner goroutine know it must quit.
		currentScanID = ""

		// Emit the [g3:cancel] audit line for each running task before broadcasting
		// the cancel, so the user's intent is captured in the durable log even if
		// the MQTT publish fails. No Redis write here — per-task state stays
		// RUNNING (or DISPATCHED) until the worker transitions it to the terminal
		// state on plugin exit. The UI signals "winding down" from the combination
		// (scan.Status == CANCELED, task.state == RUNNING|DISPATCHED).
		runningTasksSnapshot := runningTasks.ToArray()
		for _, taskid := range runningTasksSnapshot {
			if err := g3lib.SaveLogLine(sql_db, msg.ScanID, taskid, "[g3:cancel] task="+taskid); err != nil {
				log.Error("SaveLogLine (cancel) failed: " + err.Error())
			}
		}

		// Cancel all of the running tasks.
		if err := g3lib.SendTaskCancel(mq_client, msg.ScanID, runningTasksSnapshot); err != nil {
			log.Error(err.Error())
		}

		// Send a fake response to wake up the scanner goroutine.
		var m g3lib.G3Response
		m.MessageType = g3lib.MSG_RESPONSE
		responseChannel <- m
	})
	defer g3lib.Unsubscribe(mq_client, topic)

	// Handle incoming new scan requests.
	topic = g3lib.SubscribeAsScanner(mq_client, func(client g3lib.MessageQueueClient, msg g3lib.G3Scan) {

		// Check that we aren't already running that scan.
		// Note that this is just a very basic sanity check,
		// not an actual guarantee that you can't run the same
		// scan twice at the same time if g3api messes up.
		if msg.ScanID == currentScanID {
			log.Error("Ignoring duplicate scan start message: " + msg.ScanID)
			return
		}

		// Check the execution mode is supported.
		if msg.Mode != "parallel" && msg.Mode != "sequential" {
			log.Error("Unsupported execution mode: " + msg.Mode)
			if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "Unsupported execution mode"); err != nil {
				log.Error(err.Error())
			}
			return
		}

		// Check the script doesn't go over the maximum number of pipelines, if any was set.
		if maxPipelines > 0 && len(msg.Pipelines) > maxPipelines {
			log.Errorf("Got script with %d pipelines but we can only run up to %d, aborted.", len(msg.Pipelines), maxPipelines)
			if err := g3lib.SendScanFailed(mq_client, msg.ScanID, fmt.Sprintf("Too many pipelines in script (>%d)", maxPipelines)); err != nil {
				log.Error(err.Error())
			}
			return
		}

		// Check the script doesn't go over the maximum pipeline depth, if any was set.
		if maxPipeDepth > 0 {
			for _, pipeline := range msg.Pipelines {
				if len(pipeline) > maxPipeDepth {
					log.Errorf("Got script with a pipeline that's %d commands deep, but we can only run up to %d, aborted.", len(pipeline), maxPipeDepth)
					if err := g3lib.SendScanFailed(mq_client, msg.ScanID, fmt.Sprintf("Pipeline too deep in script (%d)", len(pipeline))); err != nil {
						log.Error(err.Error())
					}
					return
				}
			}
		}

		// Send the new task to the task runner.
		scanChannel <- msg
	})
	defer g3lib.Unsubscribe(mq_client, topic)

	// Subscribe to dispatch messages from g3api. Runs at scanner-process
	// level — handles dispatches for any scan, including terminated scans
	// with no active ScanRunner.
	dispatchTopic := g3lib.SubscribeAsDispatcher(mq_client, func(_ g3lib.MessageQueueClient, msg g3lib.G3Dispatch) {
		dispatchHandler(mq_client, rdb_client, sql_db, plugins, msg)
	})
	_ = dispatchTopic // dispatch subscription lives for the process lifetime; no deferred Unsubscribe needed

	// Wait until we are shut down.
	wg.Wait()
	log.Info("Quitting...")
}

// Handle an incoming scan request.
// This function will be running within a goroutine.
// TODO FIXME: this is a lot of spaghetti, I need to break it down into auxiliary functions...
func ScanRunner(responseChannel chan g3lib.G3Response, plugins g3lib.G3PluginMetadata, msg g3lib.G3Scan, scannerID string) {

	// Log the start and stop of the scan.
	defer log.Info("Finished scan: " + msg.ScanID)
	log.Info("Started scan: " + msg.ScanID)
	if log.LogLevel == "DEBUG" {
		var script g3lib.ParsedScript
		script.Pipelines = msg.Pipelines
		log.Debug("Pipeline script:\n------------------------------\n" + script.String() + "------------------------------")
	}

	// Connect to the Mosquitto broker.
	mq_client, err := g3lib.ConnectToBroker(scannerID + "-" + msg.ScanID)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	defer func() {
		g3lib.DisconnectFromBroker(mq_client)
		log.Debug("Goroutine disconnected from Mosquitto.")
	}()
	log.Debug("Goroutine connected to Mosquitto.")

	// Connect to the Mongo database.
	mdb_client, err := g3lib.ConnectToDatastore()
	if err != nil {
		log.Error(err.Error())
		if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
			log.Error(err.Error())
		}
		return
	}
	defer func() {
		g3lib.DisconnectFromDatastore(mdb_client)
		log.Debug("Goroutine disconnected from MongoDB.")
	}()
	log.Debug("Goroutine connected to MongoDB.")

	// Connect to the Redis database.
	rdb_client, err := g3lib.ConnectToRedis()
	if err != nil {
		log.Error(err.Error())
		if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
			log.Error(err.Error())
		}
		return
	}
	defer func() {
		g3lib.DisconnectFromRedis(rdb_client) //nolint:errcheck
		log.Debug("Goroutine disconnected from Redis.")
	}()
	log.Debug("Goroutine connected to Redis.")

	// Connect to the SQL database for structured audit log lines.
	scan_sql_db, err := g3lib.ConnectToSQL()
	if err != nil {
		log.Error(err.Error())
		if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
			log.Error(err.Error())
		}
		return
	}
	defer func() {
		g3lib.DisconnectFromSQL(scan_sql_db)
		log.Debug("Goroutine disconnected from SQL database.")
	}()
	log.Debug("Goroutine connected to SQL database.")

	// NB: we intentionally do NOT purge Redis task-state keys when the scan
	// ends. They now live until the scan is deleted (the /scan/delete handler
	// calls DeleteTaskStates). Clearing them on terminal used to corrupt the
	// task-status view: once a scan finished and its keys were wiped, a reporter
	// task later dispatched against it (e.g. "view report" in g3tui) would
	// repopulate Redis with just that one task, and the status endpoint's
	// "Redis non-empty wins, else fall back to SQL" rule would then hide all the
	// original tasks. Retaining the keys for the scan's whole lifetime keeps
	// Redis complete, so that rule holds. The SQL log lines remain the durable
	// audit trail and the fallback source if Redis ever loses data
	// (eviction/restart).

	// Calculate the total number of steps in the script.
	// This will be used later to determine the scan progress.
	totalScanSteps := 0
	for _, pipe := range msg.Pipelines {
		totalScanSteps += len(pipe)
	}

	// Notify the scan has started. Pure-import scans (no pipelines)
	// have nothing to track yet — the FINISHED message at the end
	// covers them.
	if totalScanSteps > 0 {
		if err := g3lib.SendScanProgress(mq_client, msg.ScanID, 0, totalScanSteps); err != nil {
			log.Error(err.Error())
		}
	}

	// Load the array of starting data.
	// This would be the targets and any data imported previously.
	startData, err := g3lib.GetScanDataIDs(mdb_client, msg.ScanID)
	if err != nil {
		log.Error(err.Error())
		if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
			log.Error(err.Error())
		}
		return
	}

	// If we have no starting data, there's no way to run any pipelines.
	if len(startData) == 0 {
		log.Error("No targets found for scan, aborting.")
		if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "No targets found for scan"); err != nil {
			log.Error(err.Error())
		}
		return
	}

	// Skip the pipeline execution part if we have no pipelines.
	// This can happen if the scan script consisted entirely of imports.
	if len(msg.Pipelines) == 0 {
		log.Debug("No pipelines to be executed, skipping to reporting phase.")
	} else {

		// Use the requested mode of operation.
		// We have two modes of operation, sequential and parallel.
		// TODO the third mode would be full auto like g2
		parallelMode := false
		if msg.Mode == "parallel" {
			parallelMode = true
		} else if msg.Mode != "sequential" {
			if msg.Mode != "" {
				log.Errorf("Unsupported execution mode: %v", msg.Mode)
				if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "Unsupported execution mode"); err != nil {
					log.Error(err.Error())
				}
			}
			parallelMode, err = strconv.ParseBool(os.Getenv(G3_SCANNER_PARALLEL_MODE))
			if err != nil {
				log.Errorf("Invalid value for %s, using sequential mode as default.", G3_SCANNER_PARALLEL_MODE)
				parallelMode = false
			}
		}

		// Parallel mode uses a state machine to track multiple parallel tasks.
		// This is much faster than sequential mode, but can introduce subtle errors in some circumstances.
		if parallelMode {

			// Pipelines will be run in parallel when possible.
			// This means we need to track the state of each pipeline
			// and which task IDs we are waiting on. We also need to
			// know when a task we're about to create is already
			// being waited on in a different, parallel pipeline.
			pipelineState := make([]PipelineState, len(msg.Pipelines))
			fpToTasks := make(FPToPendingTasks)
			for pipeidx := 0; pipeidx < len(pipelineState); pipeidx++ {
				pipelineState[pipeidx].PendingTasks = g3.StringSet{}
				pipelineState[pipeidx].CurrentData = g3.StringSet{}
				pipelineState[pipeidx].NewData = g3.StringSet{}
				pipelineState[pipeidx].CurrentData.AddMulti(startData)
			}

			// Loop until all pipelines are finished.
			pipesAreEmpty := false
			for !pipesAreEmpty {
				log.Debug("Evaluating pipelines...")

				// Check for cancelation.
				if currentScanID == "" {
					log.Debugf("Canceled scan, dropping all the pipelines...")
					if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
						log.Error(err.Error())
					}
					return
				}

				// Go through all pipelines that are not waiting for a task to complete.
				count := 0
				needRedo := false
				for pipeidx := 0; pipeidx < len(msg.Pipelines); pipeidx++ {
					pipeline := &msg.Pipelines[pipeidx]
					state := &pipelineState[pipeidx]
					//log.Debugf("--- pipeidx: %v", pipeidx)
					//log.Debugf("--- pipeline: %v", pipeline)
					//log.Debugf("--- state: %v", state)

					// Check for cancelation.
					if currentScanID == "" {
						log.Debugf("Canceled scan, dropping all the pipelines...")
						if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
							log.Error(err.Error())
						}
						return
					}

					// First check if we are still waiting for a task to complete. Skip if we are.
					if len(state.PendingTasks) > 0 {
						log.Debugf("Pipeline %d is still waiting on %d task(s)...", pipeidx, len(state.PendingTasks))
						continue
					}

					// Next check if we are in the last step.
					// If so, this means this pipeline is finished.
					if state.StepIndex == len(*pipeline) {
						log.Debugf("Pipeline %d is completed.", pipeidx)
						count++
						continue
					}

					// If we don't have any currently held data in the pipeline, it's finished.
					if len(state.CurrentData) == 0 {
						log.Debugf("Pipeline %d has no more data, skipping at step %d.", pipeidx, state.StepIndex)
						count++
						continue
					}

					// Fetch the plugin metadata.
					tool := (*pipeline)[state.StepIndex]
					plugin, ok := plugins[tool]
					if !ok {
						log.Error("Missing plugin: " + tool)
						if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "Missing plugin: "+tool); err != nil {
							log.Error(err.Error())
						}
						return
					}

					// We are in a fresh step of the pipeline.
					// Go through the currently held data and generate all the new tasks.
					for dataid := range state.CurrentData {
						log.Debugf("Pipeline %d: evaluating data %s for tool %s.", pipeidx, dataid, tool)

						// Check for cancelation.
						if currentScanID == "" {
							log.Debugf("Canceled scan, dropping all the pipelines...")
							if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
								log.Error(err.Error())
							}
							return
						}

						// Fetch the data from the database.
						data, err := g3lib.LoadOne(mdb_client, msg.ScanID, dataid)
						if err != nil {
							log.Error(err.Error())
							if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
								log.Error(err.Error())
							}
							return
						}

						// Skip over dummy objects.
						if dtype, ok := data["_type"]; ok {
							if dtypestr, ok := dtype.(string); ok {
								if dtypestr == "nil" {
									log.Debug("Found nil object, skipped")
									continue
								}
							}
						}

						// Iterate over each subcommand in the plugin.
						for index := 0; index < len(plugin.Commands); index++ {

							// Check for cancelation.
							if currentScanID == "" {
								log.Debugf("Canceled scan, dropping all the pipelines...")
								if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
									log.Error(err.Error())
								}
								return
							}

							// Dynamically evaluate if this plugin accepts this type of data.
							// Skip if it does not apply.
							ok, err := g3lib.EvalToolCondition(plugin, index, data)
							if !ok {
								if err != nil {
									log.Error(err.Error())
									if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
										log.Error(err.Error())
									}
									return
								}
								log.Debugf("Skipped subcommand %d, failed precondition.", index)
								continue
							}

							// Calculate the command that's going to be run.
							// Most importantly, his calculates the fingerprints.
							parsed, errors := g3lib.BuildToolCommand(plugin, index, data)
							if len(errors) > 0 {
								errorMsg := ""
								for _, err := range errors {
									errorMsg = errorMsg + "\n" + err.Error()
								}
								log.Error(errorMsg)
								if err := g3lib.SendScanFailed(mq_client, msg.ScanID, errorMsg); err != nil {
									log.Error(err.Error())
								}
								return
							}

							// Check for the fingerprints of the pending tasks.
							// If any pending tasks match, add them to the wait list
							// instead of calling the plugin.
							pending := fpToTasks.Find(parsed.Fingerprint)
							if len(pending) > 0 {
								state.PendingTasks.AddMulti(pending)
								log.Debugf("Subcommand %d is waiting on tasks...", index)
								continue
							}

							// If we have data in the database matching this fingerprint,
							// use it instead of calling the plugin.
							pastData, err := g3lib.GetFingerprintMatchesIDs(mdb_client, msg.ScanID, parsed.Fingerprint)
							if err != nil {
								log.Error(err.Error())
								if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
									log.Error(err.Error())
								}
								return
							}
							if len(pastData) > 0 {
								log.Debugf("Subcommand %d matched data in database, skipped", index)
								state.NewData.AddMulti(pastData)
								continue
							}

							// Run the plugin command in one of the workers.
							// Generate the taskid up-front so the per-task Redis state and
							// the audit log entry are in place *before* the MQTT publish.
							// Without this ordering, a fast worker can write its RUNNING
							// state before the scanner's DISPATCHED write lands, and the
							// scanner's write then stomps RUNNING back to DISPATCHED.
							taskid := uuid.NewString()
							// Extract the MongoDB id of the input Data. SendTask (via dispatchTask)
							// now takes dataid as a string rather than the full Data — the caller
							// owns the extraction, which makes the worker-bound message shape
							// uniform between script-driven and API-driven dispatch.
							dataid, ok := data["_id"].(string)
							if !ok {
								dispErr := fmt.Errorf("data missing _id, save to database first")
								log.Error(dispErr.Error())
								if e := g3lib.SendScanFailed(mq_client, msg.ScanID, dispErr.Error()); e != nil {
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
							log.Debugf("Subcommand %d will be run!", index)
							log.Debug("New task ID: " + taskid)
							runningTasks.Add(taskid)
							fpToTasks.Add(taskid, parsed.Fingerprint)
							state.PendingTasks.Add(taskid)
						}
					}

					// If we reached this point and we still don't have any pending tasks,
					// move to the next step.
					if len(state.PendingTasks) > 0 {
						log.Debugf("We have pending tasks on pipeline %d, moving on to next pipeline", pipeidx)
						continue
					}
					state.CurrentData = state.NewData
					state.NewData = g3.StringSet{}
					state.StepIndex++
					needRedo = true
					log.Debugf("No pending tasks on pipeline %d, moving on to next step %d", pipeidx, state.StepIndex)
				}

				// If we moved a step in a pipeline, redo the previous loop.
				if needRedo {
					log.Debug("We moved a step further in at least one pipeline, re-evaluate the pipelines")
					continue
				}

				// If all pipelines are finished, we're done!
				if count == len(msg.Pipelines) {
					log.Debug("All pipelines are finished, we are done!")
					break
				}
				if count > len(msg.Pipelines) {
					log.Errorf("Internal error: count == %d but len(msg.Pipelines) == %d", count, len(msg.Pipelines))
					if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "internal error"); err != nil {
						log.Error(err.Error())
					}
					return
				}

				// When we reach this point, all pipelines that are not finished are stuck
				// waiting on one or more pending tasks, so we can only wait for the next
				// completed task. We need to handle scan cancellations here too.

				// Before waiting for tasks to finish, update the progress of the scan.
				currentScanStep := 0
				for _, state := range pipelineState {
					currentScanStep += state.StepIndex
				}
				if err := g3lib.SendScanProgress(mq_client, msg.ScanID, currentScanStep, totalScanSteps); err != nil {
					log.Error(err.Error())
				}

				// Edge case: we are running a scan where no pipelines launched any tasks, globally.
				// TBH I'm not sure how this state is reachable (traced the loops myself a couple times,
				// and Claude did that too, we're both confused) but whatever - it's apparently possible.
				if runningTasks.Length() == 0 {
					countTotalPending := 0
					for pipeidx := 0; pipeidx < len(msg.Pipelines); pipeidx++ {
						countTotalPending += len(pipelineState[pipeidx].PendingTasks)
					}
					if countTotalPending == 0 {
						log.Debug("No pending tasks and all pipelines empty, we are done!")
						pipesAreEmpty = true
						continue
					}
					log.Errorf("Internal error while waiting for tasks!")
					log.Debugf("Pending tasks for scan %s: %v", msg.ScanID, runningTasks.ToArray())
					for pipeidx := 0; pipeidx < len(msg.Pipelines); pipeidx++ {
						log.Debugf("Pending tasks for pipeline %d: %v", pipeidx, pipelineState[pipeidx].PendingTasks)
					}
					if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "internal error"); err != nil {
						log.Error(err.Error())
					}
					return
				}

				// If on debug mode, show the pending tasks.
				if log.LogLevel == "DEBUG" {
					log.Debugf("Pending tasks for scan %s: %v", msg.ScanID, runningTasks.ToArray())
				}

				// Wait for at least one task to complete.
				log.Debug("Waiting for tasks to complete...")
				var response g3lib.G3Response
				for {
					response = <-responseChannel
					if response.TaskID != "" {
						break
					}
					if currentScanID == "" {
						log.Debugf("Canceled scan, dropping all the pipelines...")
						if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
							log.Error(err.Error())
						}
						return
					}
				}

				// We got a task response. For each completed task, add the data IDs to the
				// corresponding pipeline and remove the task IDs from the pending lists.
				// If that pipeline step has no more pending data, move on to the next step.
				// (That last bit may seem redundant, but is needed for plugins that error out).
				taskid := response.TaskID
				if !runningTasks.Exists(taskid) {
					log.Warning("Got a task end notification for a task that is not ours! ID: " + taskid)
				} else {
					// Terminal state (DONE/ERROR/CANCELED) + [g3:done] audit line are
					// written by the worker before it sent this response — no Redis
					// or log-line work for the scanner on this path.
					runningTasks.Delete(taskid)
					log.Debug("Cleaning up task: " + response.TaskID)
					fpToTasks.Remove(taskid)
					for pipeidx := 0; pipeidx < len(pipelineState); pipeidx++ {
						state := &pipelineState[pipeidx]
						if state.PendingTasks.Exists(taskid) {
							log.Debugf("Clearing task from pipeline %d", pipeidx)
							state.PendingTasks.Delete(taskid)
							if len(response.Response) == 0 {
								log.Warningf("Plugin %s has ended with an error condition, check logs", msg.Pipelines[pipeidx][state.StepIndex])
							}
							state.NewData.AddMulti(response.Response)
							if len(state.PendingTasks) == 0 { // last subcommand has ended
								state.CurrentData = state.NewData
								state.NewData = g3.StringSet{}
								state.StepIndex++
								log.Debugf("No pending tasks on pipeline %d, moving on to next step %d", pipeidx, state.StepIndex)
							}
						}
					}
					log.Debug("Finished task: " + response.TaskID)
				}
			}

			// Sequential mode just runs each command in each pipeline one by one.
			// This is considerably slower since we need to wait for each command to finish.
			// It is also a lot less error prone, so it can be useful in some circumstances.
		} else {

			// Run the commands for each pipeline sequentially.
			currentScanStep := 0
			for pipeidx := 0; pipeidx < len(msg.Pipelines); pipeidx++ {
				pipeline := msg.Pipelines[pipeidx]
				log.Debugf("Entering pipeline %d", pipeidx)

				// Check for cancelation.
				if currentScanID == "" {
					log.Debugf("Canceled scan, dropping all the pipelines...")
					if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
						log.Error(err.Error())
					}
					return
				}

				// Pipelines always start with the target/imported data.
				currentData := startData

				// Run the tools in the pipeline.
				for stepidx := 0; stepidx < len(pipeline); stepidx++ {
					currentScanStep++
					tool := pipeline[stepidx]
					log.Debugf("Entering step %d, tool %s", stepidx, tool)

					// Check for cancelation.
					if currentScanID == "" {
						log.Debugf("Canceled scan, dropping all the pipelines...")
						if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
							log.Error(err.Error())
						}
						return
					}

					// If the current pipeline is empty, end the pipeline now.
					if len(currentData) == 0 {
						break
					}

					// Fetch the plugin metadata.
					plugin, ok := plugins[tool]
					if !ok {
						log.Error("Missing plugin: " + tool)
						if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "Missing plugin: "+tool); err != nil {
							log.Error(err.Error())
						}
						return
					}

					// Here we will collect all the new data for this pipeline step.
					newData := []string{}

					// Iterate over the data in the current pipeline.
					for _, dataid := range currentData {

						// Check for cancelation.
						if currentScanID == "" {
							log.Debugf("Canceled scan, dropping all the pipelines...")
							if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
								log.Error(err.Error())
							}
							return
						}

						// Load the data from the database.
						data, err := g3lib.LoadOne(mdb_client, msg.ScanID, dataid)
						if err != nil {
							log.Error(err.Error())
							if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
								log.Error(err.Error())
							}
							return
						}

						// Skip over dummy objects.
						if dtype, ok := data["_type"]; ok {
							if dtypestr, ok := dtype.(string); ok {
								if dtypestr == "nil" {
									continue
								}
							}
						}

						// Iterate over each subcommand in the plugin.
						for index := 0; index < len(plugin.Commands); index++ {

							// Check for cancelation.
							if currentScanID == "" {
								log.Debugf("Canceled scan, dropping all the pipelines...")
								if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
									log.Error(err.Error())
								}
								return
							}

							// Dynamically evaluate if this plugin accepts this type of data.
							// Skip if it does not apply.
							ok, err := g3lib.EvalToolCondition(plugin, index, data)
							if !ok {
								if err != nil {
									log.Error(err.Error())
									if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
										log.Error(err.Error())
									}
									return
								}
								continue
							}

							// Calculate the command that's going to be run.
							parsed, errors := g3lib.BuildToolCommand(plugin, index, data)
							if len(errors) > 0 {
								errorMsg := ""
								for _, err := range errors {
									errorMsg = errorMsg + "\n" + err.Error()
								}
								log.Error(errorMsg)
								if err := g3lib.SendScanFailed(mq_client, msg.ScanID, errorMsg); err != nil {
									log.Error(err.Error())
								}
								return
							}

							// If we have data in the database matching this fingerprint,
							// use it instead of calling the plugin.
							pastData, err := g3lib.GetFingerprintMatchesIDs(mdb_client, msg.ScanID, parsed.Fingerprint)
							if err != nil {
								log.Error(err.Error())
								if err := g3lib.SendScanFailed(mq_client, msg.ScanID, err.Error()); err != nil {
									log.Error(err.Error())
								}
								return
							}
							if len(pastData) > 0 {
								log.Debugf("Matched %d results in database", len(pastData))
								newData = append(newData, pastData...)
								continue
							}

							// Run the plugin command in one of the workers.
							// Redis state + audit log written *before* the MQTT publish so
							// a fast worker can't race ahead of our bookkeeping.
							taskid := uuid.NewString()
							dataid, ok := data["_id"].(string)
							if !ok {
								dispErr := fmt.Errorf("data missing _id, save to database first")
								log.Error(dispErr.Error())
								if e := g3lib.SendScanFailed(mq_client, msg.ScanID, dispErr.Error()); e != nil {
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
							runningTasks.Add(taskid)
							log.Debug("New task ID: " + taskid)

							// Update the scan progress before waiting for the response.
							if err := g3lib.SendScanProgress(mq_client, msg.ScanID, currentScanStep-1, totalScanSteps); err != nil {
								log.Error(err.Error())
							}

							// Since we're only running one plugin at a time this must be our response.
							var response g3lib.G3Response
							for {
								response = <-responseChannel
								if response.TaskID != "" {
									break
								}
								if currentScanID == "" {
									log.Error("Canceled scan, dropping all the pipelines...")
									if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
										log.Error(err.Error())
									}
									return
								}
							}
							if response.TaskID != taskid {
								log.Errorf("Mismatched task ID! %s != %s", response.TaskID, taskid)
								if err := g3lib.SendScanFailed(mq_client, msg.ScanID, fmt.Sprintf("Mismatched task ID! %s != %s\n", response.TaskID, taskid)); err != nil {
									log.Error(err.Error())
								}
								return
							}
							if runningTasks.Exists(taskid) {
								runningTasks.Delete(taskid)
							}
							log.Debug("Finished task: " + response.TaskID)

							// Terminal state + [g3:done] audit line are written by the
							// worker before it sent this response — scanner only needs
							// to clean up its in-memory tracking here.

							// Update the scan progress now that the task is complete.
							//g3lib.SendScanProgress(mq_client, msg.ScanID, currentScanStep, totalScanSteps)

							// Add the result data into the pipeline.
							if len(response.Response) > 0 {
								log.Debugf("Task returned %d results", len(response.Response))
								newData = append(newData, response.Response...)
							}
						}
					}

					// Move on to the next step in the pipeline.
					currentData = g3lib.RemoveDuplicateStr(newData)
				}
			}
		}
	}

	// Update the scan progress now that all of the pipelines are complete.
	// Pure-import scans (totalScanSteps == 0) skip this — the FINISHED
	// notification later in this function carries the 100% value.
	if totalScanSteps > 0 {
		if err := g3lib.SendScanProgress(mq_client, msg.ScanID, totalScanSteps, totalScanSteps); err != nil {
			log.Error(err.Error())
		}
	}

	// Save the scan metadata in the database.
	var info g3.ScanMetadata
	info.ScanID = msg.ScanID
	err = g3lib.SaveScanMetadata(rdb_client, info)
	if err != nil {
		log.Error("Error saving scan metadata: " + err.Error())
		if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "Error saving scan metadata: "+err.Error()); err != nil {
			log.Error(err.Error())
		}
		return
	}

	// If the scan script declared a reporter, dispatch it and wait for it to
	// finish before completing the scan. The `report` directive is the user's
	// explicit signal that a report is mandatory — had it been optional, the
	// directive would simply be absent. So the reporter is treated as a final,
	// blocking step: the scan stays RUNNING (at 100% progress) while the report
	// generates, and a reporter failure fails the whole scan.
	//
	// Reporting is always delegated to a reporter plugin (magenta by default;
	// script.go resolves a bare `report` directive to the magenta tool), so
	// there is no in-process reporter — every report is a worker dispatch via
	// the canonical dispatchTask helper.
	//
	// Tracking the reporter in runningTasks (like any tool task) makes its
	// lifecycle observable live via /scan/tasks/status (DISPATCHED → RUNNING →
	// DONE) and lets a mid-report scan cancel propagate to the reporter worker
	// for free — the stop handler cancels everything in runningTasks. Because we
	// wait for the terminal response before returning, the worker's Redis writes
	// land before the defer DeleteTaskStates wipe, so there is no orphan hash.
	if msg.Report != nil {
		reporterTaskID := uuid.NewString()
		if err := dispatchTask(
			mq_client, rdb_client, scan_sql_db,
			msg.ScanID, reporterTaskID, "report", msg.Report.Tool,
			"", 0, msg.Report.Preset,
		); err != nil {
			// The report was requested but we couldn't even dispatch it. Since
			// the directive makes the report mandatory, this fails the scan.
			log.Error("Failed to dispatch script-declared reporter: " + err.Error())
			if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "Failed to dispatch reporter: "+err.Error()); err != nil {
				log.Error(err.Error())
			}
			return
		}
		runningTasks.Add(reporterTaskID)

		// Wait for the reporter task to terminate, staying responsive to scan
		// cancellation. This mirrors the pipeline wait loop above: a real task
		// response carries a non-empty TaskID, while the stop handler wakes us
		// with an empty fake response after clearing currentScanID. We match on
		// the reporter's own ID so any stray response is simply ignored.
		//
		// TODO: there is no per-task timeout here. A reporter worker that dies
		// without sending a terminal response blocks the scan in RUNNING
		// indefinitely, escapable only by a manual scan cancel (which does reach
		// the reporter, since it's in runningTasks). This matches the existing
		// behavior of every tool-task wait — revisit only if/when we add hang
		// detection across the board.
		log.Debug("Waiting for reporter task to complete...")
		var response g3lib.G3Response
		for {
			response = <-responseChannel
			if response.TaskID == reporterTaskID {
				break
			}
			if currentScanID == "" {
				log.Debug("Canceled scan during reporting, dropping reporter...")
				if err := g3lib.SendScanStopped(mq_client, msg.ScanID); err != nil {
					log.Error(err.Error())
				}
				return
			}
		}
		runningTasks.Delete(reporterTaskID)

		// An empty response means the reporter ended in an error condition (same
		// convention as tool tasks, see the pipeline loop). The directive made
		// the report mandatory, so a reporter failure fails the whole scan.
		if len(response.Response) == 0 {
			log.Error("Reporter task failed, marking scan as failed.")
			if err := g3lib.SendScanFailed(mq_client, msg.ScanID, "Reporter task failed"); err != nil {
				log.Error(err.Error())
			}
			return
		}
		log.Debug("Reporter task finished.")
	}

	// Send a message to indicate the scan has finished.
	if err := g3lib.SendScanCompleted(mq_client, msg.ScanID); err != nil {
		log.Error(err.Error())
	}
}

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
	mq g3lib.MessageQueueClient,
	rdb g3lib.RedisConnection,
	sql g3lib.SQLDBClient,
	scanID, taskID, kind, tool string,
	dataID string, // tool kind only
	index int, // tool kind only
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
	mq g3lib.MessageQueueClient,
	rdb g3lib.RedisConnection,
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
