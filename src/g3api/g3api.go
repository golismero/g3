package main

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

const G3_API_ID = "G3_API_ID"                   // MQTT client ID. Must be unique in your deployment or bad things will happen.
const G3_API_TOKEN = "G3_API_TOKEN"             // Shared bearer token required on every HTTP and WebSocket call.
const G3_WS_ADDR = "G3_WS_ADDR"                 // Address to bind to for the HTTP server.
const G3_WS_PORT = "G3_WS_PORT"                 // Port to bind to for the HTTP server.
const G3_WS_PATH = "G3_WS_PATH"                 // Path to route the API.
const G3_FILE_UPLOAD_MAX = "G3_FILE_UPLOAD_MAX" // Maximum file size for uploads.
const G3_WS_BUFFER = "G3_WS_BUFFER"             // Buffer size for the websocket.

// requireToken wraps an http.HandlerFunc with a bearer-token check.
// The check runs before upgrader.Upgrade() on the WebSocket path, so a
// failed token returns 401 and the socket never opens.
func requireToken(expected string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(hdr, "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			g3lib.SendApiError(w, http.StatusUnauthorized, "Unauthorized.")
			return
		}
		h(w, r)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This structure tracks scan IDs to channels of goroutines who asked for updates on that scan.

type ScanChannel struct {
	Channel chan any
}

type NotifyTracker struct {
	sync.RWMutex
	internal map[string]ScanChannel
}

func NewNotifyTracker() *NotifyTracker {
	nt := NotifyTracker{}
	nt.internal = make(map[string]ScanChannel)
	return &nt
}

func (tracker *NotifyTracker) AddChannel(channel chan any) string {
	log.Debug("Adding channel...")
	ticket := uuid.NewString()
	sc := ScanChannel{channel}
	tracker.Lock()
	tracker.internal[ticket] = sc
	tracker.Unlock()
	log.Debugf("Added channel with ticket: %s", ticket)
	return ticket
}

func (tracker *NotifyTracker) SendNotification(msg any) {
	tracker.Lock()
	for ticket, sc := range tracker.internal {
		log.Debug("Sending notification to channel with ticket: " + ticket)
		sc.Channel <- &msg
	}
	tracker.Unlock()
}

func (tracker *NotifyTracker) RemoveChannel(ticket string) bool {
	log.Debug("Removing channel with ticket: " + ticket)
	tracker.Lock()
	sc, ok := tracker.internal[ticket]
	if ok {
		sc.Channel <- nil
		delete(tracker.internal, ticket)
	}
	tracker.Unlock()
	return ok
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func Main() int {
	var wg sync.WaitGroup
	var err error

	// Load the environment variables.
	g3lib.LoadDotEnvFile()

	// Initialize the logger.
	log.InitLogger()

	// Load the shared API bearer token.
	apiToken := os.Getenv(G3_API_TOKEN)
	if apiToken == "" {
		log.Critical("Missing environment variable: " + G3_API_TOKEN)
		return 1
	}

	// Load the plugins.
	plugins := g3lib.LoadPlugins()
	if len(plugins) == 0 {
		log.Critical("No plugins found.")
		return 1
	}

	// Load the main i18n strings.
	i18nStrings := g3lib.LoadG3Strings()

	// Load the plugins i18n templates.
	pluginTemplatesCache := g3lib.LoadPluginTemplates()

	// Initialize the notification tracker.
	notifyTracker := NewNotifyTracker()

	// Create the webserver object.
	bindAddr := os.Getenv(G3_WS_ADDR)
	bindPort := os.Getenv(G3_WS_PORT)
	apiPath := os.Getenv(G3_WS_PATH)
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	if bindPort == "" {
		bindPort = "8080"
	}
	srv := &http.Server{Addr: bindAddr + ":" + bindPort}

	// Create the cancellation context for the service.
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
			log.Critical("\nSIGTERM received!")
			cancel()
			srv.Shutdown(context.Background())
			wg.Done()
		case <-ctx.Done():
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()

	// Connect to the Mosquitto broker.
	mq_client, err := g3lib.ConnectToBroker(os.Getenv(G3_API_ID))
	if err != nil {
		log.Critical(err)
		return 1
	}
	defer func() {
		g3lib.DisconnectFromBroker(mq_client)
		log.Debug("Disconnected from Mosquitto.")
	}()
	log.Debug("Connected to Mosquitto.")
	log.Info("Service ID: " + g3lib.GetClientID(mq_client))

	// Connect to the Mongo database.
	mdb_client, err := g3lib.ConnectToDatastore()
	if err != nil {
		log.Critical(err)
		return 1
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
		return 1
	}
	defer func() {
		g3lib.DisconnectFromSQL(sql_db)
		log.Debug("Disconnected from SQL database.")
	}()
	log.Debug("Connected to SQL database.")

	// Connect to the Redis database.
	rdb_client, err := g3lib.ConnectToKeyValueStore()
	if err != nil {
		log.Critical(err)
		return 1
	}
	defer func() {
		g3lib.DisconnectFromKeyValueStore(rdb_client)
		log.Debug("Disconnected from Redis.")
	}()
	log.Debug("Connected to Redis.")

	// Subscribe to the scan status topic.
	topic := g3lib.SubscribeAsAPI(mq_client, func(client g3lib.MessageQueueClient, msg g3lib.G3ScanStatus) {
		log.Debug("Received scan status: " + g3lib.PrettyPrintJSON(msg))

		// Update the scan progress in the database.
		switch msg.Status {
		case g3lib.STATUS_RUNNING:
			g3lib.UpdateScanProgress(sql_db, msg.ScanID, msg.Status, &msg.Progress, msg.Message) //nolint:errcheck
		case g3lib.STATUS_FINISHED:
			hundred := 100
			g3lib.UpdateScanProgress(sql_db, msg.ScanID, msg.Status, &hundred, msg.Message) //nolint:errcheck
		default:
			g3lib.UpdateScanProgress(sql_db, msg.ScanID, msg.Status, nil, msg.Message) //nolint:errcheck
		}

		// Notify the event if anyone wants it.
		notifyTracker.SendNotification(msg)
	})
	defer g3lib.Unsubscribe(mq_client, topic)

	// Start the web server in a goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Initialize the websocket upgrader.
		strBufferSize := os.Getenv(G3_WS_BUFFER)
		if strBufferSize == "" {
			strBufferSize = "65535"
		}
		bufferSize, err := strconv.Atoi(strBufferSize)
		if err != nil {
			bufferSize = 65536
			log.Noticef("Invalid value for %s, using default %d", G3_WS_BUFFER, bufferSize)
		}
		var upgrader = websocket.Upgrader{
			ReadBufferSize:  bufferSize,
			WriteBufferSize: bufferSize,
			CheckOrigin:     func(r *http.Request) bool { return true }, // FIXME
		}

		///////////////////////////////////////////////////////////////////////////////////////////
		// Start a scan.
		//
		http.HandleFunc(apiPath + "/scan/start", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/start")
			var request g3lib.ReqStartScan
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Validate the scan script.
			parsed, err := g3lib.ParseScript(plugins, request.Script)
			if err == nil {
				err = validator.New().Struct(parsed)
			}
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script: " + err.Error())
				return
			}

			// If a scan ID was provided, require it to already exist — guards
			// against typos silently spawning a phantom scan. The progress row
			// is the cheapest existence witness.
			//
			// TODO: race. A scan is published to MQTT here before g3scanner
			// writes its first WAITING progress row, so a second /scan/start
			// arriving for the same ID inside that window will falsely 404.
			// Narrow (milliseconds) and harmless in the single-author case,
			// but a proper fix needs an existence source that's authoritative
			// at dispatch time — e.g. writing the progress row here before
			// publishing, or checking Redis task state / MongoDB presence in
			// addition to the progress table.
			if request.ScanID != "" {
				if _, err := g3lib.GetScanStatus(sql_db, request.ScanID); err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						g3lib.SendApiError(w, http.StatusNotFound, "Scan does not exist.")
						return
					}
					log.Error(err)
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
					return
				}
			} else {
				if len(parsed.Targets) == 0 && len(parsed.Imports) == 0 {
					log.Error("No targets for new scan, aborting.")
					g3lib.SendApiError(w, http.StatusBadRequest, "No targets for new scan, aborting.")
					return
				}
				request.ScanID = uuid.NewString()
			}

			// Log the parsed script.
			log.Debug(
				"\n" +
				"--------------------------------------------------------------------------------\n" +
				"--- Running script:\n" +
				"\n" +
				parsed.String() +
				"--------------------------------------------------------------------------------\n")

			// Add the targets to the database.
			if len(parsed.Targets) > 0 {
				targetData, err := g3lib.BuildTargets(parsed.Targets)
				if err != nil {
					log.Error(err)
					g3lib.SendApiError(w, http.StatusBadRequest, "Runtime error in script: " + err.Error())
					return
				}
				_, err = g3lib.SaveData(mdb_client, request.ScanID, g3lib.NIL_TASKID, targetData)
				if err != nil {
					log.Error(err)
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
					return
				}
			}

			// Import the files into the database.
			for _, parsedImport := range parsed.Imports {

				// Get the requested importer plugin.
				plugin, ok := plugins[parsedImport.Tool]
				if !ok || plugin.Importer == nil {
					log.Error("Tool not found: " + parsedImport.Tool)
					g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script, tool not found.")
					return
				}

				// Pipe the input file.
				if ! govalidator.IsUUIDv4(parsedImport.Path) {
					log.Error("Invalid file ID: " + parsedImport.Path)
					g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script, imported file not found.")
					return
				}
				inputfile := fmt.Sprintf("/tmp/%s.bin", parsedImport.Path)
				stdin, err := os.Open(inputfile)
				if err != nil {
					log.Critical("Cannot open file " + inputfile + ": " + err.Error())
					g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script, imported file not found.")
					return
				}
				defer stdin.Close()

				// Importers don't support conditions nor command templates.
				// The command is run directly and the raw data piped to it.
				parsedCommand, errA := g3lib.BuildImporterCommand(plugin)
				if len(errA) > 0 {
					log.Error("Error executing importer " + plugin.Name + ":")
					for _, err := range errA {
						log.Error(" - " + err.Error())
					}
					g3lib.SendApiError(w, http.StatusInternalServerError, "Error while running importer: " + plugin.Name)
					return
				}
				ctx := context.Background() // FIXME this may have to be run as a task after all...
				stderr := os.Stderr         // FIXME send this log to the database
				targetData, err := g3lib.RunPluginImporter(ctx, plugin, parsedCommand, stdin, stderr)
				if err != nil {
					log.Error("Error executing importer " + plugin.Name + ": " + err.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "Error while running importer: " + plugin.Name)
					return
				}

				// Save the imported data into the database.
				_, err = g3lib.SaveData(mdb_client, request.ScanID, g3lib.NIL_TASKID, targetData)
				if err != nil {
					log.Error(err)
					g3lib.SendApiError(w, http.StatusInternalServerError, "Error while running importer: " + plugin.Name)
					return
				}
				log.Debug("Imported file: " + parsedImport.Path)
			}

			// Send the new scan message.
			err = g3lib.SendNewScan(mq_client, request.ScanID, parsed.Mode, parsed.Pipelines)
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// Return the response.
			g3lib.SendApiResponse(w, request.ScanID)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show the progress of the currently running scans.
		//
		http.HandleFunc(apiPath + "/scan/progress", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/progress")
			var request g3lib.ReqGetScanProgressTable
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the scan progress table.
			progressList, err := g3lib.GetProgressList(sql_db)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				g3lib.SendApiResponse(w, progressList)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Get the list of tasks for a scan
		//
		http.HandleFunc(apiPath + "/scan/tasks", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/tasks")
			var request g3lib.ReqQueryScanTaskList
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the logs for this task
			tasklist, err := g3lib.QueryTaskIDsFromLog(sql_db, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				g3lib.SendApiResponse(w, tasklist)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show the logs of a scan or task
		//
		http.HandleFunc(apiPath + "/scan/logs", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/logs")
			var request g3lib.ReqQueryLog
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the logs for this task
			tasklog, err := g3lib.QueryLogForTask(sql_db, request.ScanID, request.TaskID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				g3lib.SendApiResponse(w, tasklog)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show per-task status summary for a scan (first/last log timestamps, age, line count).
		//
		http.HandleFunc(apiPath + "/scan/tasks/status", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/tasks/status")
			var request g3lib.ReqQueryScanTaskStatus
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Redis is authoritative for which tasks exist and what state they're in.
			// The SQL logs table supplies timestamps and line counts as augmentation.
			// A terminal scan that has been cleaned up will have no Redis keys; we
			// deliberately do NOT reconstruct task state from logs in that case.
			taskStates, err := g3lib.GetTaskStates(rdb_client, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			logEntries, err := g3lib.QueryTaskStatus(sql_db, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			logByTask := make(map[string]g3lib.TaskStatusEntry, len(logEntries))
			for _, e := range logEntries {
				logByTask[e.TaskID] = e
			}

			entries := make([]g3lib.TaskStatusEntry, 0, len(taskStates))
			for _, ts := range taskStates {
				entry := g3lib.TaskStatusEntry{
					TaskID:     ts.TaskID,
					Tool:       ts.Tool,
					Worker:     ts.Worker,
					State:      ts.State,
					DispatchTS: ts.DispatchTS,
					StartTS:    ts.StartTS,
					CompleteTS: ts.CompleteTS,
					ErrorMsg:   ts.ErrorMsg,
				}
				if le, ok := logByTask[ts.TaskID]; ok {
					entry.FirstLogTS = le.FirstLogTS
					entry.LastLogTS = le.LastLogTS
					entry.LineCount = le.LineCount
					entry.AgeSeconds = le.AgeSeconds
				}
				entries = append(entries, entry)
			}
			// Sort: oldest dispatch first (stuckest-candidate tasks rise to the top).
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].DispatchTS < entries[j].DispatchTS
			})

			scanStatus, err := g3lib.GetScanStatus(sql_db, request.ScanID)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			g3lib.SendApiResponse(w, g3lib.ScanTaskStatusResponse{
				ScanStatus: scanStatus.Status,
				Tasks:      entries,
			})
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Stop a scan.
		//
		http.HandleFunc(apiPath + "/scan/stop", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/stop")
			var request g3lib.ReqStopScan
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Send the cancel message.
			err = g3lib.SendScanStop(mq_client, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				g3lib.SendApiResponse(w, request.ScanID)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// List every scan known to the engine.
		//
		http.HandleFunc(apiPath + "/scan/list", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/list")
			var request g3lib.ReqEnumerateScans
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the list of scan IDs.
			scanidlist, err := g3lib.GetAllScanIDs(sql_db)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				g3lib.SendApiResponse(w, scanidlist)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Delete a scan.
		//
		http.HandleFunc(apiPath + "/scan/delete", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/delete")
			var request g3lib.ReqDeleteScan
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// The following statements will print errors to the log but will not stop.
			// This is on purpose.
			var reterr string

			// Delete the scan data.
			scanid := request.ScanID
			log.Infof("Deleting scan with ID: %s", scanid)
			err = g3lib.DeleteReportInfo(rdb_client, scanid)
			if err != nil {
				log.Critical("Error deleting report info: " + err.Error())
				reterr = reterr + "Error deleting report info: " + err.Error() + "\n"
			} else {
				log.Debug("Deleted report info.")
			}
			err = g3lib.DeleteTaskStates(rdb_client, scanid)
			if err != nil {
				log.Critical("Error deleting task states: " + err.Error())
				reterr = reterr + "Error deleting task states: " + err.Error() + "\n"
			} else {
				log.Debug("Deleted task states.")
			}
			err = g3lib.ClearLogs(sql_db, scanid)
			if err != nil {
				log.Critical("Error clearing logs: " + err.Error())
				reterr = reterr + "Error clearing logs: " + err.Error() + "\n"
			} else {
				log.Debug("Deleted report logs.")
			}
			err = g3lib.DropScanData(mdb_client, scanid)
			if err != nil {
				log.Critical("Error dropping database: " + err.Error())
				reterr = reterr + "Error dropping database: " + err.Error() + "\n"
			} else {
				log.Debug("Dropping Mongo database.")
			}
			err = g3lib.DeleteScanProgress(sql_db, scanid)
			if err != nil {
				log.Critical("Error clearing scan progress: " + err.Error())
				reterr = reterr + "Error clearing scan progress: " + err.Error() + "\n"
			} else {
				log.Debug("Cleared scan progress.")
			}

			// If we logged any errors, return with an error condition.
			// Otherwise, we succeeded.
			if reterr != "" {
				g3lib.SendApiError(w, http.StatusInternalServerError, reterr)
			} else {
				g3lib.SendApiResponse(w, nil)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Generate a report.
		//
		http.HandleFunc(apiPath + "/scan/report", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/report")
			var request g3lib.ReqReport
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the list of issues from the report info, if available.
			// If there is no report info, just get all issues for the scan.
			errorText := ""
			log.Debug("Querying Redis...")
			var issues []string
			info, err := g3lib.LoadReportInfo(rdb_client, request.ScanID)
			if err != nil {
				log.Error("Could not find a finished report object in Redis, this could mean the scan has not finished yet. Error message: " + err.Error())
				errorText = errorText + "Could not find a finished report object in Redis, this could mean the scan has not finished yet.\n"
				issues, err = g3lib.GetIssueIDs(mdb_client, request.ScanID, "*")
				if err != nil {
					log.Critical(err.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "Error fetching data from the database.")
					return
				}
				log.Debugf("Found %d total issues.", len(issues))
			} else {
				log.Debugf("Found %d reported issues.", len(info.Issues))
				issues = info.Issues
			}

			// Load the data from the database.
			log.Debug("Querying MongoDB...")
			inputJson, err := g3lib.LoadData(mdb_client, request.ScanID, issues)
			if err != nil {
				log.Critical(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Error fetching data from the database.")
				return
			}
			log.Debugf("...done! Found %d objects.", len(inputJson))

			// Get the list of tools used in the scan.
			var tools []string
			if len(issues) > 0 {
				tools, err = g3lib.GetScanIssueTools(mdb_client, request.ScanID)
			} else {
				tools, err = g3lib.GetScanTools(mdb_client, request.ScanID)
			}
			if err != nil {
				log.Critical(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Error fetching data from the database.")
				return
			}

			// Build the report.
			reporter := g3lib.NewMarkdownReporter(g3lib.DefaultConfig, plugins, pluginTemplatesCache, i18nStrings)
			textOutput, errorArray := reporter.Build("en", "Golismero3 Scan Report", inputJson, tools)
			if len(errorArray) > 0 {
				for _, err := range errorArray {
					log.Error(err.Error())
					errorText = errorText + err.Error() + "\n"
				}
			}

			// Return the report text and the errors during its generation.
			if textOutput == "" {
				g3lib.SendApiError(w, http.StatusInternalServerError, errorText)
			} else {
				result := map[string]string{}
				result["report"] = textOutput
				if errorText != "" {
					result["errors"] = errorText
				}
				g3lib.SendApiResponse(w, result)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Enumerate the data objects.
		//
		http.HandleFunc(apiPath + "/scan/datalist", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/datalist")
			var request g3lib.ReqGetScanDataIDs
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the list of data IDs in this scan.
			idArray, err := g3lib.GetScanDataIDs(mdb_client, request.ScanID)
			if err != nil {
				log.Errorf("Error fetching data for scan %s: %s", request.ScanID, err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Could not fetch data IDs for scan.")
			} else {
				g3lib.SendApiResponse(w, idArray)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Load the data objects.
		//
		http.HandleFunc(apiPath + "/scan/data", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/data")
			var request g3lib.ReqLoadData
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Make sure the request is not too large.
			if len(request.DataIDs) > 100 {
				log.Errorf("Too many data IDs: %d", len(request.DataIDs))
				g3lib.SendApiError(w, http.StatusBadRequest, "Too many data IDs.")
				return
			}

			// Get the requested data objects.
			data, err := g3lib.LoadData(mdb_client, request.ScanID, request.DataIDs)
			if err != nil {
				log.Errorf("Error fetching data for scan %s: %s", request.ScanID, err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Could not fetch data objects for scan.")
			} else {
				g3lib.SendApiResponse(w, data)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Get the list of available plugins.
		//
		http.HandleFunc(apiPath + "/plugin/list", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: plugin/list")
			var request g3lib.ReqListPlugins
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Sort the plugin names alphabetically.
			pluginNames := make([]string, len(plugins))
			index := 0
			for key := range plugins {
				pluginNames[index] = key
				index++
			}
			sort.Strings(pluginNames)

			// Prepare a list of plugins with some human readable metadata.
			var pluginList []map[string]string
			for _, name := range pluginNames {
				plugin := plugins[name]
				pluginData := map[string]string{}
				pluginData["name"] = plugin.Name
				pluginData["url"] = plugin.URL
				pluginData["description"] = plugin.Description["en"]
				pluginList = append(pluginList, pluginData)
			}

			// Send the response back to the caller.
			g3lib.SendApiResponse(w, pluginList)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// File upload handler.
		//
		http.HandleFunc(apiPath + "/file/upload", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: file/upload")
			if r.Method != http.MethodPost {
				log.Error("Method not allowed: " + r.Method)
				g3lib.SendApiError(w, http.StatusMethodNotAllowed, "Error decoding payload.")
				return
			}

			var err error

			// If a maximum file upload size was set, enforce it.
			fileSizeMaxStr := os.Getenv(G3_FILE_UPLOAD_MAX)
			if fileSizeMaxStr != "" {
				var fileSizeMax int64
				fileSizeMax, err = strconv.ParseInt(fileSizeMaxStr, 10, 64)
				if err != nil {
					log.Error(err)
				} else if fileSizeMax > 0 {
					log.Debugf("Setting maximum file size of %d bytes", fileSizeMax)
					r.Body = http.MaxBytesReader(w, r.Body, fileSizeMax)
				}
			} else {
				log.Warning("No maximum upload file size was set!")
			}

			// Parse the multipart reader. Only one part is expected: the file.
			reader, err := r.MultipartReader()
			if err != nil {
				log.Error("Error reading multipart form: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			p, err := reader.NextPart()
			if err != nil {
				log.Error("Error reading multipart file form: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			defer p.Close()
			if p.FormName() != "file" {
				log.Error("Invalid form part name: " + p.FormName())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Save the uploaded contents into a file with a random name.
			// This way we don't need to trust and/or sanitize user input.
			filename := uuid.NewString()
			binPath := "/tmp/" + filename + ".bin"
			txtPath := "/tmp/" + filename + ".txt"
			fd, err := os.OpenFile(binPath, os.O_WRONLY | os.O_CREATE, 0600)
			if err != nil {
				log.Error("Error creating upload file: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			defer fd.Close()
			_, err = io.Copy(fd, p)
			if err != nil {
				os.Remove(binPath) //nolint:errcheck
				log.Error("Error writing to upload file: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			err = os.WriteFile(txtPath, []byte(p.FileName()), 0600)
			if err != nil {
				os.Remove(binPath) //nolint:errcheck
				log.Error("Error saving upload file metadata: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}

			// Return the new filename to the caller.
			g3lib.SendApiResponse(w, filename)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Websocket handler.
		//
		http.HandleFunc(apiPath + "/ws", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: /ws")

			// Upgrade from HTTP to websocket.
			ws, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Error("Could not upgrade HTTP connection to websocket, reason: " + err.Error())
				return
			}
			defer ws.Close()
			conn := g3lib.WrapWebSocket(ws)
			log.Debug("Accepted websocket connection.")

			// Listen for incoming requests, until the websocket is closed or an error occurs.
			for {
				request, err := conn.ReadRequest()
				if err != nil {
					log.Error("Error reading from websocket: " + err.Error())
					return
				}
				if request == nil {
					log.Error("Closed websocket connection.")
					return
				}

				// Decide what to do based on the request type.
				switch request.MsgType {

				// Subscribe to scan progress updates via websocket.
				case "scanprogress":

					// Create a channel and register it with the notification tracker.
					log.Debug("Subscribed to progress updates.")
					channel := make(chan any)
					ticket := notifyTracker.AddChannel(channel)
					defer notifyTracker.RemoveChannel(ticket)

					// Launch a goroutine that sends scan updates to connected websocket clients.
					wg.Add(1)
					go func(channel chan any) {
						defer wg.Done()
						log.Debug("Launched goroutine for websocket.")
						for {
							select {
							case <-ctx.Done():
								log.Debug("Shutdown requested.")
								return
							case msg := <-channel:
								if msg == nil {
									log.Debug("Closing down websocket goroutine.")
									return
								}
								log.Debug("Sending scan progress update to websocket client.")
								err := conn.WriteData("scanprogress", msg)
								if err != nil {
									log.Error(err.Error())
								}
							}
						}
					}(channel)

				default:
					log.Errorf("Unknown websocket request type: %v", request.MsgType)
					conn.WriteError("Unknown websocket request type.")
				}
			}
		}))

		// Start the web server.
		log.Info("Listening for HTTP requests on " + bindAddr + ":" + bindPort)
		err = srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Critical("HTTP server error: " + err.Error())
		}
	}()

	// Wait until we are shut down.
	log.Debug("Main thread is now waiting for children to finish...")
	wg.Wait()
	log.Info("Quitting...")
	return 0
}

func main() {
	os.Exit(Main())
}
