package main

import (
	"context"
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

const G3_API_ID = "G3_API_ID"                   // MQTT client ID. Must be unique in your deployment or bad things will happen.
const G3_WS_ADDR = "G3_WS_ADDR"                 // Address to bind to for the HTTP server.
const G3_WS_PORT = "G3_WS_PORT"                 // Port to bind to for the HTTP server.
const G3_WS_PATH = "G3_WS_PATH"                 // Path to route the API.
const G3_FILE_UPLOAD_MAX = "G3_FILE_UPLOAD_MAX" // Maximum file size for uploads.
const G3_WS_BUFFER = "G3_WS_BUFFER"             // Buffer size for the websocket.

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

	// Make sure we have the JWT environment variables.
	_, err = g3lib.GetJwtSecret()
	if err != nil {
		log.Critical(err.Error())
		return 1
	}
	_, err = g3lib.GetJwtLifetime()
	if err != nil {
		log.Critical(err.Error())
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
		// Log in to the application.
		//
		http.HandleFunc(apiPath + "/auth/login", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: auth/login")
			var request g3lib.ReqLogin
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Error decoding payload.")
				return
			}

			// Log in to the application.
			if ! g3lib.Login(sql_db, request.Username, request.Password) {
				log.Error("Login failed for username: " + request.Username)
				g3lib.SendApiError(w, http.StatusUnauthorized, "Username or password incorrect.")
				return
			}

			// Get the user ID. It's important to do this AFTER logging in.
			// Otherwise, it could be used to bruteforce valid usernames.
			userid := g3lib.GetUserID(sql_db, request.Username)
			if userid == 0 {
				log.Error("Error getting user ID for username: " + request.Username)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// Generate and sign the JWT token.
			tokenString, err := g3lib.GenerateJwt(userid)
			if err != nil {
				log.Error("Error generating JWT token: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// Return the JWT token.
			g3lib.SendApiResponse(w, tokenString)
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Refresh the JWT token.
		//
		http.HandleFunc(apiPath + "/auth/refresh", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: auth/refresh")
			var request g3lib.ReqRefresh
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Invalid token.")
				return
			}

			// Refresh the JWT token if valid.
			tokenString, err := g3lib.RefreshJwt(request.Token)
			if err != nil {
				log.Error("Error refreshing JWT token: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// Return the new JWT token.
			g3lib.SendApiResponse(w, tokenString)
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Generate a temporary JWT for using as a cookie when needed.
		//
		http.HandleFunc(apiPath + "/auth/ticket", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: auth/ticket")
			var request g3lib.ReqTicket
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}

			// Create a ticket. This is actually a very time limited JWT.
			// However from the user's perspective this is an opaque value.
			// That lets me change the mechanism in the future.
			ticket, err := g3lib.GenerateTemporaryJwt(userid, time.Second * time.Duration(30))
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}

			// Return the response.
			log.Debugf("Produced ticket: %v", []byte(ticket))
			g3lib.SendApiResponse(w, ticket)
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Start a scan.
		//
		http.HandleFunc(apiPath + "/scan/start", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/start")
			var request g3lib.ReqStartScan
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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

			// If the scan exists, check if the user has permission to access it.
			// If the scan does not exist, fail.
			// If no scan ID was provided, create one.
			if request.ScanID != "" {
				isAuthorized, err := g3lib.IsUserAuthorized(sql_db, userid, request.ScanID)
				if err != nil {
					log.Error(err.Error())
					g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
					return
				}
				if isAuthorized != 1 {
					log.Error("Not authorized.")
					g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
					return
				}
			} else {
				if len(parsed.Targets) == 0 && len(parsed.Imports) == 0 {
					log.Error("No targets for new scan, aborting.")
					g3lib.SendApiError(w, http.StatusBadRequest, "No targets for new scan, aborting.")
					return
				}
				request.ScanID = uuid.NewString()
				err = g3lib.AddUserToScan(sql_db, userid, request.ScanID)
				if err != nil {
					log.Error("Error adding new scan to SQL database: " + err.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
					return
				}
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
				inputfile := fmt.Sprintf("/tmp/%d/%s.bin", userid, parsedImport.Path)
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show the progress of the currently running scans.
		//
		http.HandleFunc(apiPath + "/scan/progress", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/progress")
			var request g3lib.ReqGetScanProgressTable
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			_, err = g3lib.ValidateJwt(request.Token) // no authorization needed
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Get the list of tasks for a scan
		//
		http.HandleFunc(apiPath + "/scan/tasks", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/tasks")
			var request g3lib.ReqQueryScanTaskList
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			_, err = g3lib.ValidateJwt(request.Token) // no authorization needed
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show the logs of a scan or task
		//
		http.HandleFunc(apiPath + "/scan/logs", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/logs")
			var request g3lib.ReqQueryLog
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			_, err = g3lib.ValidateJwt(request.Token) // no authorization needed
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Stop a scan.
		//
		http.HandleFunc(apiPath + "/scan/stop", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/stop")
			var request g3lib.ReqStopScan
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			isAuthorized, err := g3lib.IsUserAuthorized(sql_db, userid, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			if isAuthorized != 1 {
				log.Error("Not authorized.")
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// List all accessible scans for this user.
		//
		http.HandleFunc(apiPath + "/scan/list", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/list")
			var request g3lib.ReqEnumerateScans
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}

			// Get the list of scan IDs.
			scanidlist, err := g3lib.GetScansForUser(sql_db, userid)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				g3lib.SendApiResponse(w, scanidlist)
			}
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Delete a scan.
		//
		http.HandleFunc(apiPath + "/scan/delete", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/delete")
			var request g3lib.ReqDeleteScan
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			isAuthorized, err := g3lib.IsUserAuthorized(sql_db, userid, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			if isAuthorized != 1 {
				log.Error("Not authorized.")
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
			err = g3lib.RemoveUserFromScan(sql_db, userid, scanid)
			if err != nil {
				log.Critical("Error removing user permissions for scan: " + err.Error())
				reterr = reterr + "Error removing user permissions for scan: " + err.Error() + "\n"
			} else {
				log.Debug("Removed user permissions for scan.")
			}

			// If we logged any errors, return with an error condition.
			// Otherwise, we succeeded.
			if reterr != "" {
				g3lib.SendApiError(w, http.StatusInternalServerError, reterr)
			} else {
				g3lib.SendApiResponse(w, nil)
			}
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Generate a report.
		//
		http.HandleFunc(apiPath + "/scan/report", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/report")
			var request g3lib.ReqReport
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			isAuthorized, err := g3lib.IsUserAuthorized(sql_db, userid, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			if isAuthorized != 1 {
				log.Error("Not authorized.")
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Enumerate the data objects.
		//
		http.HandleFunc(apiPath + "/scan/datalist", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/datalist")
			var request g3lib.ReqGetScanDataIDs
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			isAuthorized, err := g3lib.IsUserAuthorized(sql_db, userid, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			if isAuthorized != 1 {
				log.Error("Not authorized.")
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Load the data objects.
		//
		http.HandleFunc(apiPath + "/scan/data", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/data")
			var request g3lib.ReqLoadData
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			isAuthorized, err := g3lib.IsUserAuthorized(sql_db, userid, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}
			if isAuthorized != 1 {
				log.Error("Not authorized.")
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Get the list of available plugins.
		//
		http.HandleFunc(apiPath + "/plugin/list", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: plugin/list")
			var request g3lib.ReqListPlugins
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			_, err = g3lib.ValidateJwt(request.Token) // no authorization needed
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
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
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// File upload handler.
		//
		http.HandleFunc(apiPath + "/file/upload", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: file/upload")
			if r.Method != http.MethodPost {
				log.Error("Method not allowed: " + r.Method)
				g3lib.SendApiError(w, http.StatusMethodNotAllowed, "Error decoding payload.")
				return
			}

			var userid int
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

			// Parse the multipart reader, part by part.
			reader, err := r.MultipartReader()
			if err != nil {
				log.Error("Error reading auth ticket multipart form: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// The first part should be the authentication ticket.
			p, err := reader.NextPart()
			if err != nil {
				log.Error("Error reading auth ticket: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			defer p.Close()
			if p.FormName() != "auth" {
				log.Error("Invalid form part name: " + p.FormName())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			ticketBytes := make([]byte, 8192) // 8k is an almost standard max size for JWT
			ticketLength, err := p.Read(ticketBytes)
			if err != nil && err != io.EOF {
				log.Error("Error parsing auth ticket: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			ticket := string(ticketBytes[:ticketLength])
			userid, err = g3lib.ValidateJwt(ticket)
			if err != nil {
				log.Error("Invalid auth ticket: " + err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}

			// The second part should be the file.
			p, err = reader.NextPart()
			if err != nil && err != io.EOF {
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

			// Create the user directory if it does not exist.
			userdir := fmt.Sprintf("/tmp/%d/", userid)
			err = os.Mkdir(userdir, 0700)
			if err != nil && !os.IsExist(err) {
				log.Error("Error creating user directory: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}

			// Save the uploaded contents into a file with a random name.
			// This way we don't need to trust and/or sanitize user input.
			filename := uuid.NewString()
			fd, err := os.OpenFile(userdir + filename + ".bin", os.O_WRONLY | os.O_CREATE, 0600)
			if err != nil {
				log.Error("Error creating upload file: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			defer fd.Close()
			_, err = io.Copy(fd, p)
			if err != nil {
				os.Remove(userdir + filename + ".bin") //nolint:errcheck
				log.Error("Error writing to upload file: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			err = os.WriteFile(userdir + filename + ".txt", []byte(p.FileName()), 0600)
			if err != nil {
				os.Remove(userdir + filename + ".bin") //nolint:errcheck
				log.Error("Error saving upload file metadata: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}

			// Return the new filename to the caller.
			g3lib.SendApiResponse(w, filename)
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// File download handler.
		//
		http.HandleFunc(apiPath + "/file/download", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: file/download")
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				log.Error("Method not allowed: " + r.Method)
				g3lib.SendApiError(w, http.StatusMethodNotAllowed, "Error decoding payload.")
				return
			}

			// Get the token from a cookie and validate it.
			var userid int
			var err error
			found := false
			for _, cookie := range r.Cookies() {
				if cookie.Name == "auth" {
					userid, err = g3lib.ValidateJwt(cookie.Value)
					if err != nil {
						log.Error(err.Error())
						g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
						return
					}
					found = true
					break
				}
			}
			if !found {
				log.Error("Missing auth cookie")
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}

			// Calculate the real path of the file based on the user and file IDs.
			fileid := r.URL.Query().Get("fileid")
			if ! govalidator.IsUUIDv4(fileid) {
				log.Error("Invalid file ID: " + fileid)
				g3lib.SendApiError(w, http.StatusBadRequest, "Invalid file ID.")
				return
			}
			basename := fmt.Sprintf("/tmp/%d/%s", userid, fileid)

			// Read the file with the metadata.
			fakenameBytes, err := os.ReadFile(basename + ".txt")
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "File not found.")
				return
			}
			fakename := string(fakenameBytes)
			fakename = strings.ReplaceAll(fakename, "\r", "") // this prevents HTTP
			fakename = strings.ReplaceAll(fakename, "\n", "") // request smuggling
			if fakename == "" {
				fakename = fileid
			}

			// Open the file with the data.
			fd, err := os.Open(basename + ".bin")
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "File not found.")
				return
			}
			defer fd.Close()
			fi, err := fd.Stat()
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "File not found.")
				return
			}

			// Return the file contents for GET requests, just the headers for HEAD.
			//w.Header().Set("Accept-Ranges", "bytes")	// TODO
			w.Header().Set("Connection", "close")
			w.Header().Set("Content-Disposition", "attachment; filename=" + fakename)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
			w.Header().Set("Content-Type", "application/octet-binary")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, err = io.Copy(w, fd)
				if err != nil {
					log.Error(err)
					return
				}
			}
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// File list.
		//
		http.HandleFunc(apiPath + "/file/ls", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: file/ls")
			var request g3lib.ReqListFiles
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}

			// List all files in the user directory.
			var fakenames []map[string]interface{}
			files, err := os.ReadDir(fmt.Sprintf("/tmp/%d/", userid))
			if err != nil {
				g3lib.SendApiResponse(w, fakenames)
				return
			}
			for _, file := range files {
				if !file.Type().IsRegular() {
					continue
				}
				name := file.Name()
				ext := filepath.Ext(name)
				fid := strings.TrimSuffix(name, ext)
				if ext != ".txt" {
					continue
				}
				data, err := os.ReadFile(fmt.Sprintf("/tmp/%d/%s", userid, name))
				if err != nil {
					log.Error(err.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
					return
				}
				fi, err := os.Stat(fmt.Sprintf("/tmp/%d/%s.bin", userid, fid))
				if err != nil {
					log.Error(err.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
					return
				}
				fakenames = append(fakenames,
					map[string]interface{}{"fileid": fid, "name": string(data), "size": fi.Size(), "ts": fi.ModTime().Unix()})
			}

			// Return the list of objects.
			g3lib.SendApiResponse(w, fakenames)
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// File remove.
		//
		http.HandleFunc(apiPath + "/file/rm", func (w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: file/rm")
			var request g3lib.ReqRemoveFile
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			userid, err := g3lib.ValidateJwt(request.Token)
			if err != nil {
				log.Error(err.Error())
				g3lib.SendApiError(w, http.StatusUnauthorized, "User is not authorized to perform this operation.")
				return
			}

			// Delete the files if they exist.
			prefix := fmt.Sprintf("/tmp/%d/%s", userid, request.FileID)
			err1 := os.Remove(prefix + ".bin")
			err2 := os.Remove(prefix + ".txt")
			if err1 != nil {
				log.Error(err1.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			if err2 != nil {
				log.Error(err2.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			g3lib.SendApiResponse(w, nil)
		})

		///////////////////////////////////////////////////////////////////////////////////////////
		// Websocket handler.
		//
		http.HandleFunc(apiPath + "/ws", func (w http.ResponseWriter, r *http.Request) {
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

				// Check the JWT token.
				userid, err := g3lib.ValidateJwt(request.Token)
				if err != nil {
					log.Error(err.Error())
					return
				}

				// Decide what to do based on the request type.
				switch request.MsgType {

				// Subscribe to scan progress updates via websocket.
				case "scanprogress":

					// Create a channel and register it with the notification tracker.
					log.Debugf("User ID %d subscribed to progress updates.", userid)
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
		})

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
