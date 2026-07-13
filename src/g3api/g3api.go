package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/golismero/g3/src/g3lib"
	"github.com/golismero/g3/src/g3"
	log "github.com/golismero/g3/src/g3/log"
)

const G3_API_ID = "G3_API_ID"                   // MQTT client ID. Must be unique in your deployment or bad things will happen.
const G3_API_TOKEN = "G3_API_TOKEN"             // Shared bearer token required on every HTTP and WebSocket call.
const G3_HTTP_ADDR = "G3_HTTP_ADDR"             // Address to bind to for the HTTP server.
const G3_HTTP_PORT = "G3_HTTP_PORT"             // Port to bind to for the HTTP server.
const G3_HTTP_PATH = "G3_HTTP_PATH"             // Path to route the API.
const G3_FILE_UPLOAD_MAX = "G3_FILE_UPLOAD_MAX" // Maximum file size for uploads.
const G3_UPLOAD_TTL = "G3_UPLOAD_TTL"           // time.ParseDuration string. 0 (default) disables the _uploads/ orphan sweep.
const G3_HTTP_BUFFER = "G3_HTTP_BUFFER"         // Buffer size for the websocket.

func requireToken(expected string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(hdr, "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			sendApiError(w, http.StatusUnauthorized, "Unauthorized.")
			return
		}
		h(w, r)
	}
}

func requireManagedScan(w http.ResponseWriter, db g3lib.SQLDBClient, scanid string) error {
	status, err := db.GetScanStatus(scanid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendApiError(w, http.StatusNotFound, "Scan does not exist.")
			return err
		}
		log.Error(err)
		sendApiError(w, http.StatusInternalServerError, "Internal error.")
		return err
	}
	if status != "managed" {
		sendApiError(w, http.StatusConflict, "Operation requires a managed scan.")
		return errors.New("scan is not managed: " + scanid)
	}
	return nil
}

// runImport relocates an uploaded file (identified by fileid) into the scan's
// imports/ directory, runs the plugin's importer container, and saves the
// resulting data objects into the scan. Returns the inserted Mongo IDs.
//
// The returned httpStatus tells callers which HTTP code to send on error:
//   - 400 when the request is bad (unknown tool, no importer phase, missing file)
//   - 500 when setup/run/save fails for internal reasons
//
// httpStatus is meaningful only when err != nil; on success it is 0.
func runImport(plugins g3lib.G3PluginMetadata, mdb g3lib.DatastoreClient, artifactsRoot, scanid, tool, fileid string) (ids []string, httpStatus int, err error) {
	plugin, ok := plugins[tool]
	if !ok || plugin.Importer == nil {
		return nil, http.StatusBadRequest, errors.New("tool not found or has no importer: " + tool)
	}

	if g3.Validate.Var(fileid, "required,uuid") != nil {
		return nil, http.StatusBadRequest, errors.New("invalid file ID: " + fileid)
	}

	importsDir := filepath.Join(artifactsRoot, scanid, "imports")
	if err := os.MkdirAll(importsDir, 0o755); err != nil {
		return nil, http.StatusInternalServerError, errors.New("cannot create imports dir " + importsDir + ": " + err.Error())
	}
	srcBin := filepath.Join(artifactsRoot, "_uploads", fileid+".bin")
	srcTxt := filepath.Join(artifactsRoot, "_uploads", fileid+".txt")
	inputfile := filepath.Join(importsDir, fileid+".bin")
	dstTxt := filepath.Join(importsDir, fileid+".txt")
	if err := os.Rename(srcBin, inputfile); err != nil {
		return nil, http.StatusBadRequest, errors.New("cannot relocate upload " + fileid + ": " + err.Error())
	}
	if err := os.Rename(srcTxt, dstTxt); err != nil {
		log.Error("Cannot relocate upload metadata " + fileid + ": " + err.Error())
	}
	stdin, openErr := os.Open(inputfile)
	if openErr != nil {
		return nil, http.StatusBadRequest, errors.New("cannot open file " + inputfile + ": " + openErr.Error())
	}
	defer stdin.Close()

	parsedCommand, errA := g3lib.BuildImporterCommand(plugin)
	if len(errA) > 0 {
		for _, e := range errA {
			log.Error(" - " + e.Error())
		}
		return nil, http.StatusInternalServerError, errors.New("error building importer command for " + plugin.Name)
	}
	ctx := context.Background() // FIXME this may have to be run as a task after all...
	stderr := os.Stderr         // FIXME send this log to the database
	targetData, runErr := g3lib.RunPluginImporter(ctx, plugin, parsedCommand, stdin, stderr)
	if runErr != nil {
		return nil, http.StatusInternalServerError, errors.New("error running importer " + plugin.Name + ": " + runErr.Error())
	}

	ids, saveErr := g3lib.SaveData(mdb, scanid, g3lib.NIL_TASKID, targetData)
	if saveErr != nil {
		return nil, http.StatusInternalServerError, errors.New("error saving imported data for " + plugin.Name + ": " + saveErr.Error())
	}
	log.Debug("Imported file: " + fileid)
	return ids, 0, nil
}

func validateHttpRequest(r *http.Request) error {
	if r.Method != "POST" {
		return errors.New("invalid HTTP method")
	}
	if h, ok := r.Header["Content-Type"]; !ok || len(h) != 1 || h[0] != "application/json" {
		return errors.New("invalid or missing Content-Type header")
	}
	if h, ok := r.Header["Content-Length"]; !ok || len(h) != 1 || h[0] == "0" {
		return errors.New("missing payload")
	}
	return nil
}

func decodeHttpRequest(r *http.Request, req any) error {
	if err := validateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return g3.Validate.Struct(req)
}

func sendApiResponse(w http.ResponseWriter, data any) {
	internalSendApiResponse(w, http.StatusOK, "success", data)
}

func sendApiError(w http.ResponseWriter, statusCode int, errorMsg string) {
	internalSendApiResponse(w, statusCode, "error", errorMsg)
}

func internalSendApiResponse(w http.ResponseWriter, statusCode int, status string, data any) {
	var response g3.APIResponse
	response.Status = status
	response.Data = data
	respBytes, err := g3.EncodeJSON(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) //nolint:errcheck
		log.Error("Error encoding API response: " + err.Error())
		return
	}
	w.WriteHeader(statusCode) //nolint:errcheck
	w.Write(respBytes) //nolint:errcheck
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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This structure wraps a websocket connection to ensure concurrency.

type WSRequest struct {
	MsgType string              `json:"msgtype"             validate:"required"`
	ScanID string               `json:"scanid,omitempty"    validate:"omitempty,uuid"`
}

type WSResponse struct {
	MsgType string              `json:"msgtype"             validate:"required"`
	Data any                    `json:"data,omitempty"`
}

type SyncWebSocket struct {
	mread sync.Mutex
	mwrite sync.Mutex
	conn *websocket.Conn
}

func WrapWebSocket(conn *websocket.Conn) *SyncWebSocket {
	sws := SyncWebSocket{}
	sws.conn = conn
	return &sws
}

func (sws *SyncWebSocket) ReadRequest() (*WSRequest, error) {
	for {
		sws.mread.Lock()
		messageType, data, err := sws.conn.ReadMessage()
		sws.mread.Unlock()
		if err != nil {
			return nil, err
		}
		if messageType == websocket.PingMessage {
			sws.mwrite.Lock()
			sws.conn.WriteMessage(websocket.PongMessage, data) //nolint:errcheck
			sws.mwrite.Unlock()
			continue
		}
		if messageType == websocket.CloseMessage {
			return nil, nil
		}
		if messageType != websocket.TextMessage {
			err = errors.New("invalid message type")
			return nil, err
		}
		var request WSRequest
		err = json.Unmarshal(data, &request)
		return &request, err
	}
}

func (sws *SyncWebSocket) WriteResponse(response WSResponse) error {
	data, err := json.Marshal(response)
	if err == nil {
		sws.mwrite.Lock()
		err = sws.conn.WriteMessage(websocket.TextMessage, data)
		sws.mwrite.Unlock()
	}
	return err
}

func (sws *SyncWebSocket) WriteData(msgtype string, data any) error {
	response := WSResponse{}
	response.MsgType = msgtype
	response.Data = data
	return sws.WriteResponse(response)
}

func (sws *SyncWebSocket) WriteError(text string) error {
	response := WSResponse{}
	response.MsgType = "error"
	response.Data = text
	return sws.WriteResponse(response)
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

	// Resolve the shared artifacts root and verify it is writable.
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
	// must parse as a non-negative time.Duration.
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

	// Load the plugins.
	plugins := g3lib.LoadPlugins()
	if len(plugins) == 0 {
		log.Critical("No plugins found.")
		return 1
	}

	// Initialize the notification trackers.
	progressNotify := NewNotifyTracker()
	removeNotify := NewNotifyTracker()

	// Create the webserver object.
	bindAddr := os.Getenv(G3_HTTP_ADDR)
	bindPort := os.Getenv(G3_HTTP_PORT)
	apiPath := os.Getenv(G3_HTTP_PATH)
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
			log.Critical("\nSIGINT received!")
			cancel()
			srv.Shutdown(context.Background())
			wg.Done()
		case <-ctx.Done():
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()

	// Launch the _uploads/ orphan-sweep goroutine when enabled (G3_UPLOAD_TTL > 0).
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
		sql_db.Close()
		log.Debug("Disconnected from SQL database.")
	}()
	log.Debug("Connected to SQL database.")

	// Subscribe to the scan status topic.
	topic := g3lib.SubscribeAsAPI(mq_client, func(client g3lib.MessageQueueClient, msg g3lib.G3ScanStatus) {
		log.Debug("Received scan status: " + g3lib.PrettyPrintJSON(msg))
		var status *string
		switch msg.Status {
		case g3lib.STATUS_WAITING:
			status = g3.STATUS_WAITING
		case g3lib.STATUS_RUNNING:
			status = g3.STATUS_RUNNING
		case g3lib.STATUS_ERROR:
			status = g3.STATUS_ERROR
		case g3lib.STATUS_CANCELED:
			status = g3.STATUS_CANCELED
		case g3lib.STATUS_FINISHED:
			status = g3.STATUS_DONE
		case g3lib.STATUS_UNKNOWN:
			status = nil
		case g3lib.STATUS_MANAGED:
			status = g3.STATUS_MANAGED
		default:
			status = nil
		}
		var progress *uint64 = nil
		if msg.Progress != nil && *msg.Progress >= 0 {
			var value = uint64(*msg.Progress)
			progress = &value
		}
		var message *string = nil
		if msg.Message != "" {
			message = &msg.Message
		}
		err := sql_db.UpdateScanStatus(msg.ScanID, status, progress, message, msg.Seq)
		if err != nil {
			log.Error("Internal error updating scan status! " + msg.ScanID)
		}
		progressNotify.SendNotification(msg)
	})
	defer g3lib.Unsubscribe(mq_client, topic)

	// Start the web server in a goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Initialize the websocket upgrader.
		strBufferSize := os.Getenv(G3_HTTP_BUFFER)
		if strBufferSize == "" {
			strBufferSize = "65535"
		}
		bufferSize, err := strconv.Atoi(strBufferSize)
		if err != nil {
			bufferSize = 65536
			log.Noticef("Invalid value for %s, using default %d", G3_HTTP_BUFFER, bufferSize)
		}
		var upgrader = websocket.Upgrader{
			ReadBufferSize:  bufferSize,
			WriteBufferSize: bufferSize,
			CheckOrigin:     func(r *http.Request) bool { return true }, // FIXME
		}

		///////////////////////////////////////////////////////////////////////////////////////////
		// Start a scan.
		//
		http.HandleFunc(apiPath+"/scan/start", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/start")
			var request g3.ReqStartScan
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Validate the scan script.
			parsed, err := g3lib.ParseServerScript(plugins, request.Script)
			if err != nil {
				log.Error(err)
				sendApiError(w, http.StatusBadRequest, "Syntax error in script: "+err.Error())
				return
			}

			// /scan/start always creates a fresh scan. A scan must have
			// something to do: targets are only seed data — the real work is
			// pipeline runs or imports, and a pipeline also needs seed data
			// (targets or imports) to run against, otherwise nothing dispatches
			// and the scan sits at 0% forever. Managed scans (/scan/create)
			// intentionally allow "nothing to do"; orchestrated scans do not.
			if len(parsed.Imports) == 0 && (len(parsed.Pipelines) == 0 || len(parsed.Targets) == 0) {
				log.Error("Empty scan rejected: nothing to do (need an import, or a pipeline run with at least one target).")
				sendApiError(w, http.StatusBadRequest, "Empty scan: a scan must declare at least one import, or at least one pipeline run with a target.")
				return
			}

			// Mint a new scan ID.
			scanID := uuid.NewString()
			err = sql_db.CreateScanStatus(scanID, false)
			if err != nil {
				log.Error(err)
				sendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
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
				targetData, err := g3.BuildTargets(parsed.Targets)
				if err != nil {
					log.Error(err)
					_ = sql_db.DeleteScanStatus(scanID)
					sendApiError(w, http.StatusBadRequest, "Runtime error in script: "+err.Error())
					return
				}
				_, err = g3lib.SaveData(mdb_client, scanID, "", targetData)
				if err != nil {
					log.Error(err)
					_ = sql_db.DeleteScanStatus(scanID)
					_ = g3lib.DropScanData(mdb_client, scanID)
					sendApiError(w, http.StatusInternalServerError, "Internal server error.")
					return
				}
			}

			// Import the files into the database. Each import runs in its own
			// closure so the `defer stdin.Close()` fires per-iteration rather
			// than accumulating open file descriptors until the handler returns.
			// TODO refactor this monstrosity for the love of $DEITY
			importOne := func(parsedImport g3.ImportStatement) bool {
				_, status, err := runImport(plugins, mdb_client, artifactsRoot, scanID, parsedImport.Tool, parsedImport.Path)
				if err != nil {
					log.Error(err)
					if status == http.StatusBadRequest {
						sendApiError(w, http.StatusBadRequest, "Syntax error in script, "+err.Error())
					} else {
						sendApiError(w, http.StatusInternalServerError, "Error while running importer: "+parsedImport.Tool)
					}
					return false
				}
				return true
			}
			for _, parsedImport := range parsed.Imports {
				if !importOne(parsedImport) {
					_ = sql_db.DeleteScanStatus(scanID)
					_ = g3lib.DropScanData(mdb_client, scanID)
					return	// SendApiError already called at this point
				}
			}

			// Send the new scan message.
			err = g3lib.SendNewScan(mq_client, scanID, parsed.Mode, parsed.Pipelines, parsed.Report)
			if err != nil {
				log.Error(err)
				_ = sql_db.DeleteScanStatus(scanID)
				_ = g3lib.DropScanData(mdb_client, scanID)
				sendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}
			log.Info("Started scan with ID: " + scanID)

			// Return the response.
			sendApiResponse(w, scanID)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Create a new externally-managed scan.
		//
		http.HandleFunc(apiPath+"/scan/create", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/create")
			var request g3.ReqCreateScan
			if err := decodeHttpRequest(r, &request); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			scanid := uuid.NewString()
			if err := sql_db.CreateScanStatus(scanid, true); err != nil {
				log.Error(err)
				sendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// g3api owns _uploads/, <scanid>/imports/, and <scanid> deletion;
			// owning <scanid> creation for managed scans is consistent.
			if err := os.MkdirAll(filepath.Join(artifactsRoot, scanid), 0o755); err != nil {
				log.Error("Cannot create scan dir: " + err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			sendApiResponse(w, scanid)
			log.Info("Created managed scan with ID: " + scanid)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Add targets to a managed scan.
		//
		http.HandleFunc(apiPath+"/scan/target/add", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/target/add")
			var request g3.ReqAddTargets
			if err := decodeHttpRequest(r, &request); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			targetData, err := g3.BuildTargets(request.Targets)
			if err != nil {
				log.Error(err)
				sendApiError(w, http.StatusBadRequest, "Invalid target: "+err.Error())
				return
			}

			ids, err := g3lib.SaveData(mdb_client, request.ScanID, g3lib.NIL_TASKID, targetData)
			if err != nil {
				log.Error(err)
				sendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			sendApiResponse(w, ids)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Insert raw Data objects into a managed scan.
		//
		http.HandleFunc(apiPath+"/scan/data/insert", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/data/insert")
			var request g3.ReqInsertData
			if err := decodeHttpRequest(r, &request); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			for i, obj := range request.Data {
				if err := obj.Validate(); err != nil {
					log.Error(err)
					sendApiError(w, http.StatusBadRequest, fmt.Sprintf("Invalid data at index %d: %s", i, err.Error()))
					return
				}
			}

			ids, err := g3lib.SaveData(mdb_client, request.ScanID, g3lib.NIL_TASKID, request.Data)
			if err != nil {
				log.Error(err)
				sendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			sendApiResponse(w, ids)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Import an uploaded file into a managed scan. The file must already
		// have been uploaded via /file/upload; the caller supplies its UUID.
		//
		http.HandleFunc(apiPath+"/scan/import", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/import")
			var request g3.ReqImport
			if err := decodeHttpRequest(r, &request); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			ids, status, err := runImport(plugins, mdb_client, artifactsRoot, request.ScanID, request.Tool, request.FileID)
			if err != nil {
				log.Error(err)
				if status == http.StatusBadRequest {
					sendApiError(w, http.StatusBadRequest, err.Error())
				} else {
					sendApiError(w, http.StatusInternalServerError, "Internal server error.")
				}
				return
			}

			sendApiResponse(w, ids)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show the progress of the currently running scans.
		//
		http.HandleFunc(apiPath+"/scan/progress", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/progress")
			var request g3.ReqGetScanProgressTable
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Build a legacy scan progress list.
			var progressList []g3.ScanStatusEntry
			status, err := sql_db.GetAllScansStatus()
			if err != nil {
				log.Error(err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal server error.")
			}
			for _, entry := range(status.Scans) {
				var sse g3.ScanStatusEntry
				sse.ScanID = entry.ScanID
				sse.Progress = int(entry.Progress)
				if entry.Message == nil {
					sse.Message = ""
				} else {
					sse.Message = *entry.Message
				}
				switch entry.Status {
				case "managed":
					sse.Status = g3.G3_STATUS_MANAGED
				case "waiting":
					sse.Status = g3.G3_STATUS_WAITING
				case "dispatched":
					sse.Status = g3.G3_STATUS_WAITING
				case "running":
					sse.Status = g3.G3_STATUS_RUNNING
				case "canceled":
					sse.Status = g3.G3_STATUS_CANCELED
				case "done":
					sse.Status = g3.G3_STATUS_FINISHED
				case "warning":
					sse.Status = g3.G3_STATUS_FINISHED
				case "error":
					sse.Status = g3.G3_STATUS_ERROR
				default:
					sse.Status = g3.G3_STATUS_UNKNOWN
				}
				progressList = append(progressList, sse)
			}
			sendApiResponse(w, progressList)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Get the list of tasks for a scan.
		//
		http.HandleFunc(apiPath+"/scan/tasks", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/tasks")
			var request g3.ReqQueryScanTaskList
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the list of task IDs for this scan.
			taskidlist, err := sql_db.GetScanTaskIDs(request.ScanID)
			if err != nil {
				log.Error(err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				sendApiResponse(w, taskidlist)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show the logs of a scan or task.
		//
		http.HandleFunc(apiPath+"/scan/logs", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/logs")
			var request g3.ReqQueryLog
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Scan-level: stream all log rows for the scan, return []LogEntry.
			if request.TaskID == "" {
				var entries []g3.LogEntry
				scanlog, err := sql_db.GetLogsForScan(request.ScanID)
				if err != nil {
					log.Error("GetLogsForScan failed: " + err.Error())
					sendApiError(w, http.StatusInternalServerError, "Internal error.")
					return
				}
				for _, tasklog := range(scanlog.Logs) {
					for _, line := range(tasklog.Logs) {
						var entry g3.LogEntry
						entry.ScanID = scanlog.ScanID
						entry.TaskID = tasklog.TaskID
						entry.Timestamp = int64(line.Timestamp)
						entry.Text = line.Text
						entries = append(entries, entry)
					}
				}
				slices.SortStableFunc(entries, func(a, b g3.LogEntry) int {
					return cmp.Compare(a.Timestamp, b.Timestamp)
				})
				sendApiResponse(w, entries)
				return
			}

			// Task-scoped: single G3TaskLog.
			tasklog, err := sql_db.GetLogsForTask(request.TaskID)
			if err != nil {
				log.Error("GetLogsForTask failed: " + err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				var tl g3.G3TaskLog
				tl.ScanID = request.ScanID
				tl.TaskID = request.TaskID
				for _, logline := range(tasklog.Logs) {
					var ll g3.TaskLogLine
					ts := int64(logline.Timestamp)
					ll.Timestamp = ts
					if tl.Start == 0 || tl.Start > ts {
						tl.Start = ts
					}
					if tl.End == 0 || tl.End < ts {
						tl.End = ts
					}
					ll.Text = logline.Text
					tl.Lines = append(tl.Lines, ll)
				}
				sendApiResponse(w, tl)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show per-task status summary for a scan (first/last log timestamps, age, line count).
		//
		http.HandleFunc(apiPath+"/scan/tasks/status", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/tasks/status")
			var request g3.ReqQueryScanTaskStatus
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			var response g3.ScanTaskStatusResponse
			status, err := sql_db.GetScanStatus(request.ScanID)
			if err != nil {
				log.Error(err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			switch status {
			case "managed":
				response.ScanStatus = g3.G3_STATUS_MANAGED
			case "waiting", "dispatched":
				response.ScanStatus = g3.G3_STATUS_WAITING
			case "running":
				response.ScanStatus = g3.G3_STATUS_RUNNING
			case "canceled":
				response.ScanStatus = g3.G3_STATUS_CANCELED
			case "done", "warning":
				response.ScanStatus = g3.G3_STATUS_FINISHED
			case "error":
				response.ScanStatus = g3.G3_STATUS_ERROR
			default:
				response.ScanStatus = g3.G3_STATUS_UNKNOWN
			}
			tasks, err := sql_db.GetScanTasksStatus(request.ScanID)
			if err != nil {
				log.Error(err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			for _, task := range(tasks.Tasks) {
				var tse g3.TaskStatusEntry
				tse.TaskID = task.TaskID
				if task.Tool != nil {
					tse.Tool = *task.Tool
				} else {
					tse.Tool = ""
				}
				if task.Worker != nil {
					tse.Worker = *task.Worker
				} else {
					tse.Worker = ""
				}
				switch task.Status {
				case "waiting":
					tse.State = "DISPATCHED"
				case "dispatched":
					tse.State = "DISPATCHED"
				case "running":
					tse.State = "RUNNING"
				case "done":
					tse.State = "DONE"
				case "warning":
					tse.State = "WARNING"
				case "error":
					tse.State = "ERROR"
				case "canceled":
					tse.State = "CANCELED"
				default:
					tse.State = "UNKNOWN"
				}
				tse.DispatchTS = int64(task.CreatedAt)
				if task.StartedAt != nil {
					tse.StartTS = int64(*task.StartedAt)
				}
				if task.EndedAt != nil {
					tse.CompleteTS = int64(*task.EndedAt)
				}
				tse.FirstLogTS = int64(task.CreatedAt)
				tse.LastLogTS = int64(task.LastUpdatedAt)
				tse.AgeSeconds = time.Now().Unix() - int64(task.LastUpdatedAt)
				count, err := sql_db.GetLineCountForTask(task.TaskID)
				if err != nil {
					log.Error(err.Error())
				} else {
					tse.LineCount = int(count)
				}
				response.Tasks = append(response.Tasks, tse)
			}
			sort.Slice(response.Tasks, func(i, j int) bool {
				return response.Tasks[i].DispatchTS < response.Tasks[j].DispatchTS
			})
			sendApiResponse(w, response)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Stop a scan.
		//
		http.HandleFunc(apiPath+"/scan/stop", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/stop")
			var request g3.ReqStopScan
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Send the cancel message.
			log.Info("Canceling scan with ID: " + request.ScanID)
			err = g3lib.SendScanStop(mq_client, request.ScanID)
			if err != nil {
				log.Error(err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				sendApiResponse(w, request.ScanID)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// List every scan known to the engine.
		//
		http.HandleFunc(apiPath+"/scan/list", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/list")
			var request g3.ReqEnumerateScans
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the list of scan IDs.
			scanidlist, err := sql_db.GetAllScanIDs()
			if err != nil {
				log.Error(err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
			} else {
				sendApiResponse(w, scanidlist)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Delete a scan.
		//
		http.HandleFunc(apiPath+"/scan/delete", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/delete")
			var request g3.ReqDeleteScan
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			scanid := request.ScanID

			// Notify WS subscribers.
			removeNotify.SendNotification(g3lib.G3ScanRemoved{ScanID: scanid})

			// The following statements will print errors to the log but will not stop.
			// This is on purpose.
			var reterr string

			// Delete the scan data.
			// TODO there is maybe a race condition here???? look into it later
			if g3.DoDebugAPI() {
				log.Infof("Scan with ID %s protected from deletion due to server debug mode.", scanid)
			} else {
				log.Infof("Deleting scan with ID: %s", scanid)
				err = sql_db.DeleteScanStatus(scanid)
				if err != nil {
					log.Critical("Error clearing logs: " + err.Error())
					reterr = reterr + "Error clearing logs.\n"
				} else {
					log.Debug("Cleared scan status and logs.")
				}
				err = g3lib.DropScanData(mdb_client, scanid)
				if err != nil {
					log.Critical("Error dropping database: " + err.Error())
					reterr = reterr + "Error dropping database.\n"
				} else {
					log.Debug("Dropped scan data objects.")
				}
				err = os.RemoveAll(filepath.Join(artifactsRoot, scanid))
				if err != nil {
					log.Critical("Error removing scan artifacts: " + err.Error())
					reterr = reterr + "Error removing scan artifacts.\n"
				} else {
					log.Debug("Removed scan artifacts.")
				}
			}

			// If we logged any errors, return with an error condition.
			// Otherwise, we succeeded.
			if reterr != "" {
				sendApiError(w, http.StatusInternalServerError, reterr)
			} else {
				sendApiResponse(w, nil)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Task artifacts download.
		//
		http.HandleFunc(apiPath+"/scan/task/artifacts", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/task/artifacts")
			var request g3.ReqTaskArtifacts
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Do not allow downloads from tasks that are not finished.
			task, err := sql_db.GetSingleTaskStatus(request.TaskID)
			if err != nil {
				sendApiError(w, http.StatusNotFound, "task not found")
				return
			}
			if !g3.IsTaskStatusTerminal(task.Status) {
				w.Header().Set("Retry-After", "2")
				sendApiError(w, http.StatusTooEarly, "task is not yet complete")
				return
			}

			// Terminal — bundle and stream.
			toolName := request.TaskID
			if task.Tool != nil {
				toolName = *task.Tool
			}
			artifactsRoot := os.Getenv(g3lib.G3_ARTIFACTS_ROOT)
			if artifactsRoot == "" {
				artifactsRoot = g3lib.G3_ARTIFACTS_ROOT_DEFAULT
			}
			slotDir := filepath.Join(artifactsRoot, request.ScanID, request.TaskID)
			if _, err := os.Stat(slotDir); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					sendApiError(w, http.StatusNotFound, "task produced no output")
					return
				}
				log.Error("stat slot dir failed: " + err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			var buf bytes.Buffer
			filename, contentType, bundleErr := g3lib.BundleTaskSlot(slotDir, toolName, request.TaskID, &buf)
			if bundleErr != nil {
				if errors.Is(bundleErr, os.ErrNotExist) {
					sendApiError(w, http.StatusNotFound, "task produced no output")
					return
				}
				log.Error("BundleTaskSlot failed: " + bundleErr.Error())
				sendApiError(w, http.StatusInternalServerError, "failed to bundle task artifacts")
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
			w.Header().Set("X-G3-Task-ID", request.TaskID)
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(buf.Bytes()); err != nil {
				log.Error("response write failed: " + err.Error())
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Batch task cancellation.
		//
		http.HandleFunc(apiPath+"/scan/task/cancel", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/task/cancel")
			var request g3.ReqTaskCancel
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			log.Infof("Scan %s - Canceling task(s) with IDs: %v", request.ScanID, request.TaskIDs)
			if err := g3lib.SendTaskCancel(mq_client, request.ScanID, request.TaskIDs); err != nil {
				log.Error("SendTaskCancel failed: " + err.Error())
				sendApiError(w, http.StatusInternalServerError, "failed to publish cancel")
				return
			}

			sendApiResponse(w, nil)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Dispatch a task on demand.
		//
		http.HandleFunc(apiPath+"/scan/task/dispatch", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/task/dispatch")
			var request g3.ReqTaskDispatch
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			log.Info("Dispatching tasks to scan with ID: " + request.ScanID)

			plugin, ok := plugins[request.Tool]
			if !ok {
				sendApiError(w, http.StatusBadRequest, "unknown tool: "+request.Tool)
				return
			}

			// Decide which command indices to dispatch. For kind=tool we
			// auto-evaluate plugin.Commands[i].Condition against the data
			// (matching the orchestrator's pipeline behaviour); for
			// kind=report there's a single conceptual operation that Preset
			// disambiguates.
			var indices []int
			switch request.Kind {
			case "tool":
				if len(plugin.Commands) == 0 {
					sendApiError(w, http.StatusBadRequest, "tool "+request.Tool+" does not implement the tool phase")
					return
				}
				if request.DataID == "" {
					sendApiError(w, http.StatusBadRequest, "kind=tool requires dataid")
					return
				}
				loaded, err := g3lib.LoadData(mdb_client, request.ScanID, []string{request.DataID})
				if err != nil {
					log.Error("LoadData failed: " + err.Error())
					sendApiError(w, http.StatusInternalServerError, "failed to load data object")
					return
				}
				if len(loaded) == 0 {
					sendApiError(w, http.StatusBadRequest, "data object not found: "+request.DataID)
					return
				}
				data := loaded[0]
				for i := range plugin.Commands {
					match, err := g3lib.EvalToolCondition(plugin, i, data)
					if err != nil {
						log.Errorf("EvalToolCondition failed for tool %s index %d: %s", request.Tool, i, err.Error())
						sendApiError(w, http.StatusInternalServerError, "condition evaluation failed")
						return
					}
					if match {
						indices = append(indices, i)
					}
				}
				if len(indices) == 0 {
					sendApiError(w, http.StatusBadRequest, "no command in tool "+request.Tool+" matches the given data")
					return
				}
			case "report":
				if plugin.Reporter == nil {
					sendApiError(w, http.StatusBadRequest, "tool "+request.Tool+" does not implement a reporter")
					return
				}
				if request.Preset != "" {
					if len(plugin.Reporter.Commands) == 0 {
						sendApiError(w, http.StatusBadRequest, "tool "+request.Tool+" declares no reporter presets")
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
						sendApiError(w, http.StatusBadRequest, "unknown preset for tool "+request.Tool+": "+request.Preset)
						return
					}
				}
				indices = []int{0}
			default:
				sendApiError(w, http.StatusBadRequest, "unknown kind: "+request.Kind)
				return
			}

			// Publish a dispatch per matched index; collect the task_ids.
			successIds := make([]string, 0, len(indices))
			failedIds := make([]string, 0, len(indices))
			for _, idx := range indices {
				taskid := uuid.NewString()
				log.Info("Dispatching manual task with ID: " + taskid)
				if err := sql_db.CreateTaskStatus(request.ScanID, taskid); err != nil {
					log.Error("CreateTaskStatus (dispatch) failed: " + err.Error())
					failedIds = append(failedIds, taskid)
				}
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
					Index:  idx,
					Preset: request.Preset,
				}
				if err := g3lib.SendDispatch(mq_client, dispatch); err != nil {
					log.Error("SendDispatch failed: " + err.Error())
					failedIds = append(failedIds, taskid)
				}
				successIds = append(successIds, taskid)
			}

			if len(failedIds) > 0 && len(successIds) == 0 {
				sendApiError(w, http.StatusInternalServerError, "failed to create new task(s)")
				return
			}

			internalSendApiResponse(w, http.StatusAccepted, "success", map[string][]string{"task_ids": successIds, "failed": failedIds})
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Enumerate the data objects.
		//
		http.HandleFunc(apiPath+"/scan/datalist", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/datalist")
			var request g3.ReqGetScanDataIDs
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Get the list of data IDs in this scan.
			idArray, err := g3lib.GetScanDataIDs(mdb_client, request.ScanID)
			if err != nil {
				log.Errorf("Error fetching data for scan %s: %s", request.ScanID, err.Error())
				sendApiError(w, http.StatusInternalServerError, "Could not fetch data IDs for scan.")
			} else {
				sendApiResponse(w, idArray)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Load the data objects.
		//
		http.HandleFunc(apiPath+"/scan/data", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/data")
			var request g3.ReqLoadData
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Make sure the request is not too large.
			if len(request.DataIDs) > 100 {
				log.Errorf("Too many data IDs: %d", len(request.DataIDs))
				sendApiError(w, http.StatusBadRequest, "Too many data IDs.")
				return
			}

			// Get the requested data objects. When taskid is set, the call is
			// "fetch the output of one specific task"; otherwise it's by ID
			// list (or all data when the list is empty).
			var data []g3.Data
			if request.TaskID != "" {
				data, err = g3lib.LoadDataByTask(mdb_client, request.ScanID, request.TaskID)
			} else {
				data, err = g3lib.LoadData(mdb_client, request.ScanID, request.DataIDs)
			}
			if err != nil {
				log.Errorf("Error fetching data for scan %s: %s", request.ScanID, err.Error())
				sendApiError(w, http.StatusInternalServerError, "Could not fetch data objects for scan.")
			} else {
				sendApiResponse(w, data)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Get the list of available plugins.
		//
		http.HandleFunc(apiPath+"/plugin/list", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: plugin/list")
			var request g3.ReqListPlugins
			err := decodeHttpRequest(r, &request)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
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

			// Prepare a list of plugins with human-readable metadata plus
			// capability flags (importer/reporter/runnable). A plugin may
			// expose any combination, so consumers filter on the booleans
			// rather than inferring capability from the name or category.
			var pluginList []g3.PluginListItem
			for _, name := range pluginNames {
				plugin := plugins[name]
				pluginList = append(pluginList, g3.PluginListItem{
					PluginDescription: g3.PluginDescription{
						Name:        plugin.Name,
						Category:    plugin.Category,
						URL:         plugin.URL,
						Description: plugin.Description,
					},
					IsImporter:  plugin.Importer != nil,
					IsReporter:  plugin.Reporter != nil,
					IsRunnable:  len(plugin.Commands) > 0,
				})
			}

			// Send the response back to the caller.
			sendApiResponse(w, pluginList)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Get the environment variables shared with the plugins.
		//
		http.HandleFunc(apiPath+"/config/env", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: config/env")
			var request g3.ReqGetEnv
			if err := decodeHttpRequest(r, &request); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			sendApiResponse(w, g3lib.GetSharedEnv())
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// File upload handler.
		//
		http.HandleFunc(apiPath+"/file/upload", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: file/upload")
			if r.Method != http.MethodPost {
				log.Error("Method not allowed: " + r.Method)
				sendApiError(w, http.StatusMethodNotAllowed, "Error decoding payload.")
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
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			p, err := reader.NextPart()
			if err != nil {
				log.Error("Error reading multipart file form: " + err.Error())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			defer p.Close()
			if p.FormName() != "file" {
				log.Error("Invalid form part name: " + p.FormName())
				sendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Save the uploaded contents into a file with a random name.
			// This way we don't need to trust and/or sanitize user input.
			filename := uuid.NewString()
			uploadsDir := filepath.Join(artifactsRoot, "_uploads")
			if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
				log.Error("Cannot create uploads dir " + uploadsDir + ": " + err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			binPath := filepath.Join(uploadsDir, filename+".bin")
			txtPath := filepath.Join(uploadsDir, filename+".txt")
			fd, err := os.OpenFile(binPath, os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				log.Error("Error creating upload file: " + err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			defer fd.Close()
			_, err = io.Copy(fd, p)
			if err != nil {
				os.Remove(binPath) //nolint:errcheck
				log.Error("Error writing to upload file: " + err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			err = os.WriteFile(txtPath, []byte(p.FileName()), 0600)
			if err != nil {
				os.Remove(binPath) //nolint:errcheck
				log.Error("Error saving upload file metadata: " + err.Error())
				sendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}

			// Return the new filename to the caller.
			sendApiResponse(w, filename)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Websocket handler.
		//
		http.HandleFunc(apiPath+"/ws", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: /ws")

			// Upgrade from HTTP to websocket.
			ws, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Error("Could not upgrade HTTP connection to websocket, reason: " + err.Error())
				return
			}
			defer ws.Close()
			conn := WrapWebSocket(ws)
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
				case "scan.status":

					// Create a channel and register it with the notification tracker.
					log.Debug("Subscribed to progress updates.")
					channel := make(chan any)
					ticket := progressNotify.AddChannel(channel)
					defer progressNotify.RemoveChannel(ticket)

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
								err := conn.WriteData("scan.status", msg)
								if err != nil {
									log.Error(err.Error())
								}
							}
						}
					}(channel)

				// Subscribe to scan-removal events via websocket. Mirrors
				// the scan.status case in structure; payload is a tiny
				// G3ScanRemoved{ScanID} pushed when /scan/delete succeeds.
				case "scan.removed":

					log.Debug("Subscribed to scan-removal events.")
					channel := make(chan any)
					ticket := removeNotify.AddChannel(channel)
					defer removeNotify.RemoveChannel(ticket)

					wg.Add(1)
					go func(channel chan any) {
						defer wg.Done()
						log.Debug("Launched goroutine for scan.removed websocket.")
						for {
							select {
							case <-ctx.Done():
								log.Debug("Shutdown requested.")
								return
							case msg := <-channel:
								if msg == nil {
									log.Debug("Closing down scan.removed websocket goroutine.")
									return
								}
								log.Debug("Sending scan-removal event to websocket client.")
								err := conn.WriteData("scan.removed", msg)
								if err != nil {
									log.Error(err.Error())
								}
							}
						}
					}(channel)

				default:
					log.Errorf("Unknown websocket request type: %v", request.MsgType)
					err := conn.WriteError("Unknown websocket request type.")
					if err != nil {
						log.Error(err.Error())
					}
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
