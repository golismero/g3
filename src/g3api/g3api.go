package main

import (
	"bytes"
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

const G3_API_ID = "G3_API_ID"                   // MQTT client ID. Must be unique in your deployment or bad things will happen.
const G3_API_TOKEN = "G3_API_TOKEN"             // Shared bearer token required on every HTTP and WebSocket call.
const G3_HTTP_ADDR = "G3_HTTP_ADDR"             // Address to bind to for the HTTP server.
const G3_HTTP_PORT = "G3_HTTP_PORT"             // Port to bind to for the HTTP server.
const G3_HTTP_PATH = "G3_HTTP_PATH"             // Path to route the API.
const G3_FILE_UPLOAD_MAX = "G3_FILE_UPLOAD_MAX" // Maximum file size for uploads.
const G3_UPLOAD_TTL = "G3_UPLOAD_TTL"           // time.ParseDuration string. 0 (default) disables the _uploads/ orphan sweep.
const G3_HTTP_BUFFER = "G3_HTTP_BUFFER"         // Buffer size for the websocket.

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

// requireManagedScan looks up the scan's progress row and returns nil when its
// status is STATUS_MANAGED. On any other state — including missing scan or
// non-managed scan — it writes the appropriate API error to w and returns a
// non-nil error so the caller can return early.
func requireManagedScan(w http.ResponseWriter, db g3lib.SQLDBClient, scanid string) error {
	entry, err := g3lib.GetScanStatus(db, scanid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			g3lib.SendApiError(w, http.StatusNotFound, "Scan does not exist.")
			return err
		}
		log.Error(err)
		g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
		return err
	}
	if entry.Status != g3lib.STATUS_MANAGED {
		g3lib.SendApiError(w, http.StatusConflict, "Operation requires a managed scan.")
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

	if !govalidator.IsUUIDv4(fileid) {
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

// buildPluginContract assembles the LLM-facing contract for one plugin. The
// caller MUST have ensured plugin.LLM != nil; plugins without the LLM block
// are not reachable to LLM consumers and are filtered out at the handler
// before reaching this function.
func buildPluginContract(plugin g3lib.G3Plugin) g3lib.PluginContract {
	return g3lib.PluginContract{
		Name:     plugin.Name,
		Summary:  plugin.LLM.Summary,
		Accepts:  plugin.LLM.Accepts,
		Produces: plugin.LLM.Produces,
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

	// Load the plugins.
	plugins := g3lib.LoadPlugins()
	if len(plugins) == 0 {
		log.Critical("No plugins found.")
		return 1
	}

	// Initialize the notification trackers. Each WS msgtype has its own
	// tracker so a subscriber to "scanremoved" never receives a
	// "scanprogress" payload (which would otherwise be wrapped with the
	// wrong msgtype on the wire by the per-subscription writer goroutine).
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
	rdb_client, err := g3lib.ConnectToRedis()
	if err != nil {
		log.Critical(err)
		return 1
	}
	defer func() {
		g3lib.DisconnectFromRedis(rdb_client)
		log.Debug("Disconnected from Redis.")
	}()
	log.Debug("Connected to Redis.")

	// Subscribe to the scan status topic.
	topic := g3lib.SubscribeAsAPI(mq_client, func(client g3lib.MessageQueueClient, msg g3lib.G3ScanStatus) {
		log.Debug("Received scan status: " + g3lib.PrettyPrintJSON(msg))

		// Update the scan progress in the database. msg.Progress is
		// already nullable (*int) — UpdateScanProgress nil-skips the
		// progress column, so we pass it through verbatim. The sender
		// is the authority on whether the value is meaningful; the
		// subscriber doesn't second-guess.
		g3lib.UpdateScanProgressSeq(sql_db, msg.ScanID, msg.Status, msg.Progress, msg.Message, msg.Seq) //nolint:errcheck

		// Notify the event if anyone wants it.
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
				g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script: "+err.Error())
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
				g3lib.SendApiError(w, http.StatusBadRequest, "Empty scan: a scan must declare at least one import, or at least one pipeline run with a target.")
				return
			}
			scanID := uuid.NewString()

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
					g3lib.SendApiError(w, http.StatusBadRequest, "Runtime error in script: "+err.Error())
					return
				}
				_, err = g3lib.SaveData(mdb_client, scanID, g3lib.NIL_TASKID, targetData)
				if err != nil {
					log.Error(err)
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
					return
				}
			}

			// Import the files into the database. Each import runs in its own
			// closure so the `defer stdin.Close()` fires per-iteration rather
			// than accumulating open file descriptors until the handler returns.
			importOne := func(parsedImport g3lib.ParsedImport) bool {
				_, status, err := runImport(plugins, mdb_client, artifactsRoot, scanID, parsedImport.Tool, parsedImport.Path)
				if err != nil {
					log.Error(err)
					if status == http.StatusBadRequest {
						g3lib.SendApiError(w, http.StatusBadRequest, "Syntax error in script, "+err.Error())
					} else {
						g3lib.SendApiError(w, http.StatusInternalServerError, "Error while running importer: "+parsedImport.Tool)
					}
					return false
				}
				return true
			}
			for _, parsedImport := range parsed.Imports {
				if !importOne(parsedImport) {
					return
				}
			}

			// Send the new scan message. parsed.Report is nil when the script
			// has no report directive, non-nil with empty Tool for the built-in,
			// non-nil with a Tool for a plugin reporter.
			err = g3lib.SendNewScan(mq_client, scanID, parsed.Mode, parsed.Pipelines, parsed.Report)
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}
			log.Info("Started scan with ID: " + scanID)

			// Return the response.
			g3lib.SendApiResponse(w, scanID)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Create a new externally-managed scan. The scan exists in the progress
		// table with STATUS_MANAGED so the orchestrator never claims it; no
		// G3Scan is published, no pipelines run. Used by external clients (e.g.
		// the Python g3client) to host on-demand task dispatch.
		http.HandleFunc(apiPath+"/scan/create", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/create")
			var request g3lib.ReqCreateScan
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			scanid := uuid.NewString()

			// Write the progress row first so subsequent managed-only calls find
			// the scan via GetScanStatus, then mark it MANAGED.
			if err := g3lib.InsertScanProgress(sql_db, scanid); err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}
			if err := g3lib.UpdateScanProgress(sql_db, scanid, g3lib.STATUS_MANAGED, nil, "Externally managed."); err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// g3api owns _uploads/, <scanid>/imports/, and <scanid> deletion;
			// owning <scanid> creation for managed scans is consistent.
			if err := os.MkdirAll(filepath.Join(artifactsRoot, scanid), 0o755); err != nil {
				log.Error("Cannot create scan dir: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			g3lib.SendApiResponse(w, scanid)
			log.Info("Created managed scan with ID: " + scanid)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Add targets to a managed scan. Reuses BuildTargets so canonicalization
		// (URL parsing, loopback rejection, _type/_fp synthesis) stays identical
		// to the existing `target X` script directive. Returns the inserted
		// Mongo IDs so the caller can immediately dispatch tasks against them.
		http.HandleFunc(apiPath+"/scan/target/add", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/target/add")
			var request g3lib.ReqAddTargets
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			targetData, err := g3lib.BuildTargets(request.Targets)
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusBadRequest, "Invalid target: "+err.Error())
				return
			}

			ids, err := g3lib.SaveData(mdb_client, request.ScanID, g3lib.NIL_TASKID, targetData)
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			g3lib.SendApiResponse(w, ids)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Insert raw G3Data objects into a managed scan. Each object is validated
		// server-side via IsValidData; malformed objects are rejected with 400
		// before any write occurs. Returns the inserted Mongo IDs.
		http.HandleFunc(apiPath+"/scan/data/insert", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/data/insert")
			var request g3lib.ReqInsertData
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			for i, obj := range request.Data {
				if _, err := g3lib.IsValidData(obj); err != nil {
					log.Error(err)
					g3lib.SendApiError(w, http.StatusBadRequest, fmt.Sprintf("Invalid data at index %d: %s", i, err.Error()))
					return
				}
			}

			ids, err := g3lib.SaveData(mdb_client, request.ScanID, g3lib.NIL_TASKID, request.Data)
			if err != nil {
				log.Error(err)
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			g3lib.SendApiResponse(w, ids)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Import an uploaded file into a managed scan. The file must already
		// have been uploaded via /file/upload; the caller supplies its UUID.
		// Reuses the same runImport helper that drives /scan/start's imports.
		http.HandleFunc(apiPath+"/scan/import", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/import")
			var request g3lib.ReqImport
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if err := requireManagedScan(w, sql_db, request.ScanID); err != nil {
				return
			}

			ids, status, err := runImport(plugins, mdb_client, artifactsRoot, request.ScanID, request.Tool, request.FileID)
			if err != nil {
				log.Error(err)
				if status == http.StatusBadRequest {
					g3lib.SendApiError(w, http.StatusBadRequest, err.Error())
				} else {
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal server error.")
				}
				return
			}

			g3lib.SendApiResponse(w, ids)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Show the progress of the currently running scans.
		//
		http.HandleFunc(apiPath+"/scan/progress", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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
		http.HandleFunc(apiPath+"/scan/tasks", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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
		http.HandleFunc(apiPath+"/scan/logs", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/logs")
			var request g3lib.ReqQueryLog
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			if request.TaskID == "" {
				// Scan-level: stream all log rows for the scan, return []LogEntry.
				// Order is timestamp ASC then row id ASC (set by QueryLog), so the
				// client receives a chronologically interleaved stream across tasks.
				entries := make([]g3lib.LogEntry, 0)
				cb := func(e g3lib.LogEntry) error {
					entries = append(entries, e)
					return nil
				}
				if err := g3lib.QueryLog(sql_db, cb, request.ScanID); err != nil {
					log.Error(err.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
					return
				}
				g3lib.SendApiResponse(w, entries)
				return
			}

			// Task-scoped: single G3TaskLog (existing behavior, unchanged).
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
		http.HandleFunc(apiPath+"/scan/tasks/status", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/tasks/status")
			var request g3lib.ReqQueryScanTaskStatus
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Redis is authoritative for per-task state and is retained for the
			// scan's whole lifetime (cleared only by /scan/delete). When Redis
			// has genuinely lost the data (eviction/restart, or a scan old enough
			// to predate retained state), we fall back to reconstructing from
			// structured log markers — see the fallback further down. The SQL
			// logs table supplies timestamps and line counts as augmentation.
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

			// If Redis has no per-task state at all, fall back to reconstructing
			// from structured log markers. SQL `logs` is durable, so this works
			// for scans whose Redis keys were lost (eviction/restart) or deleted.
			//
			// TODO: this fallback is all-or-nothing — it assumes Redis is either
			// complete or empty. If Redis is ever *partially* populated for a scan
			// (some keys evicted, or a task added to a scan whose other keys are
			// gone), the non-empty branch hides the missing tasks instead of
			// merging in the SQL-reconstructed ones. Retaining task-state keys
			// until /scan/delete (see g3scanner) keeps this from firing in normal
			// operation; a fully robust fix would merge Redis over SQL by taskid.
			if len(entries) == 0 {
				reconstructed, rerr := g3lib.ReconstructTaskStatesFromLogs(sql_db, request.ScanID)
				if rerr != nil {
					log.Error("ReconstructTaskStatesFromLogs failed: " + rerr.Error())
					// Soft-fail: respond with an empty list rather than 500.
					// The TUI handles empty gracefully.
				} else {
					for _, entry := range reconstructed {
						if le, ok := logByTask[entry.TaskID]; ok {
							entry.FirstLogTS = le.FirstLogTS
							entry.LastLogTS = le.LastLogTS
							entry.LineCount = le.LineCount
							entry.AgeSeconds = le.AgeSeconds
						}
						entries = append(entries, entry)
					}
				}
			}

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
		http.HandleFunc(apiPath+"/scan/stop", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/stop")
			var request g3lib.ReqStopScan
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Send the cancel message.
			log.Info("Canceling scan with ID: " + request.ScanID)
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
		http.HandleFunc(apiPath+"/scan/list", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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
		http.HandleFunc(apiPath+"/scan/delete", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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
			err = g3lib.DeleteScanMetadata(rdb_client, scanid)
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
			err = os.RemoveAll(filepath.Join(artifactsRoot, scanid))
			if err != nil {
				log.Critical("Error removing scan artifacts: " + err.Error())
				reterr = reterr + "Error removing scan artifacts: " + err.Error() + "\n"
			} else {
				log.Debug("Removed scan artifacts.")
			}

			// If we logged any errors, return with an error condition.
			// Otherwise, we succeeded.
			if reterr != "" {
				g3lib.SendApiError(w, http.StatusInternalServerError, reterr)
			} else {
				// Notify WS subscribers so they can drop the row
				// immediately rather than wait for the next periodic
				// snapshot to reveal the absence. Fire only on full
				// success; partial failures leave the row in some tables
				// and the next snapshot will reconcile.
				removeNotify.SendNotification(g3lib.G3ScanRemoved{ScanID: scanid})
				g3lib.SendApiResponse(w, nil)
			}
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Generic task-artifacts download. Lifecycle-first: task state is read from Redis
		// (fast path) or reconstructed from SQL log markers (durable fallback). Filesystem
		// participates only in the bundling step. Redis absence is NEVER a failure signal;
		// the endpoint falls through to SQL when Redis is silent. Tool name for the bundle
		// filename comes from the SQL [g3:dispatch] marker — uniform across task kinds.
		//
		// See docs/superpowers/specs/2026-05-18-reporter-tier3-design.md (Component 3).
		//
		http.HandleFunc(apiPath+"/scan/task/artifacts", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/task/artifacts")
			var request g3lib.ReqTaskArtifacts
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			// Lifecycle lookup — Redis fast path, SQL log fallback. Filesystem
			// state never participates in the lifecycle decision. See
			// docs/superpowers/specs/2026-05-18-reporter-tier3-design.md Component 3.
			state, _ := g3lib.GetTaskState(rdb_client, request.ScanID, request.TaskID)
			toolName := ""

			switch state {
			case "DISPATCHED", "RUNNING":
				w.Header().Set("Retry-After", "2")
				g3lib.SendApiError(w, http.StatusTooEarly, "task is still "+state)
				return
			case "DONE", "WARNING", "ERROR", "CANCELED":
				// Terminal via Redis. Tool name lives in the same per-task hash
				// (populated by SetTaskDispatched). For simplicity we always
				// re-derive via SQL below so both paths share the same code —
				// SQL call is cheap relative to bundling and avoids a special
				// branch for the Redis-warm case.
				fallthrough
			default:
				// Either terminal via Redis (fallthrough) or Redis silent (state=="").
				// Consult SQL log markers for authoritative lifecycle and tool name.
				sqlState, sqlTool, qerr := g3lib.ReconstructTaskStateFromLogs(sql_db, request.ScanID, request.TaskID)
				if qerr != nil {
					log.Error("ReconstructTaskStateFromLogs failed: " + qerr.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
					return
				}
				if sqlState == "" && state == "" {
					// No record anywhere: task never existed in this scan.
					g3lib.SendApiError(w, http.StatusNotFound, "task not found")
					return
				}
				// If Redis was terminal, use that; if SQL is more authoritative
				// (Redis silent), use that.
				effectiveState := state
				if effectiveState == "" {
					effectiveState = sqlState
				}
				switch effectiveState {
				case "DONE", "WARNING", "ERROR", "CANCELED", "FINISHED":
					toolName = sqlTool
					// Proceed to bundling.
				case "WAITING", "RUNNING", "UNKNOWN":
					w.Header().Set("Retry-After", "2")
					g3lib.SendApiError(w, http.StatusTooEarly, "task is not yet complete")
					return
				default:
					log.Error("Unexpected effective task state: " + effectiveState)
					g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
					return
				}
			}

			// Terminal — bundle and stream.
			artifactsRoot := os.Getenv(g3lib.G3_ARTIFACTS_ROOT)
			if artifactsRoot == "" {
				artifactsRoot = g3lib.G3_ARTIFACTS_ROOT_DEFAULT
			}
			slotDir := filepath.Join(artifactsRoot, request.ScanID, request.TaskID)
			if _, err := os.Stat(slotDir); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					g3lib.SendApiError(w, http.StatusNotFound, "task produced no output")
					return
				}
				log.Error("stat slot dir failed: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			// Fallback tool name if SQL didn't have it (e.g. brand-new task that
			// somehow lost its dispatch marker — pathological but defended).
			if toolName == "" {
				toolName = request.TaskID
			}
			var buf bytes.Buffer
			filename, contentType, bundleErr := g3lib.BundleTaskSlot(slotDir, toolName, request.TaskID, &buf)
			if bundleErr != nil {
				if errors.Is(bundleErr, os.ErrNotExist) {
					g3lib.SendApiError(w, http.StatusNotFound, "task produced no output")
					return
				}
				log.Error("BundleTaskSlot failed: " + bundleErr.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "failed to bundle task artifacts")
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
		// Batch task cancellation. Publishes a single G3CancelTask MQTT message covering
		// all task IDs in one publish. Fire-and-forget: the API doesn't wait for workers
		// to acknowledge — task state transitions to CANCELED flow through the existing
		// SetTaskTerminal / /scan/tasks/status / WebSocket task channel pipeline.
		//
		// See docs/superpowers/specs/2026-05-18-reporter-tier2-design.md (Component 3).
		//
		http.HandleFunc(apiPath+"/scan/task/cancel", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/task/cancel")
			var request g3lib.ReqTaskCancel
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			log.Infof("Scan %s - Canceling task(s) with IDs: %v", request.ScanID, request.TaskIDs)
			if err := g3lib.SendTaskCancel(mq_client, request.ScanID, request.TaskIDs); err != nil {
				log.Error("SendTaskCancel failed: " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "failed to publish cancel")
				return
			}

			g3lib.SendApiResponse(w, nil)
		}))

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
		http.HandleFunc(apiPath+"/scan/task/dispatch", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: scan/task/dispatch")
			var request g3lib.ReqTaskDispatch
			err := request.Decode(r)
			if err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			log.Info("Dispatching tasks to scan with ID: " + request.ScanID)

			plugin, ok := plugins[request.Tool]
			if !ok {
				g3lib.SendApiError(w, http.StatusBadRequest, "unknown tool: "+request.Tool)
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
					g3lib.SendApiError(w, http.StatusBadRequest, "tool "+request.Tool+" does not implement the tool phase")
					return
				}
				if request.DataID == "" {
					g3lib.SendApiError(w, http.StatusBadRequest, "kind=tool requires dataid")
					return
				}
				loaded, err := g3lib.LoadData(mdb_client, request.ScanID, []string{request.DataID})
				if err != nil {
					log.Error("LoadData failed: " + err.Error())
					g3lib.SendApiError(w, http.StatusInternalServerError, "failed to load data object")
					return
				}
				if len(loaded) == 0 {
					g3lib.SendApiError(w, http.StatusBadRequest, "data object not found: "+request.DataID)
					return
				}
				data := loaded[0]
				for i := range plugin.Commands {
					match, err := g3lib.EvalToolCondition(plugin, i, data)
					if err != nil {
						log.Errorf("EvalToolCondition failed for tool %s index %d: %s", request.Tool, i, err.Error())
						g3lib.SendApiError(w, http.StatusInternalServerError, "condition evaluation failed")
						return
					}
					if match {
						indices = append(indices, i)
					}
				}
				if len(indices) == 0 {
					g3lib.SendApiError(w, http.StatusBadRequest, "no command in tool "+request.Tool+" matches the given data")
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
				indices = []int{0}
			default:
				g3lib.SendApiError(w, http.StatusBadRequest, "unknown kind: "+request.Kind)
				return
			}

			// Publish a dispatch per matched index; collect the task_ids.
			// TODO: better error handling if one of many tasks fails.
			taskIds := make([]string, 0, len(indices))
			for _, idx := range indices {
				taskid := uuid.NewString()
				log.Info("Dispatching manual task with ID: " + taskid)
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
					g3lib.SendApiError(w, http.StatusInternalServerError, "failed to publish dispatch")
					return
				}
				taskIds = append(taskIds, taskid)
			}

			w.WriteHeader(http.StatusAccepted)
			response := g3lib.APIResponse{
				Status: "success",
				Data:   map[string][]string{"task_ids": taskIds},
			}
			response.Write(w)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Enumerate the data objects.
		//
		http.HandleFunc(apiPath+"/scan/datalist", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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
		http.HandleFunc(apiPath+"/scan/data", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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

			// Get the requested data objects. When taskid is set, the call is
			// "fetch the output of one specific task"; otherwise it's by ID
			// list (or all data when the list is empty).
			var data []g3lib.G3Data
			if request.TaskID != "" {
				data, err = g3lib.LoadDataByTask(mdb_client, request.ScanID, request.TaskID)
			} else {
				data, err = g3lib.LoadData(mdb_client, request.ScanID, request.DataIDs)
			}
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
		http.HandleFunc(apiPath+"/plugin/list", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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

			// Prepare a list of plugins with human-readable metadata plus
			// capability flags (importer/reporter/runnable). A plugin may
			// expose any combination, so consumers filter on the booleans
			// rather than inferring capability from the name or category.
			var pluginList []g3lib.PluginListItem
			for _, name := range pluginNames {
				plugin := plugins[name]
				pluginList = append(pluginList, g3lib.PluginListItem{
					Name:        plugin.Name,
					Category:    plugin.Category,
					URL:         plugin.URL,
					Description: plugin.Description,
					Importer:    plugin.Importer != nil,
					Reporter:    plugin.Reporter != nil,
					Runnable:    len(plugin.Commands) > 0,
				})
			}

			// Send the response back to the caller.
			g3lib.SendApiResponse(w, pluginList)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// LLM-facing tool contract: per-plugin Summary/Accepts/Produces/Operations
		// sourced from optional .g3p `llm:` metadata, with graceful fallback when
		// the block is absent. Excludes Description/URL/Image (those stay on
		// /plugin/list for humans and GUIs).
		http.HandleFunc(apiPath+"/plugin/describe", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: plugin/describe")
			var request g3lib.ReqListPlugins
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			pluginNames := make([]string, 0, len(plugins))
			for key := range plugins {
				pluginNames = append(pluginNames, key)
			}
			sort.Strings(pluginNames)

			contracts := make([]g3lib.PluginContract, 0, len(plugins))
			for _, name := range pluginNames {
				plugin := plugins[name]
				// Tools without an `llm:` block in their .g3p are not reachable
				// to LLM consumers — the absence of the block is the opt-out
				// signal. Present-but-empty (`llm: {}`) still counts as opt-in.
				if plugin.LLM == nil {
					continue
				}
				contracts = append(contracts, buildPluginContract(plugin))
			}

			g3lib.SendApiResponse(w, contracts)
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// Read-only deployment-wide capability flags: the subset of environment
		// variables prefixed G3_ENV_*, which g3worker injects into every plugin
		// container. The operator owns the values; this endpoint just surfaces
		// them so consumers can reason about capabilities (e.g. IPv6 support).
		http.HandleFunc(apiPath+"/config/env", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: config/env")
			var request g3lib.ReqGetEnv
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}
			g3lib.SendApiResponse(w, g3lib.GetSharedEnv())
		}))

		///////////////////////////////////////////////////////////////////////////////////////////
		// File upload handler.
		//
		http.HandleFunc(apiPath+"/file/upload", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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
			uploadsDir := filepath.Join(artifactsRoot, "_uploads")
			if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
				log.Error("Cannot create uploads dir " + uploadsDir + ": " + err.Error())
				g3lib.SendApiError(w, http.StatusInternalServerError, "Internal error.")
				return
			}
			binPath := filepath.Join(uploadsDir, filename+".bin")
			txtPath := filepath.Join(uploadsDir, filename+".txt")
			fd, err := os.OpenFile(binPath, os.O_WRONLY|os.O_CREATE, 0600)
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
		http.HandleFunc(apiPath+"/ws", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
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
								err := conn.WriteData("scanprogress", msg)
								if err != nil {
									log.Error(err.Error())
								}
							}
						}
					}(channel)

				// Subscribe to scan-removal events via websocket. Mirrors
				// the scanprogress case in structure; payload is a tiny
				// G3ScanRemoved{ScanID} pushed when /scan/delete succeeds.
				case "scanremoved":

					log.Debug("Subscribed to scan-removal events.")
					channel := make(chan any)
					ticket := removeNotify.AddChannel(channel)
					defer removeNotify.RemoveChannel(ticket)

					wg.Add(1)
					go func(channel chan any) {
						defer wg.Done()
						log.Debug("Launched goroutine for scanremoved websocket.")
						for {
							select {
							case <-ctx.Done():
								log.Debug("Shutdown requested.")
								return
							case msg := <-channel:
								if msg == nil {
									log.Debug("Closing down scanremoved websocket goroutine.")
									return
								}
								log.Debug("Sending scan-removal event to websocket client.")
								err := conn.WriteData("scanremoved", msg)
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
