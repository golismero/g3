package g3lib

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"        // MySQL / MariaDB
)

const SQL_DSN = "SQL_DSN"

type SQLDBClient struct {
	db *sql.DB
}

type LogEntry struct {
	Timestamp int64  `json:"timestamp"   validate:"gte=0"`
	ScanID    string `json:"scanid"      validate:"required,uuid4"`
	TaskID    string `json:"taskid"      validate:"required,uuid4"`
	Text      string `json:"text"`
}

type TaskLogLine struct {
	Timestamp int64  `json:"timestamp"       validate:"gte=0"`
	Text      string `json:"text"`
}
type G3TaskLog struct {
	ScanID string        `json:"scanid"          validate:"required,uuid4"`
	TaskID string        `json:"taskid"          validate:"required,uuid4"`
	Start  int64         `json:"start,omitempty" validate:"gte=0"`
	End    int64         `json:"end,omitempty"   validate:"gte=0"`
	Lines  []TaskLogLine `json:"lines,omitempty" validate:"dive"`
}

func (log G3TaskLog) String() string {
	var text string
	for _, line := range log.Lines {
		text = text + fmt.Sprintf("[%s]\t%s\n", time.Unix(line.Timestamp, 0), StripAnsi(line.Text))
	}
	return text
}

type ScanStatusEntry struct {
	ScanID   string       `json:"scanid"      validate:"required,uuid4"`
	Status   G3SCANSTATUS `json:"status"      validate:"required"`
	Progress int          `json:"progress"    validate:"gte=0,lte=100"`
	Message  string       `json:"message"`
}

type TaskStatusEntry struct {
	TaskID     string `json:"taskid"                   validate:"required,uuid4"`
	Tool       string `json:"tool,omitempty"`
	Worker     string `json:"worker,omitempty"`
	State      string `json:"state,omitempty"` // RUNNING / DONE / ERROR / CANCELED (from Redis)
	DispatchTS int64  `json:"dispatch_ts,omitempty"`
	StartTS    int64  `json:"start_ts,omitempty"`
	CompleteTS int64  `json:"complete_ts,omitempty"`
	ErrorMsg   string `json:"error_msg,omitempty"`
	FirstLogTS int64  `json:"first_log_ts"             validate:"gte=0"`
	LastLogTS  int64  `json:"last_log_ts"              validate:"gte=0"`
	LineCount  int    `json:"line_count"               validate:"gte=0"`
	AgeSeconds int64  `json:"age_seconds"              validate:"gte=0"`
}

// Response container for /scan/tasks/status. Bundles the scan-level status
// alongside per-task entries so the client can render a coherent view
// (e.g. suppress the age column for terminal scans).
type ScanTaskStatusResponse struct {
	ScanStatus G3SCANSTATUS      `json:"scan_status"`
	Tasks      []TaskStatusEntry `json:"tasks"`
}

type QueryLogCallback func(LogEntry) error

// Connect to the SQL database.
func ConnectToSQL() (SQLDBClient, error) {
	c := SQLDBClient{}

	// Get the connection string.
	dsn := os.Getenv(SQL_DSN)
	if dsn == "" {
		return c, errors.New("missing environment variable: " + SQL_DSN)
	}

	// Connect to the database.
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return c, err
	}

	// Set the connection options.
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	// Return the DB client object.
	c.db = db
	return c, nil
}

// Defer this call after calling ConnectToSQL().
func DisconnectFromSQL(db SQLDBClient) {
	if db.db != nil {
		db.db.Close()
		db.db = nil
	}
}

// Add a log line to the database.
func SaveLogLine(db SQLDBClient, scanid, taskid, text string) error {
	query := "INSERT INTO `logs` (`timestamp`, `scanid`, `taskid`, `text`) VALUES (UNIX_TIMESTAMP(), ?, ?, ?)"
	_, err := db.db.ExecContext(context.Background(), query, scanid, taskid, text)
	return err
}

// Query the log.
func QueryLog(db SQLDBClient, callback QueryLogCallback, args ...string) error {
	var err error

	// Build the query string dynamically.
	query := "SELECT `timestamp`, `scanid`, `taskid`, `text` FROM `logs`"
	if len(args) > 0 {
		query = query + " WHERE (scanid=?"
		if len(args) > 1 {
			query = query + " AND (taskid=?"
			for range args[2:] {
				query = query + " OR taskid=?"
			}
			query = query + ")"
		}
		query = query + ")"
	}
	if len(args) > 0 {
		query = query + " ORDER BY `timestamp`, `id` ASC"
	}

	// Make the SQL query.
	parameters := make([]interface{}, len(args))
	for i := range args {
		parameters[i] = args[i]
	}
	rows, err := db.db.Query(query, parameters...)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Fetch the rows.
	for rows.Next() {
		var entry LogEntry
		e := rows.Scan(&entry.Timestamp, &entry.ScanID, &entry.TaskID, &entry.Text)
		if e != nil {
			err = e
			continue
		}
		e = callback(entry)
		if e != nil {
			err = e
			break
		}
	}
	return err
}

// Query the logs for the list of tasks for a scan.
func QueryTaskIDsFromLog(db SQLDBClient, scanid string) ([]string, error) {
	var tasklist []string
	var err error

	// Get the task IDs from the log. Since we always output one line of log
	// before the task is even run, this should work well enough for our
	// purposes, which is mostly recovering logs anyway.
	query := "SELECT DISTINCT `taskid` FROM `logs` WHERE `scanid` = ? ORDER BY `timestamp`, `id` ASC"
	rows, err := db.db.Query(query, scanid)
	if err != nil {
		return tasklist, err
	}
	defer rows.Close()

	// Fetch the rows.
	for rows.Next() {
		var taskid string
		e := rows.Scan(&taskid)
		if e != nil {
			err = e
			continue
		}
		tasklist = append(tasklist, taskid)
	}
	return tasklist, err
}

// Query the per-task status summary for a scan (one row per task with first/last
// log timestamps and line count). Used by Tier 4 visibility to answer "which
// tasks haven't produced output in a while?" without pulling every log line.
func QueryTaskStatus(db SQLDBClient, scanid string) ([]TaskStatusEntry, error) {
	var entries []TaskStatusEntry

	// Sort so the task with the oldest last-log timestamp (= highest age,
	// most likely stuck) appears first. This is the whole point of the view.
	query := "SELECT `taskid`, MIN(`timestamp`), MAX(`timestamp`), COUNT(*) " +
		"FROM `logs` WHERE `scanid` = ? GROUP BY `taskid` ORDER BY MAX(`timestamp`) ASC"
	rows, err := db.db.Query(query, scanid)
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	now := time.Now().Unix()
	for rows.Next() {
		var entry TaskStatusEntry
		if e := rows.Scan(&entry.TaskID, &entry.FirstLogTS, &entry.LastLogTS, &entry.LineCount); e != nil {
			return entries, e
		}
		entry.AgeSeconds = now - entry.LastLogTS
		if entry.AgeSeconds < 0 {
			entry.AgeSeconds = 0
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// Query the log lines for a specific task execution.
func QueryLogForTask(db SQLDBClient, scanid string, taskid string) (G3TaskLog, error) {
	var log G3TaskLog
	log.ScanID = scanid
	log.TaskID = taskid
	callback := func(entry LogEntry) error {
		var line TaskLogLine
		if entry.Timestamp != 0 && (log.Start == 0 || entry.Timestamp < log.Start) {
			log.Start = entry.Timestamp
		}
		if entry.Timestamp > log.End {
			log.End = entry.Timestamp
		}
		line.Timestamp = entry.Timestamp
		line.Text = entry.Text
		log.Lines = append(log.Lines, line)
		return nil
	}
	err := QueryLog(db, callback, scanid, taskid)
	return log, err
}

// Clear the logs for a given scan.
func ClearLogs(db SQLDBClient, scanid string) error {
	query := "DELETE FROM `logs` WHERE `scanid` = ?"
	_, err := db.db.ExecContext(context.Background(), query, scanid)
	return err
}

// Add a scan to the progress table.
func InsertScanProgress(db SQLDBClient, scanid string) error {
	query := "INSERT INTO `progress` (`scanid`) VALUES (?)"
	_, err := db.db.ExecContext(context.Background(), query, scanid)
	if err != nil {
		progress := 0
		err = UpdateScanProgress(db, scanid, STATUS_WAITING, &progress, "Waiting in queue...")
	}
	return err
}

// Update the progress of a scan, unconditionally. Used for setup writes (e.g.
// marking a scan MANAGED) that are not racing concurrent status messages.
func UpdateScanProgress(db SQLDBClient, scanid string, status G3SCANSTATUS, progress *int, message string) error {
	return updateScanProgress(db, scanid, status, progress, message, nil)
}

// UpdateScanProgressSeq updates a scan's progress only if seq is newer than the
// last persisted sequence number for that scan. g3api processes status messages
// concurrently (SetOrderMatters(false)), so a stale update — e.g. a RUNNING that
// lost the race to a near-simultaneous FINISHED — must not overwrite a newer
// one. Makes persistence order-independent and idempotent under duplicate delivery.
func UpdateScanProgressSeq(db SQLDBClient, scanid string, status G3SCANSTATUS, progress *int, message string, seq uint64) error {
	return updateScanProgress(db, scanid, status, progress, message, &seq)
}

func updateScanProgress(db SQLDBClient, scanid string, status G3SCANSTATUS, progress *int, message string, seq *uint64) error {
	var query string
	var args []interface{}

	query = "UPDATE `progress` SET "
	correct := false

	if status != "" {
		found := false
		for _, st := range VALID_STATUS {
			if status == st {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unsupported value for argument `status`: %v", status)
		}
		query = query + "`status` = ?, "
		args = append(args, status)
		correct = true
	}

	if progress != nil {
		if *progress < 0 {
			*progress = 0
		} else if *progress > 100 {
			*progress = 100
		}
		query = query + "`progress` = ?, "
		args = append(args, *progress)
		correct = true
	}

	if message != "" {
		query = query + "`message` = ?, "
		args = append(args, message)
		correct = true
	}

	if seq != nil {
		query = query + "`last_seq` = ?, "
		args = append(args, *seq)
		correct = true
	}

	if !correct {
		return errors.New("invalid call to UpdateScanProgress(), nothing to update")
	}
	query = query[:len(query)-2] + " WHERE `scanid` = ?"
	args = append(args, scanid)

	if seq != nil {
		// Ordering guard: apply only if this message is newer than the last one
		// persisted for this scan. Stale, out-of-order updates match zero rows.
		query = query + " AND `last_seq` < ?"
		args = append(args, *seq)
	}

	_, err := db.db.ExecContext(context.Background(), query, args...)
	return err
}

// Get the scan IDs of every scan known to the progress table.
func GetAllScanIDs(db SQLDBClient) ([]string, error) {
	var ids []string
	rows, err := db.db.Query("SELECT `scanid` FROM `progress` ORDER BY `id` DESC")
	if err != nil {
		return ids, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if e := rows.Scan(&id); e != nil {
			return ids, e
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Get the progress of each scan.
func GetProgressList(db SQLDBClient) ([]ScanStatusEntry, error) {
	var scanstatus []ScanStatusEntry
	var err error
	var validate = validator.New()

	query := "SELECT `scanid`, `status`, `progress`, `message` FROM `progress` ORDER BY `id` DESC"
	rows, err := db.db.Query(query)
	if err != nil {
		return scanstatus, err
	}
	defer rows.Close()

	for rows.Next() {
		var entry ScanStatusEntry
		e := rows.Scan(&entry.ScanID, &entry.Status, &entry.Progress, &entry.Message)
		if e != nil {
			err = e
			continue
		}
		err = validate.Struct(entry)
		if err != nil {
			err = e
			continue
		}
		scanstatus = append(scanstatus, entry)
	}
	return scanstatus, err
}

// Get the progress entry for a single scan. Returns sql.ErrNoRows wrapped if the
// scan is not in the progress table; callers that tolerate a missing row (e.g.
// the tasks-status endpoint for a just-queued scan) should check for that.
func GetScanStatus(db SQLDBClient, scanid string) (ScanStatusEntry, error) {
	var entry ScanStatusEntry
	query := "SELECT `scanid`, `status`, `progress`, `message` FROM `progress` WHERE `scanid` = ?"
	err := db.db.QueryRow(query, scanid).Scan(&entry.ScanID, &entry.Status, &entry.Progress, &entry.Message)
	return entry, err
}

// Remove the progress of a scan.
func DeleteScanProgress(db SQLDBClient, scanid string) error {
	query := "DELETE FROM `progress` WHERE `scanid` = ?"
	_, err := db.db.ExecContext(context.Background(), query, scanid)
	return err
}

// ReconstructTaskStatesFromLogs walks the structured lifecycle markers
// in the `logs` table and builds a TaskStatusEntry per task. It is the
// fallback path for /scan/tasks/status when Redis-backed task state has
// expired — the structured markers persist in SQL.
//
// Markers it understands:
//
//	[g3:dispatch] task=<id> tool=<name>   (from scanner)
//	[g3:start]    task=<id> worker=<id>   (from worker)
//	[g3:done]     task=<id> state=<S>     (from worker, or scanner on dispatch-fail)
//	[g3:cancel]   task=<id>               (from scanner)
//
// Defensive parsing: only the FIRST [g3:dispatch] per task is treated
// as authoritative. Anything later that looks like a marker is from
// tool stdout and is ignored.
func ReconstructTaskStatesFromLogs(db SQLDBClient, scanid string) ([]TaskStatusEntry, error) {
	query := "SELECT `taskid`, `timestamp`, `text` FROM `logs` " +
		"WHERE `scanid` = ? AND `text` LIKE '[g3:%' " +
		"ORDER BY `taskid`, `timestamp`, `id` ASC"
	rows, err := db.db.Query(query, scanid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type acc struct {
		entry        TaskStatusEntry
		dispatchSeen bool
		startSeen    bool
		doneSeen     bool
		cancelSeen   bool
	}
	byTask := map[string]*acc{}

	for rows.Next() {
		var taskid string
		var ts int64
		var text string
		if e := rows.Scan(&taskid, &ts, &text); e != nil {
			return nil, e
		}
		a, ok := byTask[taskid]
		if !ok {
			a = &acc{entry: TaskStatusEntry{TaskID: taskid}}
			byTask[taskid] = a
		}
		switch {
		case strings.HasPrefix(text, "[g3:dispatch]"):
			if a.dispatchSeen {
				continue // defensive: only first dispatch wins
			}
			a.dispatchSeen = true
			a.entry.DispatchTS = ts
			a.entry.Tool = parseMarkerField(text, "tool")
			if a.entry.State == "" {
				a.entry.State = string(STATUS_WAITING)
			}
		case strings.HasPrefix(text, "[g3:start]"):
			a.startSeen = true
			a.entry.StartTS = ts
			a.entry.Worker = parseMarkerField(text, "worker")
			a.entry.State = string(STATUS_RUNNING)
		case strings.HasPrefix(text, "[g3:done]"):
			a.doneSeen = true
			a.entry.CompleteTS = ts
			if s := parseMarkerField(text, "state"); s != "" {
				a.entry.State = s
			} else {
				a.entry.State = string(STATUS_FINISHED)
			}
		case strings.HasPrefix(text, "[g3:cancel]"):
			// Record that a cancel was issued. We don't set State here
			// because if the worker survives long enough to emit
			// [g3:done] state=CANCELED, that's the authoritative
			// completion record. The promotion step below uses
			// cancelSeen as a fallback when [g3:done] never arrives —
			// e.g. worker container killed before it could write the
			// done line — so the task lands as CANCELED rather than
			// UNKNOWN.
			a.cancelSeen = true
			if a.entry.CompleteTS == 0 {
				a.entry.CompleteTS = ts
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Resolve final state for tasks without a [g3:done] marker:
	//   - cancelSeen → CANCELED (user-initiated stop; worker likely
	//     didn't survive long enough to write the done line, or the
	//     task was killed before it ever started).
	//   - startSeen but no done/cancel → UNKNOWN (worker crashed
	//     mid-run with no explicit termination signal).
	// Tasks whose [g3:done] arrived keep whatever state that marker
	// set; no further promotion needed.
	out := make([]TaskStatusEntry, 0, len(byTask))
	for _, a := range byTask {
		if !a.doneSeen {
			switch {
			case a.cancelSeen:
				a.entry.State = string(STATUS_CANCELED)
			case a.startSeen:
				a.entry.State = string(STATUS_UNKNOWN)
			}
		}
		out = append(out, a.entry)
	}
	// Sort: oldest dispatch first (mirrors the live-path ordering in
	// the /scan/tasks/status handler).
	sort.Slice(out, func(i, j int) bool {
		return out[i].DispatchTS < out[j].DispatchTS
	})
	return out, nil
}

// ReconstructTaskStateFromLogs returns the lifecycle state and tool name
// for a single task, reconstructed from SQL log markers. Returns
// ("", "", nil) if no markers for this task exist (the task either was
// never dispatched or its log lines were never written).
//
// Mirrors ReconstructTaskStatesFromLogs's parsing logic but scoped to
// one task — useful for endpoints that need to look up a single task's
// state without paying for the per-scan full reconstruction.
//
// State precedence (matches the plural function):
//   [g3:done]   → state from marker's state= field
//   [g3:cancel] without [g3:done] → CANCELED
//   [g3:start]  without done/cancel → UNKNOWN (worker crashed mid-run)
//   [g3:dispatch] only → WAITING
func ReconstructTaskStateFromLogs(db SQLDBClient, scanid, taskid string) (string, string, error) {
	query := "SELECT `timestamp`, `text` FROM `logs` " +
		"WHERE `scanid` = ? AND `taskid` = ? AND `text` LIKE '[g3:%' " +
		"ORDER BY `timestamp`, `id` ASC"
	rows, err := db.db.Query(query, scanid, taskid)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	state := ""
	tool := ""
	dispatchSeen := false
	startSeen := false
	doneSeen := false
	cancelSeen := false

	for rows.Next() {
		var ts int64
		var text string
		if e := rows.Scan(&ts, &text); e != nil {
			return "", "", e
		}
		_ = ts // timestamp not currently used; reserved for future
		switch {
		case strings.HasPrefix(text, "[g3:dispatch]"):
			if dispatchSeen {
				continue // defensive: only first dispatch wins
			}
			dispatchSeen = true
			if t := parseMarkerField(text, "tool"); t != "" {
				tool = t
			}
			if state == "" {
				state = string(STATUS_WAITING)
			}
		case strings.HasPrefix(text, "[g3:start]"):
			startSeen = true
			state = string(STATUS_RUNNING)
		case strings.HasPrefix(text, "[g3:done]"):
			doneSeen = true
			if s := parseMarkerField(text, "state"); s != "" {
				state = s
			} else {
				state = string(STATUS_FINISHED)
			}
		case strings.HasPrefix(text, "[g3:cancel]"):
			cancelSeen = true
		}
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}

	// Resolve final state for tasks without a [g3:done] marker:
	//   - cancelSeen → CANCELED (worker killed before [g3:done])
	//   - startSeen without done/cancel → UNKNOWN (worker crashed mid-run)
	// Tasks whose [g3:done] arrived keep whatever state that marker set.
	if !doneSeen {
		if cancelSeen {
			state = string(STATUS_CANCELED)
		} else if startSeen {
			state = string(STATUS_UNKNOWN)
		}
	}

	return state, tool, nil
}

// parseMarkerField extracts a `key=value` field from a [g3:*] marker
// line. Values are tokenized at whitespace; this matches the format
// the scanner/worker emit, where values are simple identifiers (UUIDs,
// tool names, worker IDs, state names) without spaces.
func parseMarkerField(text, key string) string {
	prefix := key + "="
	for _, tok := range strings.Fields(text) {
		if strings.HasPrefix(tok, prefix) {
			return tok[len(prefix):]
		}
	}
	return ""
}
