package g3lib

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"

	// For the time being I am deliberately not supporting Oracle since it requires proprietary C code to work.
	// As for the rest of the drivers, check each one for DSN and environment variable details on how to use them.
	// Note that enabling all of these can increase compilation time and binary size - if this is a problem to you
	// consider commenting out the database drivers you don't need and recompiling the binaries.

	_ "github.com/btnguyen2k/gocosmos"        // Azure Cosmos
	_ "github.com/denisenkom/go-mssqldb"      // Microsoft SQL Server
	_ "github.com/go-sql-driver/mysql"        // MySQL / MariaDB
	_ "github.com/lib/pq"                     // Postgres
	_ "github.com/mattn/go-sqlite3"           // SQLite
	_ "github.com/nakagami/firebirdsql"       // Firebird
	_ "github.com/ydb-platform/ydb-go-sdk/v3" // YandexDB

	log "golismero.com/g3log"
)

const SQL_DRIVER = "SQL_DRIVER"
const SQL_DSN = "SQL_DSN"

type SQLDBClient struct {
	db *sql.DB
}

type LogEntry struct {
	Timestamp int64         `json:"timestamp"   validate:"gte=0"`
	ScanID string           `json:"scanid"      validate:"required,uuid4"`
	TaskID string           `json:"taskid"      validate:"required,uuid4"`
	Text string             `json:"text"`
}

type TaskLogLine struct {
	Timestamp int64         `json:"timestamp"       validate:"gte=0"`
	Text string             `json:"text"`
}
type G3TaskLog struct {
	ScanID string           `json:"scanid"          validate:"required,uuid4"`
	TaskID string           `json:"taskid"          validate:"required,uuid4"`
	Start int64             `json:"start,omitempty" validate:"gte=0"`
	End int64               `json:"end,omitempty"   validate:"gte=0"`
	Lines []TaskLogLine     `json:"lines,omitempty" validate:"dive"`
}
func (log G3TaskLog) String() string {
	var text string
	for _, line := range log.Lines {
		text = text + fmt.Sprintf("[%s]\t%s\n", time.Unix(line.Timestamp, 0), StripAnsi(line.Text))
	}
	return text
}

type ScanStatusEntry struct {
	ScanID string           `json:"scanid"      validate:"required,uuid4"`
	Status G3SCANSTATUS     `json:"status"      validate:"required"`
	Progress int            `json:"progress"    validate:"gte=0,lte=100"`
	Message string          `json:"message"`
}

type TaskStatusEntry struct {
	TaskID     string       `json:"taskid"                   validate:"required,uuid4"`
	Tool       string       `json:"tool,omitempty"`
	Worker     string       `json:"worker,omitempty"`
	State      string       `json:"state,omitempty"`          // RUNNING / DONE / ERROR / CANCELED (from Redis)
	DispatchTS int64        `json:"dispatch_ts,omitempty"`
	StartTS    int64        `json:"start_ts,omitempty"`
	CompleteTS int64        `json:"complete_ts,omitempty"`
	ErrorMsg   string       `json:"error_msg,omitempty"`
	FirstLogTS int64        `json:"first_log_ts"             validate:"gte=0"`
	LastLogTS  int64        `json:"last_log_ts"              validate:"gte=0"`
	LineCount  int          `json:"line_count"               validate:"gte=0"`
	AgeSeconds int64        `json:"age_seconds"              validate:"gte=0"`
}

// Response container for /scan/tasks/status. Bundles the scan-level status
// alongside per-task entries so the client can render a coherent view
// (e.g. suppress the age column for terminal scans).
type ScanTaskStatusResponse struct {
	ScanStatus G3SCANSTATUS      `json:"scan_status"`
	Tasks      []TaskStatusEntry `json:"tasks"`
}

type QueryLogCallback func(LogEntry)(error)

// Connect to the SQL database.
func ConnectToSQL() (SQLDBClient, error) {
	c := SQLDBClient{}

	// Get the connection string.
	dbtype := os.Getenv(SQL_DRIVER)
	if dbtype == "" {
		return c, errors.New("missing environment variable: " + SQL_DRIVER)
	}
	dsn := os.Getenv(SQL_DSN)
	if dsn == "" {
		return c, errors.New("missing environment variable: " + SQL_DSN)
	}

	// Connect to the database.
	db, err := sql.Open(dbtype, dsn)
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
func QueryLog(db SQLDBClient, callback QueryLogCallback, args ...string) (error) {
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
	for i := range(args) {
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

	// Get the task IDs from the log. Since we always output on line of log
	// before the task is even run, this should work well enough for our
	// purposes, which is mostly recovering logs anyway.
	query := "SELECT UNIQUE(`taskid`) FROM `logs` ORDER BY `timestamp`, `id` ASC"
	rows, err := db.db.Query(query)
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
	callback := func(entry LogEntry)(error) {
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

// Update the progress of a scan.
func UpdateScanProgress(db SQLDBClient, scanid string, status G3SCANSTATUS, progress *int, message string) error {
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
		if ! found {
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

	if !correct {
		return errors.New("invalid call to UpdateScanProgress(), nothing to update")
	}
	query = query[:len(query) - 2] + " WHERE `scanid` = ?"
	args = append(args, scanid)
	_, err := db.db.ExecContext(context.Background(), query, args...)
	return err
}

// Get the progress of each scan.
func GetProgressList(db SQLDBClient) ([]ScanStatusEntry, error) {
	var scanstatus []ScanStatusEntry
	var err error
	var validate = validator.New()

	query := "SELECT `scanid`, `status`, `progress`, `message` FROM `progress`"
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

// Log in to the application.
func Login(db SQLDBClient, username, password string) bool {
	query := "SELECT `password` FROM `users` WHERE `username` = ?"
	var hashed []byte
	err := db.db.QueryRow(query, username).Scan(&hashed)
	if err != nil {
		log.Error(err.Error())
		return false
	}
	return bcrypt.CompareHashAndPassword(hashed, []byte(password)) == nil
}

// Get the user ID for a username.
func GetUserID(db SQLDBClient, username string) int {
	query := "SELECT `id` FROM `users` WHERE `username` = ?"
	var userid int
	err := db.db.QueryRow(query, username).Scan(&userid)
	if err != nil {
		log.Error(err.Error())
		return 0
	}
	return userid
}

// Check if a user is authorized to access a scan.
// Returns 1 if authorized, 0 if not, -1 if the scan does not exist.
func IsUserAuthorized(db SQLDBClient, userid int, scanid string) (int, error) {

	// Get a Tx for making transaction requests.
	tx, err := db.db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Error(err.Error())
		return 0, err
	}

	// Defer a rollback in case anything fails.
	defer tx.Rollback()

	// Check if the scan exists.
	query := "SELECT COUNT(`id`) FROM `scans` WHERE `scanid` = ? LIMIT 1"
	var scanExists int
	err = tx.QueryRow(query, scanid).Scan(&scanExists)
	if err != nil {
		log.Error(err.Error())
		return 0, err
	}

	// Check if the user is authorized for that scan.
	// We issue both queries for regular users to mitigate possible timing attacks.
	// For the admin user we skip this query.
	query = "SELECT COUNT(`id`) FROM `scans` WHERE `userid` = ? AND `scanid` = ? LIMIT 1"
	var isAuthorized int
	if userid == 1 {
		isAuthorized = 1
	} else {
		err = tx.QueryRow(query, userid, scanid).Scan(&isAuthorized)
		if err != nil {
			log.Error(err.Error())
			return 0, err
		}
	}

	// Return -1 if the scan does not exist, 1 or 0 if the user is authorized or not.
	if scanExists == 0 {
		return -1, nil
	}
	return isAuthorized, nil
}

// Grant permissions to a user to access a given scan.
func AddUserToScan(db SQLDBClient, userid int, scanid string) error {
	query := "INSERT INTO `scans` (`userid`, `scanid`) VALUES (?, ?)"
	_, err := db.db.ExecContext(context.Background(), query, userid, scanid)
	return err
}

// Get the list of scan IDs this user can access.
func GetScansForUser(db SQLDBClient, userid int) ([]string, error) {
	var scanidlist []string
	query := "SELECT `scanid` FROM `scans` WHERE `userid` = ? or 1 = ?"
	rows, err := db.db.Query(query, userid, userid)
	if err != nil {
		return scanidlist, err
	}
	defer rows.Close()
	for rows.Next() {
		var scanid string
		e := rows.Scan(&scanid)
		if e != nil {
			err = e
			continue
		}
		scanidlist = append(scanidlist, scanid)
	}
	return scanidlist, err
}

// Remove permissions from a user to access a given scan.
func RemoveUserFromScan(db SQLDBClient, userid int, scanid string) error {
	query := "DELETE FROM `scans` WHERE `userid` = ? AND `scanid` = ?"
	_, err := db.db.ExecContext(context.Background(), query, userid, scanid)
	return err
}
