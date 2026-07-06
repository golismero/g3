package g3lib

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/golismero/g3/src/g3"
)

const SQL_DSN = "SQL_DSN"

type SQLDBClient struct {
	db *sql.DB
	ctx context.Context
}

// CREATE TABLE IF NOT EXISTS scans (
//     scanid UUID PRIMARY KEY NOT NULL,
//     status VARCHAR(16) NOT NULL DEFAULT 'waiting',
//     progress INTEGER UNSIGNED NOT NULL DEFAULT 0,
//     message VARCHAR(255) DEFAULT NULL,
//     created_at BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
//     started_at BIGINT UNSIGNED DEFAULT NULL,
//     ended_at BIGINT UNSIGNED DEFAULT NULL,
//     last_updated_at BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
//     last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0
// )
func ScanStatusFromRows(rows *sql.Rows, status *g3.ScanStatusResponse) error {
	return rows.Scan(
		&status.ScanID,
		&status.Status,
		&status.Progress,
		&status.Message,
		&status.CreatedAt,
		&status.StartedAt,
		&status.EndedAt,
		&status.LastUpdatedAt,
		&status.LastSeq,
	)
}
func ScanStatusFromRow(row *sql.Row, status *g3.ScanStatusResponse) error {
	return row.Scan(
		&status.ScanID,
		&status.Status,
		&status.Progress,
		&status.Message,
		&status.CreatedAt,
		&status.StartedAt,
		&status.EndedAt,
		&status.LastUpdatedAt,
		&status.LastSeq,
	)
}

// CREATE TABLE IF NOT EXISTS tasks (
//     taskid UUID PRIMARY KEY NOT NULL,
//     scanid UUID NOT NULL,
//     status VARCHAR(16) NOT NULL DEFAULT 'waiting',
//     tool VARCHAR(64) DEFAULT NULL,
//     worker VARCHAR(64) DEFAULT NULL,
//     created_at BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
//     started_at BIGINT UNSIGNED DEFAULT NULL,
//     ended_at BIGINT UNSIGNED DEFAULT NULL,
//     last_updated_at BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
//     last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0
// )
func TaskStatusFromRows(rows *sql.Rows, status *g3.TaskStatusResponse, scanid *string) error {
	return rows.Scan(
		&status.TaskID,
		&scanid,
		&status.Status,
		&status.Tool,
		&status.Worker,
		&status.CreatedAt,
		&status.StartedAt,
		&status.EndedAt,
		&status.LastUpdatedAt,
		&status.LastSeq,
	)
}
func TaskStatusFromRow(row *sql.Row, status *g3.TaskStatusResponse, scanid *string) error {
	return row.Scan(
		&status.TaskID,
		&scanid,
		&status.Status,
		&status.Tool,
		&status.Worker,
		&status.CreatedAt,
		&status.StartedAt,
		&status.EndedAt,
		&status.LastUpdatedAt,
		&status.LastSeq,
	)
}

// Connect to the SQL database.
func ConnectToSQL() (SQLDBClient, error) {
	return ConnectToSQLWithContext(nil)
}

// Connect to the SQL database.
func ConnectToSQLWithContext(ctx context.Context) (SQLDBClient, error) {
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

	// Provide a background context if none is given.
	// This is non-cancellable and has no timeout, so it kinda sucks.
	if ctx == nil {
		ctx = context.Background()
	}

	// Return the DB client object.
	c.db = db
	c.ctx = ctx
	return c, nil
}

// Defer this call after calling ConnectToSQL().
func (c SQLDBClient) Close() {
	if c.db != nil {
		c.db.Close()
		c.db = nil
	}
}

// Add a log line to the database.
func (c SQLDBClient) SaveLogLine(scanid, taskid, text string) error {
	query := "INSERT INTO logs (scanid, taskid, text) VALUES (?, ?, ?)"
	_, err := c.db.ExecContext(c.ctx, query, scanid, taskid, text)
	return err
}

// Get the log lines for a specific task execution.
func (c SQLDBClient) GetLogsForTask(scanid string, taskid string) (g3.TaskLogsResponse, error) {
	var response = g3.TaskLogsResponse{TaskID: taskid}
	query := "SELECT timestamp, text FROM logs WHERE taskid=? ORDER BY (taskid, timestamp, id)"
	rows, err := c.db.QueryContext(c.ctx, query, taskid)
	if err != nil {
		return response, err
	}
	defer rows.Close()
	for rows.Next() {
		var line g3.LogLine
		err = rows.Scan(&line.Timestamp, &line.Text)
		if err != nil {
			return response, err
		}
		response.Logs = append(response.Logs, line)
	}
	return response, rows.Err()
}

// Get the log lines for an entire scan.
func (c SQLDBClient) GetLogsForScan(scanid string) (g3.ScanLogsResponse, error) {
	var response = g3.ScanLogsResponse{ScanID: scanid}
	query := "SELECT taskid, timestamp, text FROM logs WHERE scanid=? ORDER BY (taskid, timestamp, id)"
	rows, err := c.db.QueryContext(c.ctx, query, scanid)
	if err != nil {
		return response, err
	}
	defer rows.Close()
	for rows.Next() {
		var taskid string
		var line g3.LogLine
		err = rows.Scan(&taskid, &line.Timestamp, &line.Text)
		if err != nil {
			return response, err
		}
		found := false
		for _, tasklogs := range(response.Logs) {
			if tasklogs.TaskID == taskid {
				tasklogs.Logs = append(tasklogs.Logs, line)
				found = true
			}
		}
		if !found {
			var tlog = g3.TaskLogsResponse{TaskID: taskid}
			tlog.Logs = append(tlog.Logs, line)
			response.Logs = append(response.Logs, tlog)
		}
	}
	return response, rows.Err()
}

// Create a new scan status row.
func (c SQLDBClient) CreateScanStatus(scanid string, is_managed bool) error {
	var err error
	if is_managed {
		_, err = c.db.ExecContext(c.ctx, "INSERT INTO scans (scanid, status) VALUES (?, ?)", scanid, "managed")
	} else {
		_, err = c.db.ExecContext(c.ctx, "INSERT INTO scans (scanid) VALUES (?)", scanid)
	}
	return err
}

// Delete a scan status entry from the SQL database.
// This will cascade delete all related information for this scan, including logs.
func (c SQLDBClient) DeleteScanStatus(scanid string) error {
	_, err := c.db.ExecContext(c.ctx, "DELETE FROM scans WHERE scanid=?", scanid)
	return err
}

// Saves a received status update message from the scanner, if the sequence number is newer.
func (c SQLDBClient) UpdateScanStatus(scanid string, status *string, progress *uint64, message *string, seq uint64) error {
	var query = "UPDATE scans SET "
	var args = []any{}
	if status != nil {
		query += "status=?, "
		args = append(args, *status)
	}
	if progress != nil {
		query += "progress=?, "
		args = append(args, *progress)
	}
	if message != nil {
		query += "message=?, "
		args = append(args, *message)
	}
	query += "last_seq=? "
	args = append(args, seq)
	query += "WHERE scanid=?"
	args = append(args, scanid)
	_, err := c.db.ExecContext(c.ctx, query, args...)
	return err
}

// Create a new task status row.
func (c SQLDBClient) CreateTaskStatus(scanid string, taskid string) error {
	_, err := c.db.ExecContext(c.ctx, "INSERT INTO tasks (scanid, taskid) VALUES (?, ?)", scanid, taskid)
	return err
}

// Delete a task status entry from the SQL database.
// This will cascade delete all related information for this task, including logs.
func (c SQLDBClient) DeleteTaskStatus(taskid string) error {
	_, err := c.db.ExecContext(c.ctx, "DELETE FROM tasks WHERE taskid=?", taskid)
	return err
}

// Updates a task status entry, following the state machine logic.
func (c SQLDBClient) UpdateTaskStatus(taskid string, status *string, tool *string, worker *string) error {
	var query = "UPDATE tasks SET "
	var args = []any{}
	if status != nil {
		query += "status=?, "
		args = append(args, *status)
	}
	if tool != nil {
		query += "tool=?, "
		args = append(args, *tool)
	}
	if worker != nil {
		query += "worker=?, "
		args = append(args, *worker)
	}
	query += "last_seq=last_seq+1 "
	query += "WHERE taskid=?"
	args = append(args, taskid)
	_, err := c.db.ExecContext(c.ctx, query, args...)
	return err
}

// Resolves a scan ID from a given task ID.
func (c SQLDBClient) GetScanIdFromTaskId(taskid string) (string, error) {
	var scanid string
	err := c.db.QueryRowContext(c.ctx, "SELECT scanid FROM tasks WHERE taskid=?", taskid).Scan(&scanid)
	return scanid, err
}

// Helper to get just the scan state.
func (c SQLDBClient) GetScanStatus(scanid string) (string, error) {
	var status string
	err := c.db.QueryRowContext(c.ctx, "SELECT status FROM scans WHERE scanid=?", scanid).Scan(&status)
	return scanid, err
}

// Helper to get just the task state.
func (c SQLDBClient) GetTaskStatus(taskid string) (string, error) {
	var status string
	err := c.db.QueryRowContext(c.ctx, "SELECT status FROM tasks WHERE taskid=?", taskid).Scan(&status)
	return taskid, err
}

// Gets the current status of a single scan.
func (c SQLDBClient) GetSingleScanStatus(scanid string) (g3.ScanStatusResponse, error) {
	var status g3.ScanStatusResponse
	err := ScanStatusFromRow(c.db.QueryRowContext(c.ctx, "SELECT * FROM scans WHERE scanid=?", scanid), &status)
	return status, err
}

// Gets the current status of a single task.
func (c SQLDBClient) GetSingleTaskStatus(taskid string) (g3.TaskStatusResponse, error) {
	var status g3.TaskStatusResponse
	var unused string
	err := TaskStatusFromRow(c.db.QueryRowContext(c.ctx, "SELECT * FROM tasks WHERE taskid=?", taskid), &status, &unused)
	return status, err
}

// Gets the status of all tasks in a scan.
func (c SQLDBClient) GetScanTasksStatus(scanid string) (g3.ScanTasksResponse, error) {
	var response g3.ScanTasksResponse
	rows, err := c.db.QueryContext(c.ctx, "SELECT * FROM tasks WHERE scanid=?", scanid)
	if err != nil {
		return response, err
	}
	defer rows.Close()
	for rows.Next() {
		var status g3.TaskStatusResponse
		err = TaskStatusFromRows(rows, &status, &response.ScanID)
		if err != nil {
			return response, err
		}
		response.Tasks = append(response.Tasks, status)
	}
	return response, rows.Err()
}

// Gets a full status snapshot of a scan and all of its tasks.
func (c SQLDBClient) GetScanFullStatus(scanid string) (g3.ScanFullResponse, error) {
	var response g3.ScanFullResponse
	tx, err := c.db.BeginTx(c.ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return response, err
	}
	defer tx.Rollback()
	err = ScanStatusFromRow(tx.QueryRowContext(c.ctx, "SELECT * FROM scans WHERE scanid=?", scanid), &response.ScanStatusResponse)
	if err != nil {
		return response, err
	}
	rows, err := tx.QueryContext(c.ctx, "SELECT * FROM tasks WHERE scanid=?", scanid)
	if err != nil {
		return response, err
	}
	defer rows.Close()
	for rows.Next() {
		var status g3.TaskStatusResponse
		err = TaskStatusFromRows(rows, &status, &response.ScanID)
		if err != nil {
			return response, err
		}
		response.Tasks = append(response.Tasks, status)
	}
	return response, rows.Err()
}

// Gets the status of all scans in the server.
func (c SQLDBClient) GetAllScansStatus() (g3.AllScansStatusResponse, error) {
	var response g3.AllScansStatusResponse
	rows, err := c.db.QueryContext(c.ctx, "SELECT * FROM scans")
	if err != nil {
		return response, err
	}
	defer rows.Close()
	for rows.Next() {
		var status g3.ScanStatusResponse
		err = ScanStatusFromRows(rows, &status)
		if err != nil {
			return response, err
		}
		response.Scans = append(response.Scans, status)
	}
	return response, rows.Err()
}

// Gets a full status snapshot for the entire server.
func (c SQLDBClient) GetAllScansAndTasksStatus() (g3.AllScansFullResponse, error) {
	var response g3.AllScansFullResponse
	tx, err := c.db.BeginTx(c.ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return response, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(c.ctx, "SELECT * FROM scans")
	if err != nil {
		return response, err
	}
	defer rows.Close()
	for rows.Next() {
		var status g3.ScanStatusResponse
		err = ScanStatusFromRows(rows, &status)
		if err != nil {
			return response, err
		}
		var info g3.ScanFullResponse
		info.ScanStatusResponse = status
		response.Scans = append(response.Scans, info)
	}
	err = rows.Err()
	if err != nil {
		return response, err
	}
	rows, err = tx.QueryContext(c.ctx, "SELECT * FROM tasks")
	if err != nil {
		return response, err
	}
	defer rows.Close()
	for rows.Next() {
		var status g3.TaskStatusResponse
		var scanid string
		err = TaskStatusFromRows(rows, &status, &scanid)
		if err != nil {
			return response, err
		}
		for _, info := range(response.Scans) {
			if info.ScanID == scanid {
				info.Tasks = append(info.Tasks, status)
			}
		}
	}
	return response, rows.Err()
}
