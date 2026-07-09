package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golismero/g3/src/g3"
)

type Client struct {
	BaseURL string
	WSURL   string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, wsURL, token string) *Client {
	return &Client{BaseURL: baseURL, WSURL: wsURL, Token: token, HTTP: http.DefaultClient}
}

// call is a thin convenience over g3.MakeApiRequest that decodes Data
// into the caller's destination via json round-trip. We use this rather
// than asserting on map[string]interface{} as g3cli does — keeps the
// per-endpoint methods short.
func (c *Client) call(ctx context.Context, endpoint string, body any, dest any) error {
	resp, err := g3.MakeApiRequest(ctx, c.BaseURL, endpoint, c.Token, body)
	if err != nil {
		return err
	}
	if resp.Status != "success" {
		msg := "API error"
		if s, ok := resp.Data.(string); ok && s != "" {
			msg = s
		}
		return errors.New(msg)
	}
	if dest == nil || resp.Data == nil {
		return nil
	}
	raw, err := json.Marshal(resp.Data)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dest)
}

// ListScans → /scan/list. Returns just the IDs (the server response shape).
func (c *Client) ListScans(ctx context.Context) ([]string, error) {
	var out []string
	if err := c.call(ctx, "/scan/list", g3.ReqEnumerateScans{}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetProgress → /scan/progress. Returns the full progress table.
func (c *Client) GetProgress(ctx context.Context) ([]g3.ScanStatusEntry, error) {
	var out []g3.ScanStatusEntry
	if err := c.call(ctx, "/scan/progress", g3.ReqGetScanProgressTable{}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTaskStatus → /scan/tasks/status for one scan.
func (c *Client) GetTaskStatus(ctx context.Context, scanID string) (g3.ScanTaskStatusResponse, error) {
	var out g3.ScanTaskStatusResponse
	err := c.call(ctx, "/scan/tasks/status", g3.ReqQueryScanTaskStatus{ScanID: scanID}, &out)
	return out, err
}

// GetTaskLogs → /scan/logs for one (scan, task). Returns the existing
// G3TaskLog response (top-level taskid, lines:[{timestamp,text}]).
func (c *Client) GetTaskLogs(ctx context.Context, scanID, taskID string) (g3.G3TaskLog, error) {
	var out g3.G3TaskLog
	err := c.call(ctx, "/scan/logs", g3.ReqQueryLog{ScanID: scanID, TaskID: taskID}, &out)
	return out, err
}

// GetScanLogs → /scan/logs with empty TaskID, returning all rows for
// the scan as []LogEntry (chronologically interleaved per the server's
// ORDER BY timestamp,id ASC). Used by the full-screen logs viewer.
func (c *Client) GetScanLogs(ctx context.Context, scanID string) ([]g3.LogEntry, error) {
	var out []g3.LogEntry
	err := c.call(ctx, "/scan/logs", g3.ReqQueryLog{ScanID: scanID}, &out)
	return out, err
}

// GetReport dispatches the magenta reporter plugin for the scan, waits for the
// reporter task to complete, then downloads the produced report. Returns
// (markdown, errorsText, error); errorsText is retained for signature
// compatibility and is always empty now that reporting is delegated to the
// plugin (the built-in reporter has been removed). Safe to call from a tea.Cmd
// goroutine — it blocks while polling.
func (c *Client) GetReport(ctx context.Context, scanID string) (string, string, error) {
	// 1. Dispatch the magenta reporter.
	var dispatch struct {
		TaskIDs []string `json:"task_ids"`
	}
	if err := c.call(ctx, "/scan/task/dispatch", g3.ReqTaskDispatch{ScanID: scanID, Kind: "report", Tool: "magenta"}, &dispatch); err != nil {
		return "", "", err
	}
	if len(dispatch.TaskIDs) == 0 {
		return "", "", errors.New("no reporter task was dispatched")
	}
	taskID := dispatch.TaskIDs[0]

	// 2. Poll until the reporter task reaches a terminal state.
	state := ""
	for {
		status, err := c.GetTaskStatus(ctx, scanID)
		if err != nil {
			return "", "", err
		}
		state = ""
		for _, t := range status.Tasks {
			if t.TaskID == taskID {
				state = t.State
				break
			}
		}
		if state == "DONE" || state == "ERROR" || state == "CANCELED" {
			break
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if state != "DONE" {
		return "", "", fmt.Errorf("reporter task did not complete (state: %s)", state)
	}

	// 3. Download the report artifact into memory.
	var buf bytes.Buffer
	if err := g3.DownloadFile(ctx, c.BaseURL, "/scan/task/artifacts", c.Token, g3.ReqTaskArtifacts{ScanID: scanID, TaskID: taskID}, &buf); err != nil {
		return "", "", err
	}
	return buf.String(), "", nil
}

// GetScanDataList → /scan/datalist. Returns all data object IDs for the
// scan. Used by [E] export to enumerate IDs before batch-fetching the
// objects themselves.
func (c *Client) GetScanDataList(ctx context.Context, scanID string) ([]string, error) {
	var out []string
	if err := c.call(ctx, "/scan/datalist", g3.ReqGetScanDataIDs{ScanID: scanID}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetScanData → /scan/data. Fetches the data objects for the given IDs
// in one batch. The server caps each call at 100 IDs; callers must
// batch larger sets. We follow g3cli's batch size of 20 for export.
// Returns the raw objects as []map[string]any so the caller can
// re-marshal each one with the desired indentation for output.
func (c *Client) GetScanData(ctx context.Context, scanID string, dataIDs []string) ([]map[string]any, error) {
	var out []map[string]any
	err := c.call(ctx, "/scan/data", g3.ReqLoadData{ScanID: scanID, DataIDs: dataIDs}, &out)
	return out, err
}

// StartScan → /scan/start. Returns the new scan ID.
func (c *Client) StartScan(ctx context.Context, script string) (string, error) {
	var out string
	err := c.call(ctx, "/scan/start", g3.ReqStartScan{Script: script}, &out)
	return out, err
}

// StopScan → /scan/stop.
func (c *Client) StopScan(ctx context.Context, scanID string) error {
	var sink any
	return c.call(ctx, "/scan/stop", g3.ReqStopScan{ScanID: scanID}, &sink)
}

// DeleteScan → /scan/delete.
func (c *Client) DeleteScan(ctx context.Context, scanID string) error {
	var sink any
	return c.call(ctx, "/scan/delete", g3.ReqDeleteScan{ScanID: scanID}, &sink)
}

// ListPlugins → /plugin/list.
func (c *Client) ListPlugins(ctx context.Context) ([]PluginListEntry, error) {
	var raw []g3.PluginListItem
	if err := c.call(ctx, "/plugin/list", g3.ReqListPlugins{}, &raw); err != nil {
		return nil, err
	}
	out := make([]PluginListEntry, 0, len(raw))
	for _, m := range raw {
		out = append(out, PluginListEntry{
			Name:        m.Name,
			URL:         m.URL,
			Description: m.Description,
			Importer:    m.IsImporter,
			Reporter:    m.IsReporter,
			Runnable:    m.IsRunnable,
		})
	}
	return out, nil
}

// UploadFile → /file/upload. Mirrors g3cli's multipart upload, returns the
// server-assigned file ID.
func (c *Client) UploadFile(ctx context.Context, localPath string) (string, error) {
	fd, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer fd.Close()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", filepath.Base(localPath))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, fd); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/file/upload", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upload failed: %s: %s", resp.Status, string(body))
	}
	var api g3.APIResponse
	if err := json.Unmarshal(body, &api); err != nil {
		return "", err
	}
	if api.Status != "success" {
		if s, ok := api.Data.(string); ok && s != "" {
			return "", errors.New(s)
		}
		return "", errors.New("upload rejected")
	}
	id, _ := api.Data.(string)
	if id == "" {
		return "", errors.New("upload returned empty file id")
	}
	return id, nil
}
