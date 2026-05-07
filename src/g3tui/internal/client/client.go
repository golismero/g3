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

	"golismero.com/g3lib"
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

// call is a thin convenience over g3lib.MakeApiRequest that decodes Data
// into the caller's destination via json round-trip. We use this rather
// than asserting on map[string]interface{} as g3cli does — keeps the
// per-endpoint methods short.
func (c *Client) call(ctx context.Context, endpoint string, body any, dest any) error {
	resp, err := g3lib.MakeApiRequest(ctx, c.BaseURL, endpoint, c.Token, body)
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
	if err := c.call(ctx, "/scan/list", g3lib.ReqEnumerateScans{}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetProgress → /scan/progress. Returns the full progress table.
func (c *Client) GetProgress(ctx context.Context) ([]g3lib.ScanStatusEntry, error) {
	var out []g3lib.ScanStatusEntry
	if err := c.call(ctx, "/scan/progress", g3lib.ReqGetScanProgressTable{}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTaskStatus → /scan/tasks/status for one scan.
func (c *Client) GetTaskStatus(ctx context.Context, scanID string) (g3lib.ScanTaskStatusResponse, error) {
	var out g3lib.ScanTaskStatusResponse
	err := c.call(ctx, "/scan/tasks/status", g3lib.ReqQueryScanTaskStatus{ScanID: scanID}, &out)
	return out, err
}

// GetLogs → /scan/logs for one (scan, task).
func (c *Client) GetLogs(ctx context.Context, scanID, taskID string) (g3lib.G3TaskLog, error) {
	var out g3lib.G3TaskLog
	err := c.call(ctx, "/scan/logs", g3lib.ReqQueryLog{ScanID: scanID, TaskID: taskID}, &out)
	return out, err
}

// GetReport → /scan/report. Returns (markdown, errorsText). The server
// ships errors alongside the report when generation had non-fatal issues.
func (c *Client) GetReport(ctx context.Context, scanID string) (string, string, error) {
	var raw struct {
		Report string `json:"report"`
		Errors string `json:"errors"`
	}
	if err := c.call(ctx, "/scan/report", g3lib.ReqReport{ScanID: scanID}, &raw); err != nil {
		return "", "", err
	}
	return raw.Report, raw.Errors, nil
}

// StartScan → /scan/start. Returns the new scan ID.
func (c *Client) StartScan(ctx context.Context, script string) (string, error) {
	var out string
	err := c.call(ctx, "/scan/start", g3lib.ReqStartScan{Script: script}, &out)
	return out, err
}

// StopScan → /scan/stop.
func (c *Client) StopScan(ctx context.Context, scanID string) error {
	var sink any
	return c.call(ctx, "/scan/stop", g3lib.ReqStopScan{ScanID: scanID}, &sink)
}

// DeleteScan → /scan/delete.
func (c *Client) DeleteScan(ctx context.Context, scanID string) error {
	var sink any
	return c.call(ctx, "/scan/delete", g3lib.ReqDeleteScan{ScanID: scanID}, &sink)
}

// ListPlugins → /plugin/list.
func (c *Client) ListPlugins(ctx context.Context) ([]PluginListEntry, error) {
	var raw []map[string]string
	if err := c.call(ctx, "/plugin/list", g3lib.ReqListPlugins{}, &raw); err != nil {
		return nil, err
	}
	out := make([]PluginListEntry, 0, len(raw))
	for _, m := range raw {
		out = append(out, PluginListEntry{
			Name:        m["name"],
			URL:         m["url"],
			Description: m["description"],
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
	var api g3lib.APIResponse
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
