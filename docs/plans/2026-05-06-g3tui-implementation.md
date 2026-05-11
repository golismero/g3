# g3tui Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `g3tui`, an interactive terminal UI that coexists with `g3cli` and covers six operator workflows (create scan, monitor, cancel, view logs, view report, delete) against the existing `g3api` HTTP/WebSocket surface.

**Architecture:** Single Go binary at `src/g3tui/`, three internal packages (`client/` for I/O, `pipelines/` for embedded+user scan-type registry, `ui/` for Bubble Tea models). Persistent dashboard with left scan list (WS-driven) + right detail pane that swaps between task table, log viewer, report viewer, and a modal new-scan wizard.

**Tech Stack:** Go (per `src/*/go.mod`, currently `1.26.2`); Bubble Tea + Bubbles + Lip Gloss + Glamour; reuses `g3lib` request/response types; no new server endpoints.

**Source spec:** [`docs/plans/2026-05-06-g3tui-design.md`](2026-05-06-g3tui-design.md)

**Status:** Tier 0 detailed and ready to implement. Tiers 1–3 outlined only — detail each at its own kickoff per project convention (memory: `feedback_tiered_implementation_plans.md`).

**Tests are user-owned** (memory: `feedback_tests_are_user_owned.md`). The plan does not include test-writing tasks. **Agent verification per task is strictly `go build` + `golangci-lint run ./...`.** Running the binary, hitting the live API, and any other behavioral verification is user-owned — agents do not run smoke tests, do not source `.env` and exec `bin/g3tui`, and do not bring `docker compose` services up/down/restart. Suggested smoke commands appear in each task as guidance for the user; agents skip those steps.

**Git is user-owned** (memory: `feedback_git_is_user_owned.md`). Agents must not run mutating git commands. Each task ends at a "STOP — user commits" checkpoint with a suggested commit message in plain text; the user commits at their chosen boundaries. Read-only inspection (`git status`, `git diff`, `git log`) is fine.

---

## Tier overview

| Tier | End state | Status |
|---|---|---|
| **0 — Foundations** | `make bin` produces `bin/g3tui`. Running it loads env, fetches `/scan/list` once, prints scan IDs, then exits. Pipelines package loads embedded + user scan types. Client package has typed wrappers for every endpoint, the `tea.Msg` types, the WS scanprogress subscription with reconnect FSM, and the generic poller. `golangci-lint` clean. No TUI yet. | Implemented |
| **1 — Dashboard** | Persistent dashboard launches: left panel shows live scan list (WS), right pane shows per-task table for selected scan (2s poll), header connection indicator, footer keybinds, cancel/delete confirmation flows. Initial connection failure goes to a full-screen retry/quit prompt. | Implemented; layout/columns/scrolling rebrainstormed and reimplemented in the [2026-05-08 redesign](2026-05-08-g3tui-layout-redesign-design.md) |
| **2 — New-scan wizard** | `[N]` opens the modal overlay. Targets textarea, imports overlay (tool-first batch picker → multi-file picker), mode toggle, scan-type list with `Custom…`, parallel uploads (cap 4), `/scan/start`. New scan appears in left panel via WS push. | Implemented |
| **3 — Logs & report viewers + README** | `[L]` opens log viewer with task switcher, 2s polling, follow-tail, save-to-file. `[R]` opens Glamour-rendered report with save-as-Markdown. Both pause polling on terminal scan state. `src/g3tui/README.md` written (env vars, build, install, six workflows, config-dir overrides). | Outlined; not yet started |

---

## Prerequisites

Before starting Tier 0:

- A reachable `g3api`. The fastest path is `docker compose up` from the repo root, which boots Mongo + MariaDB + Mosquitto + Redis + nginx + `g3api` per `docker-compose.yml`.
- A populated `.env` with at least `G3_API_BASEURL`, `G3_API_WSURL`, `G3_API_TOKEN`. These are the same vars `g3cli` uses, so an existing working `g3cli` setup transfers directly.
- One or more scans already in the database is helpful for behavioral verification of `ListScans` / `GetProgress`. If empty, seed by running `g3cli scan -i samples/example.script` in a separate terminal before each smoke run.
- `go` toolchain matching `src/*/go.mod` (currently `1.26.2`); `golangci-lint` for the lint check.

If any verification step fails, stop and report — don't paper over connection or env issues.

---

## Tier 0 — Foundations

**Intent.** Stand up the module, build integration, pipelines registry, and client package. Prove that the binary builds, env loads, and every API call/subscription works end-to-end against a live `g3api`. No TUI yet — `main()` is a smoke-test driver that exercises each part of the client package and exits.

**End state.**
- `bin/g3tui` exists and is built by `make bin`.
- `bin/g3tui` reads `.env`, requires `G3_API_BASEURL`, `G3_API_WSURL`, `G3_API_TOKEN`, fails with a clear message otherwise.
- Running `bin/g3tui` against a live `g3api` prints the list of scans, the loaded pipelines (with sources), and a brief WS scanprogress smoke-test output, then exits.
- `internal/client/` has typed wrappers for every endpoint the TUI will use, `tea.Msg` types for every event, a generic poller, and a WS subscription with reconnect FSM.
- `internal/pipelines/` loads embedded + user-supplied `.pipeline` files with the merge rule.

**Verification per task.** Agent-side: `go build` (or `make bin`) succeeds, and `golangci-lint run ./...` is clean. That is the entire scope of agent verification. Each task lists "Run: ... bin/g3tui" smoke-test commands and "Expected: ..." outputs — those are guidance for the **user** to run if they want to verify behaviorally. Agents do not execute the binary, do not source `.env`, and do not poke the live API. The user commits at each task's STOP checkpoint (or batches commits at the tier boundary — see memory: `feedback_plan_commit_cadence.md`). No automated tests in this plan (those are user-owned).

**Prerequisites.** A reachable `g3api` (compose stack `docker compose up`) with `G3_API_TOKEN` set, plus `.env` populated. A scan or two already in the database is helpful for Task 0.5 verification; the `samples/` directory has scripts you can submit via `g3cli` to seed state.

---

### Task 0.1: Module skeleton and stub `main`

**Files:**
- Create: `src/g3tui/go.mod`
- Create: `src/g3tui/main.go`

- [ ] **Step 1: Create `src/g3tui/go.mod`**

```
module golismero.com/g3tui

go 1.26.2

replace golismero.com/g3lib => ../g3lib

replace golismero.com/g3log => ../g3log

require (
	golismero.com/g3lib v0.0.0-00010101000000-000000000000
	golismero.com/g3log v0.0.0-00010101000000-000000000000
)
```

- [ ] **Step 2: Create `src/g3tui/main.go` with env loading and required-var check**

```go
package main

import (
	"fmt"
	"os"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)

const (
	G3_API_BASEURL    = "G3_API_BASEURL"
	G3_API_WSURL      = "G3_API_WSURL"
	G3_API_TOKEN      = "G3_API_TOKEN"
	G3_PIPELINES_DIR  = "G3_PIPELINES_DIR"
	G3_CMD_LOG_LEVEL  = "G3_CMD_LOG_LEVEL"
)

type config struct {
	BaseURL      string
	WSURL        string
	Token        string
	PipelinesDir string
}

func loadConfig() (config, error) {
	g3lib.LoadDotEnvFile() //nolint:errcheck

	cfg := config{
		BaseURL:      os.Getenv(G3_API_BASEURL),
		WSURL:        os.Getenv(G3_API_WSURL),
		Token:        os.Getenv(G3_API_TOKEN),
		PipelinesDir: os.Getenv(G3_PIPELINES_DIR),
	}
	for name, v := range map[string]string{
		G3_API_BASEURL: cfg.BaseURL,
		G3_API_WSURL:   cfg.WSURL,
		G3_API_TOKEN:   cfg.Token,
	} {
		if v == "" {
			return cfg, fmt.Errorf("missing required environment variable: %s", name)
		}
	}
	return cfg, nil
}

func main() {
	log.InitLogger()
	if ll := os.Getenv(G3_CMD_LOG_LEVEL); ll != "" {
		log.SetLogLevel(ll)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Critical(err.Error())
		os.Exit(1)
	}

	fmt.Printf("g3tui — config loaded\n")
	fmt.Printf("  BaseURL = %s\n", cfg.BaseURL)
	fmt.Printf("  WSURL   = %s\n", cfg.WSURL)
	fmt.Printf("  Token   = (%d bytes)\n", len(cfg.Token))
}
```

- [ ] **Step 3: Resolve module deps**

Run: `cd src/g3tui && go mod tidy`

Expected: `go.sum` is created; no errors. The `replace` directives keep `g3lib`/`g3log` local.

- [ ] **Step 4: Build the binary**

Run: `cd src/g3tui && go build -o /tmp/g3tui-smoke .`

Expected: clean build, no output.

- [ ] **Step 5: Run with missing vars to see the error**

Run: `env -u G3_API_BASEURL /tmp/g3tui-smoke`

Expected: `CRITICAL: missing required environment variable: G3_API_BASEURL`, exit code 1.

- [ ] **Step 6: Run with all vars set to confirm happy path**

Run: `(set -a; source .env; set +a; /tmp/g3tui-smoke)` (from the repo root with `.env` populated)

Expected: three lines reporting BaseURL, WSURL, and a non-zero token byte count.

- [ ] **Step 7: STOP — user commit checkpoint**

Working tree at this point:
- Created: `src/g3tui/go.mod`, `src/g3tui/go.sum`, `src/g3tui/main.go`

Suggested commit message: `g3tui: module skeleton with env-var config loader`

Stop here and let the user commit before starting the next task.

---

### Task 0.2: Wire `g3tui` into the Makefile

**Files:**
- Modify: `src/Makefile`
- Modify: `Makefile`

- [ ] **Step 1: Add the `g3tui` build target to `src/Makefile`**

Append to `src/Makefile`:

```makefile

../bin/g3tui: g3lib g3log
	cd g3tui && go mod tidy && go build -o ../../bin/g3tui
```

And update the `all` target:

```makefile
all: ../bin/g3 ../bin/g3api ../bin/g3cli ../bin/g3config ../bin/g3scanner ../bin/g3worker ../bin/g3tui
```

- [ ] **Step 2: Add the install symlink line in the top-level `Makefile`**

Inside the `install:` recipe, add:

```makefile
	sudo ln -s -f $$(pwd)/bin/g3tui /usr/bin/g3tui
```

(Place it in alphabetical order with the existing six lines.)

- [ ] **Step 3: Run `make bin` from repo root**

Run: `make bin`

Expected: all seven binaries built, including `bin/g3tui`. No errors.

- [ ] **Step 4: Verify the binary runs**

Run: `(set -a; source .env; set +a; bin/g3tui)`

Expected: same three-line output from Task 0.1, Step 6, but now from `bin/g3tui`.

- [ ] **Step 5: STOP — user commit checkpoint**

Working tree at this point:
- Modified: `src/Makefile`, `Makefile`

Suggested commit message: `g3tui: wire into top-level and src Makefiles`

Stop here and let the user commit before starting the next task.

---

### Task 0.3: Pipelines package — embed and load defaults

**Files:**
- Create: `src/g3tui/internal/pipelines/pipelines.go`
- Create: `src/g3tui/internal/pipelines/embed.go`
- Modify: `src/g3tui/main.go`

Note: `src/g3tui/internal/pipelines/{network,web}.pipeline` are already in place (moved into the package directory so the embed directive doesn't need to traverse `..`). The `//go:embed` directive reads them as siblings of the source file.

- [ ] **Step 1: Create `src/g3tui/internal/pipelines/pipelines.go`**

```go
// Package pipelines loads the scan-type catalog: embedded defaults
// (compiled into the binary) plus optional user files dropped into a
// configurable directory. User files override embedded ones with the
// same basename. Validation is best-effort — invalid files are logged
// and skipped, never fatal.
package pipelines

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)

type Source string

const (
	SourceEmbedded Source = "embedded"
	SourceUser     Source = "user"
)

type Pipeline struct {
	Name    string
	Source  Source
	Content string
}

// Load returns the merged pipeline catalog. userDir may be empty (then the
// xdg fallback is used). A missing user dir is not an error. Returned slice
// is sorted alphabetically by Name.
func Load(userDir string) ([]Pipeline, error) {
	merged := map[string]Pipeline{}

	for name, content := range embedded() {
		merged[name] = Pipeline{Name: name, Source: SourceEmbedded, Content: content}
	}

	resolved := userDir
	if resolved == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			resolved = filepath.Join(home, ".config", "g3tui", "pipelines")
		}
	}
	if resolved != "" {
		userPipelines, err := loadDir(resolved)
		if err != nil {
			return nil, err
		}
		for name, content := range userPipelines {
			merged[name] = Pipeline{Name: name, Source: SourceUser, Content: content}
		}
	}

	out := make([]Pipeline, 0, len(merged))
	for _, p := range merged {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func loadDir(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pipeline") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Warningf("skipping unreadable pipeline file: %s (%v)", path, err)
			continue
		}
		content := string(raw)
		if err := validate(content); err != nil {
			log.Warningf("skipping invalid pipeline file: %s (%v)", path, err)
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pipeline")
		out[name] = content
	}
	return out, nil
}

// validate confirms a pipeline file's content parses cleanly when wrapped
// with synthetic mode and target lines. Embedded files skip this — they
// were validated at PR review time and are part of the binary.
func validate(content string) error {
	wrapped := fmt.Sprintf("mode parallel\ntarget placeholder.local\n%s", content)
	_, err := g3lib.ParseScript(nil, wrapped)
	return err
}
```

- [ ] **Step 2: Create `src/g3tui/internal/pipelines/embed.go`**

```go
package pipelines

import (
	"embed"
	"strings"
)

//go:embed *.pipeline
var embeddedFS embed.FS

func embedded() map[string]string {
	out := map[string]string{}
	entries, err := embeddedFS.ReadDir(".")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pipeline") {
			continue
		}
		raw, err := embeddedFS.ReadFile(e.Name())
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pipeline")
		out[name] = string(raw)
	}
	return out
}
```

The pattern `*.pipeline` matches every `.pipeline` file sitting next to `embed.go` in the same package directory.

- [ ] **Step 3: Update `main.go` to print the loaded pipelines**

Append to the bottom of `main()`:

```go
	pipes, err := pipelines.Load(cfg.PipelinesDir)
	if err != nil {
		log.Critical("failed to load pipelines: " + err.Error())
		os.Exit(1)
	}
	fmt.Printf("\nLoaded %d scan type(s):\n", len(pipes))
	for _, p := range pipes {
		fmt.Printf("  %-20s (%s)\n", p.Name, p.Source)
	}
```

Add the import at the top:

```go
	"golismero.com/g3tui/internal/pipelines"
```

- [ ] **Step 4: Build and run**

Run: `make bin && (set -a; source .env; set +a; bin/g3tui)`

Expected: original three config lines, then `Loaded 2 scan type(s):` followed by `network              (embedded)` and `web                  (embedded)`.

- [ ] **Step 5: Verify user-override merge**

Run:
```bash
mkdir -p /tmp/g3tui-test-pipes
echo "nikto" > /tmp/g3tui-test-pipes/quick-recon.pipeline
G3_PIPELINES_DIR=/tmp/g3tui-test-pipes (set -a; source .env; set +a; bin/g3tui)
```

Expected: 3 scan types listed: `network (embedded)`, `quick-recon (user)`, `web (embedded)`.

- [ ] **Step 6: Verify invalid user file is skipped, not fatal**

Run:
```bash
echo "this is not a pipeline >>>" > /tmp/g3tui-test-pipes/broken.pipeline
G3_PIPELINES_DIR=/tmp/g3tui-test-pipes (set -a; source .env; set +a; bin/g3tui)
```

Expected: a `WARNING` line about skipping `broken.pipeline`, the binary still completes, and `quick-recon` still appears.

- [ ] **Step 7: STOP — user commit checkpoint**

Working tree at this point:
- Created: `src/g3tui/internal/pipelines/pipelines.go`, `src/g3tui/internal/pipelines/embed.go`
- Modified: `src/g3tui/main.go`, `src/g3tui/go.mod`, `src/g3tui/go.sum`

Suggested commit message: `g3tui: pipelines package with embed + user-override merge`

Stop here and let the user commit before starting the next task.

---

### Task 0.4: Client package — `tea.Msg` types and HTTP endpoint wrappers

**Files:**
- Create: `src/g3tui/internal/client/messages.go`
- Create: `src/g3tui/internal/client/client.go`
- Modify: `src/g3tui/main.go`

- [ ] **Step 1: Add `bubbletea` to the module**

Run: `cd src/g3tui && go get github.com/charmbracelet/bubbletea`

Expected: `go.mod` and `go.sum` updated; no build yet.

- [ ] **Step 2: Create `src/g3tui/internal/client/messages.go`**

```go
// Package client wraps every g3api endpoint and the WS scanprogress
// subscription used by g3tui. All inputs/outputs are domain types from
// g3lib; tea.Msg carriers below are just thin envelopes so the UI layer
// can route updates without depending on the underlying transport.
package client

import (
	"golismero.com/g3lib"
)

// Snapshot of the scan list (id + status + progress + message) returned
// by /scan/list+/scan/progress, or by the polling fallback when WS is down.
type ScanListSnapshot struct {
	Entries []g3lib.ScanStatusEntry
}

// Single scan-status update pushed via the WS scanprogress channel.
type ScanProgressUpdate struct {
	ScanID   string
	Status   g3lib.G3SCANSTATUS
	Progress int
	Message  string
}

// Per-task status payload from /scan/tasks/status.
type TaskStatusUpdate struct {
	ScanID   string
	Response g3lib.ScanTaskStatusResponse
}

// Per-task log payload from /scan/logs.
type LogChunk struct {
	Log g3lib.G3TaskLog
}

// Successful one-shot fetch from /scan/report.
type ReportLoaded struct {
	ScanID   string
	Markdown string
	Errors   string // non-empty if the server reported parse errors during generation
}

// Wizard upload result for one file.
type FileUploaded struct {
	LocalPath string
	FileID    string // server-side handle to substitute into the script's import line
}

// Submit-flow result of POST /scan/start.
type ScanStarted struct {
	ScanID string
}

// Outcome of POST /scan/stop.
type ScanCancelRequested struct {
	ScanID string
}

// Outcome of POST /scan/delete.
type ScanDeleted struct {
	ScanID string
}

// Cached at app start; the wizard's import-tool dropdown reads this.
type PluginsLoaded struct {
	Plugins []PluginListEntry
}

type PluginListEntry struct {
	Name        string
	URL         string
	Description string
}

// ErrorMsg is the generic carrier for any failed call. The owning model
// decides how to surface it (banner, inline error, etc.).
type ErrorMsg struct {
	Op  string // human label like "/scan/start"
	Err error
}
```

- [ ] **Step 3: Create `src/g3tui/internal/client/client.go`**

```go
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
```

- [ ] **Step 4: Update `main.go` smoke-test to exercise `ListScans` and `ListPlugins`**

Append to the bottom of `main()`:

```go
	ctx := context.Background()
	cli := client.New(cfg.BaseURL, cfg.WSURL, cfg.Token)

	scans, err := cli.ListScans(ctx)
	if err != nil {
		log.Critical("ListScans failed: " + err.Error())
		os.Exit(1)
	}
	fmt.Printf("\nScans: %d\n", len(scans))
	for _, id := range scans {
		fmt.Printf("  %s\n", id)
	}

	plugins, err := cli.ListPlugins(ctx)
	if err != nil {
		log.Critical("ListPlugins failed: " + err.Error())
		os.Exit(1)
	}
	fmt.Printf("\nPlugins: %d\n", len(plugins))
	for _, p := range plugins {
		fmt.Printf("  %s — %s\n", p.Name, p.Description)
	}
```

Add imports:

```go
	"context"

	"golismero.com/g3tui/internal/client"
```

- [ ] **Step 5: Build and run against a live server**

Prereqs: `docker compose up` is running, `.env` is populated.

Run: `make bin && (set -a; source .env; set +a; bin/g3tui)`

Expected: prior config and pipeline output, then a list of scan IDs (or "Scans: 0" if the database is empty), then a list of plugin names with descriptions.

- [ ] **Step 6: Run with the API down to verify network-error handling**

Run: `docker compose stop g3api && (set -a; source .env; set +a; bin/g3tui); docker compose start g3api`

Expected: `CRITICAL: ListScans failed: ...connection refused...`, exit 1. Then restart g3api so subsequent tasks work.

- [ ] **Step 7: STOP — user commit checkpoint**

Working tree at this point:
- Created: `src/g3tui/internal/client/messages.go`, `src/g3tui/internal/client/client.go`
- Modified: `src/g3tui/main.go`, `src/g3tui/go.mod`, `src/g3tui/go.sum`

Suggested commit message: `g3tui: client package with HTTP wrappers and tea.Msg envelopes`

Stop here and let the user commit before starting the next task.

---

### Task 0.5: Client package — generic poller

**Files:**
- Create: `src/g3tui/internal/client/poll.go`
- Modify: `src/g3tui/main.go`

- [ ] **Step 1: Create `src/g3tui/internal/client/poll.go`**

```go
package client

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Poll drives a single fetch-and-emit loop until ctx is cancelled. Each
// iteration calls fetch() and forwards the resulting tea.Msg via send.
// Returning nil from fetch is allowed — the iteration is skipped silently
// (useful when the caller wants to suppress emission for a tick).
//
// Errors are emitted as ErrorMsg{Op: opLabel, Err: err}; the loop continues.
// Pause-on-blur is implemented by the caller cancelling its ctx; when the
// pane regains focus it spawns a fresh Poll.
func Poll(ctx context.Context, interval time.Duration, opLabel string,
	fetch func(context.Context) (tea.Msg, error),
	send func(tea.Msg),
) {
	t := time.NewTicker(interval)
	defer t.Stop()

	tick := func() {
		msg, err := fetch(ctx)
		if err != nil {
			if ctx.Err() == nil {
				send(ErrorMsg{Op: opLabel, Err: err})
			}
			return
		}
		if msg != nil {
			send(msg)
		}
	}

	tick() // fire once immediately so first paint isn't blocked by `interval`
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
```

- [ ] **Step 2: Update `main.go` to smoke-test the poller**

Add this block at the bottom of `main()`, before the function returns:

```go
	fmt.Printf("\nPolling /scan/progress for ~6 seconds at 2s cadence...\n")
	pollCtx, pollCancel := context.WithTimeout(ctx, 6*time.Second)
	defer pollCancel()
	client.Poll(pollCtx, 2*time.Second, "/scan/progress",
		func(ctx context.Context) (tea.Msg, error) {
			entries, err := cli.GetProgress(ctx)
			if err != nil {
				return nil, err
			}
			return client.ScanListSnapshot{Entries: entries}, nil
		},
		func(msg tea.Msg) {
			switch m := msg.(type) {
			case client.ScanListSnapshot:
				fmt.Printf("  tick: %d scans\n", len(m.Entries))
			case client.ErrorMsg:
				fmt.Printf("  tick: error from %s: %v\n", m.Op, m.Err)
			}
		},
	)
```

Add imports:

```go
	"time"

	tea "github.com/charmbracelet/bubbletea"
```

- [ ] **Step 3: Build and run**

Run: `make bin && (set -a; source .env; set +a; bin/g3tui)`

Expected: previous output, then "Polling /scan/progress for ~6 seconds at 2s cadence..." followed by ~3 tick lines (immediate + two more before timeout), then exit.

- [ ] **Step 4: Verify error path**

Run with API down (`docker compose stop g3api`):

```bash
docker compose stop g3api
(set -a; source .env; set +a; bin/g3tui) 2>&1 | tail -10
docker compose start g3api
```

(The earlier `ListScans` will now fail-fast and you won't reach the poller — that's fine. The error-handling pathway already proves out.)

- [ ] **Step 5: STOP — user commit checkpoint**

Working tree at this point:
- Created: `src/g3tui/internal/client/poll.go`
- Modified: `src/g3tui/main.go`

Suggested commit message: `g3tui: generic poller with error-as-message handling`

Stop here and let the user commit before starting the next task.

---

### Task 0.6: Client package — WS scanprogress subscription with reconnect FSM

**Files:**
- Create: `src/g3tui/internal/client/stream.go`
- Modify: `src/g3tui/main.go`
- Modify: `src/g3tui/go.mod` (via `go get`)

- [ ] **Step 1: Add `gorilla/websocket` to the module**

Run: `cd src/g3tui && go get github.com/gorilla/websocket`

Expected: `go.mod`/`go.sum` updated.

- [ ] **Step 2: Create `src/g3tui/internal/client/stream.go`**

```go
package client

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gorilla/websocket"
	"golismero.com/g3lib"
)

type StreamState int

const (
	StreamConnecting StreamState = iota
	StreamConnected
	StreamDisconnected
	StreamReconnecting
)

func (s StreamState) String() string {
	switch s {
	case StreamConnecting:
		return "connecting"
	case StreamConnected:
		return "connected"
	case StreamDisconnected:
		return "disconnected"
	case StreamReconnecting:
		return "reconnecting"
	}
	return "unknown"
}

// StreamStateChanged fires every time the WS connection transitions between
// Connecting, Connected, Disconnected, Reconnecting. The header bar
// consumes this for its dot color.
type StreamStateChanged struct {
	State StreamState
	Err   error // populated on transitions into Disconnected/Reconnecting
}

// SubscribeScanProgress dials c.WSURL, subscribes to the scanprogress
// channel, and forwards each progress message as ScanProgressUpdate.
// Reconnects with exponential backoff up to 30s on any error or close.
// Stops cleanly when ctx is cancelled.
func (c *Client) SubscribeScanProgress(ctx context.Context, send func(tea.Msg)) {
	backoff := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	attempt := 0

	for {
		if ctx.Err() != nil {
			return
		}

		if attempt == 0 {
			send(StreamStateChanged{State: StreamConnecting})
		} else {
			send(StreamStateChanged{State: StreamReconnecting})
		}

		conn, err := dialAndSubscribe(ctx, c.WSURL, c.Token)
		if err != nil {
			send(StreamStateChanged{State: StreamDisconnected, Err: err})
			d := backoff[min(attempt, len(backoff)-1)]
			attempt++
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
				continue
			}
		}

		send(StreamStateChanged{State: StreamConnected})
		attempt = 0
		readLoop(ctx, conn, send)
		_ = conn.Close()
		send(StreamStateChanged{State: StreamDisconnected})
	}
}

func dialAndSubscribe(ctx context.Context, wsURL, token string) (*websocket.Conn, error) {
	dialer := *websocket.DefaultDialer
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return nil, err
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"msgtype":"scanprogress"}`)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func readLoop(ctx context.Context, conn *websocket.Conn, send func(tea.Msg)) {
	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		_ = conn.Close()
		close(closed)
	}()
	defer func() {
		select {
		case <-closed:
		default:
			// caller-side close; drain the watcher goroutine
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() == nil {
				send(StreamStateChanged{State: StreamDisconnected, Err: err})
			}
			return
		}
		var env struct {
			MsgType string          `json:"msgtype"`
			Data    json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			send(ErrorMsg{Op: "ws-decode", Err: err})
			continue
		}
		if env.MsgType != "scanprogress" {
			continue
		}
		var status g3lib.G3ScanStatus
		if err := json.Unmarshal(env.Data, &status); err != nil {
			send(ErrorMsg{Op: "ws-decode", Err: err})
			continue
		}
		send(ScanProgressUpdate{
			ScanID:   status.ScanID,
			Status:   status.Status,
			Progress: status.Progress,
			Message:  status.Message,
		})
	}
}

```

(Go 1.21+ has a builtin `min` for ordered types — no helper needed.)

- [ ] **Step 3: Update `main.go` to smoke-test the WS subscription**

Replace the polling block from Task 0.5 with this combined block (so the smoke test exercises both poller and WS in one run):

```go
	fmt.Printf("\nSubscribing to WS scanprogress for ~10 seconds...\n")
	wsCtx, wsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer wsCancel()
	send := func(msg tea.Msg) {
		switch m := msg.(type) {
		case client.StreamStateChanged:
			fmt.Printf("  ws state: %s (err=%v)\n", m.State, m.Err)
		case client.ScanProgressUpdate:
			fmt.Printf("  ws update: scan=%s status=%s progress=%d\n", m.ScanID, m.Status, m.Progress)
		case client.ErrorMsg:
			fmt.Printf("  ws error: %s: %v\n", m.Op, m.Err)
		}
	}
	go cli.SubscribeScanProgress(wsCtx, send)

	// Run the poller in parallel for the same window so we see both transports together.
	client.Poll(wsCtx, 2*time.Second, "/scan/progress",
		func(ctx context.Context) (tea.Msg, error) {
			entries, err := cli.GetProgress(ctx)
			if err != nil {
				return nil, err
			}
			return client.ScanListSnapshot{Entries: entries}, nil
		},
		func(msg tea.Msg) {
			if m, ok := msg.(client.ScanListSnapshot); ok {
				fmt.Printf("  poll: %d scans\n", len(m.Entries))
			}
		},
	)
```

(The `Poll` call blocks until `wsCtx` expires, which is what we want for the smoke test.)

- [ ] **Step 4: Build and run**

Run: `make bin && (set -a; source .env; set +a; bin/g3tui)`

Expected: prior output, then `ws state: connecting`, `ws state: connected`, ~5 `poll: ... scans` lines, and (if there's an active scan) zero or more `ws update: ...` lines.

- [ ] **Step 5: Verify reconnect on mid-session drop**

In one terminal, run: `make bin && (set -a; source .env; set +a; bin/g3tui)`

Quickly in another terminal: `docker compose restart g3api`

Expected (in the first terminal): the ws state goes `connected` → `disconnected` (with err) → `reconnecting` → `connected` again, all within ~5–10s. The poller may also report errors during the gap.

- [ ] **Step 6: Verify auth failure surfaces cleanly**

Run with a wrong token:
```bash
G3_API_TOKEN=wrong (set -a; source .env; G3_API_TOKEN=wrong; set +a; bin/g3tui)
```

Expected: `ListScans failed: ...Unauthorized...` exits before reaching the WS section. (We exercise the WS auth path in Tier 1 where the dashboard owns the lifecycle.)

- [ ] **Step 7: STOP — user commit checkpoint**

Working tree at this point:
- Created: `src/g3tui/internal/client/stream.go`
- Modified: `src/g3tui/main.go`, `src/g3tui/go.mod`, `src/g3tui/go.sum`

Suggested commit message: `g3tui: WS scanprogress subscription with reconnect FSM`

Stop here and let the user commit before starting the next task.

---

### Task 0.7: Tier 0 wrap-up — clean smoke test

**Files:**
- Modify: `src/g3tui/main.go`

The smoke test in `main.go` has accumulated a lot of one-off `fmt.Printf` calls. Tier 1 will replace `main()` entirely with a Bubble Tea `tea.Program.Run()`, so we don't need to polish it — but we should leave a single coherent `main()` that exercises every Tier 0 piece in sequence and exits cleanly. This task tightens the file before handing off to Tier 1.

- [ ] **Step 1: Refactor `main()` into a single linear smoke routine**

Replace the body of `main()` with a structured run that:
1. Loads config.
2. Loads pipelines, prints them.
3. Creates a `client.Client`.
4. Calls `ListScans`, `ListPlugins`, prints summary.
5. Subscribes to WS + runs poller in parallel for 10s, prints state transitions and updates.
6. Exits cleanly.

(Use the existing prints — just consolidate ordering and remove duplicate context creation. Final smoke output should fit in ~30 lines on a typical terminal.)

- [ ] **Step 2: Build and run end-to-end**

Run: `make bin && (set -a; source .env; set +a; bin/g3tui)`

Expected: a single coherent run with sections clearly labeled (config / pipelines / scans / plugins / ws+poll). Exits with status 0 after ~10–11 seconds.

- [ ] **Step 3: Run `golangci-lint` if installed**

Run: `cd src/g3tui && golangci-lint run ./... 2>&1 | head -30 || true`

Expected: clean, or only warnings consistent with the repo's correctness-only config.

- [ ] **Step 4: STOP — user commit checkpoint (Tier 0 complete)**

Working tree at this point:
- Modified: `src/g3tui/main.go`

Suggested commit message: `g3tui: tier 0 smoke-test driver covers config, pipelines, HTTP, WS`

Stop here. Tier 0 is complete — `bin/g3tui` builds, lints clean, and exercises every transport against a live server. Hand back to the user for commit and Tier 1 kickoff.

---

## Tier 1 — Dashboard with live updates

> **Note (2026-05-08):** The dashboard layout (column shape, scrolling, panel structure, focus model) was rebrainstormed and reimplemented against [`2026-05-08-g3tui-layout-redesign-design.md`](2026-05-08-g3tui-layout-redesign-design.md) and [`2026-05-08-g3tui-layout-redesign-implementation.md`](2026-05-08-g3tui-layout-redesign-implementation.md). The right pane is now a stacked Tasks + Logs panel pair with progressive column collapse, scrolling viewports in both list and table, Tab-driven focus cycling, and a server-side fallback that reconstructs task state from log markers for terminated scans. The Tier 1 description below documents the original first-pass intent; the redesign supersedes it for the layout/columns/scrolling concerns. Tier 2 (wizard) and Tier 3 (logs/report viewers) are still valid as written.

**Intent.** Replace the smoke-test `main` with a Bubble Tea program that runs the persistent dashboard. The dashboard owns the WS lifecycle, scan-list rendering, per-task drill-in, header connection indicator, footer keybinds, cancel/delete confirmation flows, and the initial-connection-failure screen.

**End state.**
- Launching `bin/g3tui` lands in the dashboard. Left panel lists scans (live via WS, polling fallback), sorted RUNNING-first.
- Selecting a scan fills the right pane with the per-task table (2s polled, off on terminal scan state).
- Header dot reflects WS state in real time (green/yellow/red).
- `c` on a selected scan opens a confirm overlay → `/scan/stop`.
- `d` on a non-running selected scan opens a confirm overlay → `/scan/stop` then `/scan/delete`.
- Initial WS dial failure (or auth failure on first HTTP call) shows a full-screen retry/quit prompt.
- `q` / `Ctrl-C` exits cleanly.

**Build order rationale.** Polling-only scan list lands first (Task 1.2), then per-task drill-in (1.3), then chrome (1.4). WS subscription is wired in *after* the polling-only path works (1.5) so the UI is fully debuggable before adding a second transport. Confirm overlays come last among interactive features (1.6) because they depend on the scan-list selection and the right pane being mature. The initial-failure screen (1.7) is bolt-on ahead of the polish task (1.8).

---

### Task 1.1: UI foundations & app skeleton

**Files (create):**
- `src/g3tui/internal/ui/styles.go` — single Lip Gloss palette: header, footer, list-pane border, list-row (default/selected/dimmed), table-header, indicator dot variants. No theming for v1.
- `src/g3tui/internal/ui/keys.go` — `key.Binding` declarations for global keys (`q` quit, `?` help, `↑↓` navigate, `enter` select, `c` cancel, `d` delete, `n` new, `l` logs, `r` report, `esc` back, `/` filter).
- `src/g3tui/internal/ui/app.go` — top-level `tea.Model` with `Init/Update/View`. Owns `client.Client`, the `[]pipelines.Pipeline` cache, the cached plugin list, the scan list, the selected scan ID, the WS connection state, and a sub-model focus enum. View is a placeholder for now (title bar + "loading…" body) — sub-pane rendering arrives in 1.2/1.3.

**Files (modify):**
- `src/g3tui/main.go` — strip the smoke driver. Load config, build `client.Client`, do the one-shot `/scan/list` + `/plugin/list` fetches synchronously to seed the model (so initial render isn't blank), then `tea.NewProgram(ui.New(cfg, cli, plugins, pipes), tea.WithAltScreen()).Run()`. On error during seeding, emit a friendly stderr message and exit 1 (the full retry screen is added in 1.7; until then a hard-fail at launch is acceptable).

**Design decisions.**
- `App.Update` uses a top-level `switch m := msg.(type)` and dispatches to the sub-model owning the focus. Messages from `client.*` (e.g. `ScanListSnapshot`, `StreamStateChanged`) are broadcast to the relevant pane.
- Window-resize handling lives in `App` and re-flows the layout on each `tea.WindowSizeMsg`. Sub-models receive their own resize as a `paneResize` message we synthesize from the parent.
- `tea.WithAltScreen()` is set so the dashboard takes the full terminal and restores cleanly on exit.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 1.2: Scan list pane (polling-only first)

**Files (create):**
- `src/g3tui/internal/ui/scanlist.go` — `ScanList` sub-model. Owns: filtered/sorted list, current selection index, filter string, focus state. View renders the left panel: title row, then one row per scan with status pill + progress %.

**Wiring.**
- `App.Init()` returns a `tea.Cmd` that spawns a 3s `client.Poll` for `/scan/progress`, sending `ScanListSnapshot`. The poller's context is owned by `App`; cancelled on quit.
- On `ScanListSnapshot`, `ScanList` replaces its entries, re-sorts (RUNNING → WAITING → terminal-newest-first), and re-applies the current filter.
- Sort uses status precedence then a stable secondary by `LastSeen` (descending). Filter is an inline ID-prefix or status-name match — no fuzzy matching for v1.

**Keybinds owned here.**
- `↑/↓` move selection.
- `/` enters filter mode (textinput attached to the bottom of the panel; `esc` clears and exits).
- `enter` is a no-op in 1.2 (drill-in arrives in 1.3).

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 1.3: Scan detail pane (per-task table)

**Files (create):**
- `src/g3tui/internal/ui/scandetail.go` — `ScanDetail` sub-model. Renders the right pane: a table of tasks for the currently-selected scan.

**Columns** mirror `g3cli ps <scanid>`: TASK ID (truncated), STATE, TOOL, WORKER (truncated), LAST SEEN (relative duration), AGE (relative duration), LINES.

**Wiring.**
- `App` watches scan selection changes from `ScanList` and tells `ScanDetail` to focus on the new scan. `ScanDetail` spawns a 2s `client.Poll` for `/scan/tasks/status` keyed on the focused scan ID; cancels its previous poller on selection change.
- Polling pauses when the scan reaches a terminal status (FINISHED/CANCELED/FAILED) — `ScanDetail` checks the latest entry from the scan list before deciding whether to re-arm the ticker.
- Empty state mirrors `g3cli ps`: "Scan has no tasks yet" if the response is empty.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 1.4: Header bar + footer

**Files (modify):**
- `src/g3tui/internal/ui/app.go` — add `renderHeader()` and `renderFooter()` helpers, joined into the top-level `View()` via `lipgloss.JoinVertical`.

**Header.** `g3tui` title, a connection indicator (placeholder dot in 1.4 — fully wired in 1.5), and the host portion of `cfg.BaseURL` (never the token). Right-aligned filler.

**Footer.** Default keybinds joined with `·`. Sub-models contribute their own keybinds via a `Help() []key.Binding` interface — the footer renders the focused sub-model's bindings in addition to the globals.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 1.5: WS subscription + connection indicator

**Files (modify):**
- `src/g3tui/internal/ui/app.go` — wire `client.SubscribeScanProgress` lifecycle. The subscription runs in a goroutine spawned from `App.Init` via a `tea.Cmd` that returns once the goroutine is running. Messages flow through `tea.Program.Send` (passed as the `send` callback to the subscription).

**State machine.**
- `App` tracks the latest `StreamState` (Connecting / Connected / Disconnected / Reconnecting) plus the most recent error.
- Header dot color: green = Connected, yellow = Connecting/Reconnecting, red = Disconnected.
- When state transitions to Connected, `App` cancels the polling fallback's context. When it goes Disconnected, `App` arms a new `client.Poll` against `/scan/progress` at 3s. The `ScanList` is agnostic: it accepts `ScanListSnapshot` (from poll) and `ScanProgressUpdate` (from WS) and merges accordingly.

**ScanProgressUpdate handling.** Single-row update; `ScanList` upserts by ScanID. Re-sort is amortized — flag the list as dirty and re-sort once per render frame, not per message.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 1.6: Cancel/delete confirmation overlays

**Files (create):**
- `src/g3tui/internal/ui/confirm.go` — generic `Confirm` sub-model: title, body line, [Y]es / [N]o keybinds, on-confirm callback that returns a `tea.Cmd`.

**Files (modify):**
- `src/g3tui/internal/ui/app.go` — `c` on a selected scan opens `Confirm("Cancel scan <id>?", ...)` whose callback issues `client.StopScan`. `d` on a non-running selected scan opens `Confirm("Delete scan <id>? This cannot be undone.", ...)` whose callback issues `client.StopScan` then `client.DeleteScan` (matches `g3cli rm`'s sequencing).

**Error surfacing.** If the API call fails, render a one-line red banner under the header for ~5s (consume an `ErrorMsg` and time it out via a `tea.Tick`). No modal blockers.

**Out of scope for 1.6.** Per-task cancel (server doesn't expose it, see design's "Future API improvements").

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 1.7: Initial-connection-failure screen

**Files (modify):**
- `src/g3tui/main.go` — instead of exiting on initial seed failure, hand control to a small `ui.RetryScreen` model that renders the error, the host, and `[R]etry / [Q]uit`. On `R`, it re-attempts `/scan/list` + `/plugin/list` and the WS dial; on success it transitions to the dashboard model. On `Q`, exit 0.
- `src/g3tui/internal/ui/app.go` — accept the seeded data via the constructor; the retry screen builds the data and hands it over.

**Distinct from mid-session failure.** Mid-session WS drops are silent reconnects (1.5's responsibility) — only the *first* dial or first auth call uses this screen.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 1.8: Tier 1 polish & lint wrap-up

**Files:** sweep across `src/g3tui/` for any straggler `fmt.Print*` smoke-test residue, dead imports, TODO comments left from in-progress work.

**Final agent verification.** `make bin` clean across the whole module, `golangci-lint run ./...` clean. Hand back to user for behavioral verification (layout, drill-in, cancel, delete, indicator color flips on `docker compose restart g3api`).

**Out of scope for Tier 1.** New-scan wizard (Tier 2), logs viewer (Tier 3), report viewer (Tier 3).

---

## Tier 2 — New-scan wizard

**Intent.** Add the `[N]` modal overlay that lets the operator build and submit a new scan without writing a script.

**End state.**
- `[N]` opens the wizard overlay. Tab/Shift-Tab navigates between Targets, Imports, Mode, Scan type sections.
- Targets: multi-line textarea, blank lines ignored.
- Imports: tool-first batch flow — pick a plugin, then multi-select files via a small custom file browser (`Space` toggle, `Enter` confirm).
- Mode: two-button toggle, default `parallel`.
- Scan type: list of embedded + user pipelines (alphabetical), then `Custom…`.
- `Custom…` opens a textarea; validation via `g3lib.ParseScript("mode parallel\ntarget placeholder.local\n" + content)`.
- Submit: parallel uploads (cap 4 via buffered-channel semaphore) → script assembly → `/scan/start`. New scan appears in left panel via WS push (already wired in Tier 1).
- Server errors render in a banner inside the overlay; the form is preserved for correction.

**Build order rationale.** Skeleton + tab navigation lands first (2.1) so every subsequent section can drop into a known frame. The three "static" sections (targets/mode/scan-type list) come together in 2.2. The Custom… textarea and the imports stack are larger and get their own tasks (2.3, 2.4). Submit pipeline closes out (2.5) — depends on every other section being complete.

**Out of scope for Tier 2.** Pre-filtering the import-tool dropdown to importer-only plugins (requires server-side `/plugin/list` extension; logged in the design doc as a future API improvement). Live preview pane (operators who want hand-crafted scripts use `g3cli scan -i my.script` per the design's coexist-with-g3cli story).

---

### Task 2.1: Wizard skeleton & overlay plumbing

**Files (create):**
- `src/g3tui/internal/ui/wizard.go` — `Wizard` sub-model with sections enum, focused-section index, Tab/Shift-Tab navigation, esc-to-dismiss, banner state. View renders the four section headers as inert placeholders for now; sections themselves arrive in 2.2/2.3/2.4.

**Files (modify):**
- `src/g3tui/internal/ui/app.go` — `n` key opens the wizard (App holds `wizard *Wizard`, nil when inactive). While the wizard is open, App routes all keystrokes to it. Wizard dismissal via a `wizardClosedMsg` clears `a.wizard`.
- `src/g3tui/internal/ui/keys.go` — add bindings for Tab / Shift-Tab if missing.

**Design decisions.**
- Mirror Tier 1's `Confirm` plumbing: pointer-or-nil on App, dismissal message, Help() override.
- Wizard banner reuses the same `bannerExpiredMsg` infra and the same red `BannerError` style.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 2.2: Targets / Mode / Scan type sections

**Files (modify):**
- `src/g3tui/internal/ui/wizard.go` — implement the three "static" sections.
- `src/g3tui/go.mod` — add `github.com/charmbracelet/bubbles/textarea` (auto-pulled by `go mod tidy` once imported).

**Sections.**
- **Targets.** `bubbles/textarea` (multi-line). Blank lines stripped at submit time. No soft warning per line in v1 — server's `BuildTargets` is the validation authority.
- **Mode.** Two-button toggle: `( ) sequential   (●) parallel`. Default `parallel`. `←/→` or `space` toggles when focused.
- **Scan type.** Plain list (no nested model). `↑/↓` selects. Sources merged from `App.pipes` (already sorted alphabetically by `pipelines.Load`). `Custom…` is appended as the last entry — selection just sets a flag in 2.2; the actual sub-overlay arrives in 2.3.

**Tab navigation.** Tab focuses Targets → Imports (placeholder for now) → Mode → Scan type → Targets. Shift-Tab goes backward. Per-section keybinds only fire when that section is focused.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 2.3: Custom… scan-type sub-overlay

**Files (modify):**
- `src/g3tui/internal/ui/wizard.go` — when the Scan type list has `Custom…` selected and the user presses `Enter`, push a `customPipelineEditor` sub-overlay (a textarea + validation footer). On `esc`, return to the wizard with whatever content was typed (preserved across re-opens). On `Enter` outside the textarea (e.g. on the validation footer button), validate via `g3lib.ParseScript`.

**Validation contract.**
- Wrap user content with synthetic `mode parallel\ntarget placeholder.local\n` prefix and call `g3lib.ParseScript(nil, wrapped)`.
- On parse error: show the error inline below the textarea, do not dismiss.
- On success: dismiss sub-overlay, retain content in wizard state.
- Empty content is treated as "user wants to abandon Custom" — wizard reverts the Scan type selection to whatever was previously highlighted.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 2.4: Imports section (tool dropdown + multi-file picker)

**Files (modify):**
- `src/g3tui/internal/ui/wizard.go` — Imports section: list of `<tool>  <path>  [×]` rows; `[+ Add]` button opens the stacked sub-overlay flow.
- `src/g3tui/internal/ui/picker.go` (new) — small file browser with multi-select. Renders a list of files in the current directory; `↑/↓` move the cursor, `Space` toggles selection on the current row, `Enter` confirms (returns `[]string` of selected paths), `←` (or `h`) goes up a directory, `→` (or `l`) descends into a directory under cursor.

**Stacked sub-overlay flow.**
1. Tool dropdown — alphabetical from `App.plugins`. `↑/↓` select, `Enter` confirm, `Esc` cancel. Sets `pendingTool` on the wizard, then opens the file picker. (Future API improvement: when `/plugin/list` exposes `has_importer`, filter this list. Not in scope for v1.)
2. File picker — lands in `$HOME` (or `$PWD` if `$HOME` is unset). Shows directories + files; multi-select via Space. On Enter, each selected file becomes an imports row with `tool = pendingTool`. On Esc, abort without adding.

**Imports list editing.** `Enter` on a row removes it. The `[+ Add]` button is conceptually below the rows; `↓` past the last row selects it; `Enter` opens the tool dropdown.

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

### Task 2.5: Submit pipeline

**Files (create):**
- `src/g3tui/internal/script/build.go` — single function: `Build(targets []string, imports []ImportEntry, mode string, content string) (string, error)`. Returns the full script as a string by simple templating (no parser round-trip in the render path; see design's "Submit flow" step 1). Caller is responsible for substituting file IDs into the imports before calling.

**Files (modify):**
- `src/g3tui/internal/ui/wizard.go` — wire `Enter` (when not inside a section's own input) to submit. Submit flow:
  1. **Local validation.** ≥1 non-blank target OR ≥1 import row; a scan type is selected; if Custom is selected, content is non-empty and parses.
  2. **Parallel uploads.** For each import row, POST `/file/upload` via `client.UploadFile`. Cap concurrency at 4 using a buffered-channel semaphore. Implemented in a single goroutine spawned by a `tea.Cmd` that returns a `wizardSubmitProgress` message stream — but for v1 simplicity, the goroutine collects all results and sends a single `wizardUploadsDoneMsg{results []FileUploaded, errs []ErrorMsg}`. No per-file progress UI.
  3. **Substitute file IDs** into the imports before calling `script.Build`.
  4. **POST `/scan/start`** via `client.StartScan` with the assembled script. On success, dispatch `wizardClosedMsg` (App clears the wizard); the new scan arrives via the existing WS push.
  5. **On any error** (validation, upload, or start): banner inside the wizard, form preserved.

**Concurrency note.** The semaphore goroutine is spawned by a `tea.Cmd` — it runs to completion without further coordination from the model. This is acceptable because uploads are short and the form is locked while submitting (a "submitting…" banner replaces the regular footer hint).

**Verification (agent).** `make bin` clean, `golangci-lint run ./...` clean.

---

## Tier 3 — Logs viewer, report viewer, README

**Intent.** Replace the right pane with a logs viewer (`[L]`) or report viewer (`[R]`) for the selected scan. Document usage in `src/g3tui/README.md` to close out the user-facing implementation.

**End state.**
- `[L]` opens `LogsPane` with a task picker at the top, scrollable log area, follow-tail toggle (`G`), save-to-file (`S`), and 2s polling that pauses on blur and stops on terminal scan state.
- `[R]` opens `ReportPane` with one-shot `/scan/report` fetch, Glamour-rendered Markdown in a `bubbles/viewport`, errors-banner if the server reports parse errors, and save-as-Markdown (`S`).
- `[Esc]` returns each pane to the per-task table.
- `src/g3tui/README.md` describes env vars (`G3_API_BASEURL`, `G3_API_WSURL`, `G3_API_TOKEN`, `G3_PIPELINES_DIR`, `G3_CMD_LOG_LEVEL`), build (`make bin`), install (`make install`), the six workflows, and the user-pipelines override directory.

**Key tasks (to be detailed at Tier 3 kickoff).**
1. `internal/ui/logs.go` — task picker, viewport, polling glue, save-to-file.
2. `internal/ui/report.go` — Glamour render, viewport, save-as.
3. Reusable save-file overlay (`bubbles/filepicker` in save mode + filename textinput).
4. `go get github.com/charmbracelet/glamour`; tie into `App` routing.
5. Write `src/g3tui/README.md`.

**Out of scope for Tier 3.** Multiple report formats (JSON, Obsidian) — design doc tags as future. Incremental log cursor — out of scope until server-side support lands.

**Verification.** Open logs on a running scan, observe live updates. Toggle follow-tail off, scroll up, observe sticky position. Save a log to a temp file, diff with `g3cli logs --output`. Open a report on a finished scan, confirm Glamour rendering. Save report, diff with `g3cli report --output`. README renders cleanly.

---

## Out of plan: tests

Per project rule (`feedback_tests_are_user_owned.md`), automated test coverage for `internal/client/`, `internal/pipelines/`, and `internal/ui/` is not part of this plan. The user writes tests at their own cadence on whichever cadence works for them. Agent-side verification across all tiers is `golangci-lint run ./...` + `go build` + behavioral checks against a live `g3api`.

---

## Self-review notes

- **Spec coverage check:** Every section of `2026-05-06-g3tui-design.md` maps to a tier — Architecture & file structure → Tier 0; Layout / dashboard / cancel-delete / error handling → Tier 1; Wizard → Tier 2; Logs & report viewers + README → Tier 3; Build integration & lint → Tier 0; Verification & testing → "Out of plan: tests" (user-owned).
- **Placeholder check:** Tier 0 contains complete code blocks for every "create file" step. Tiers 1–3 are intentionally outlined-only per the project's tiered-plans preference; they will be detailed at their respective kickoffs against this same spec.
- **Type consistency:** `tea.Msg` envelope names (`ScanListSnapshot`, `ScanProgressUpdate`, `TaskStatusUpdate`, `LogChunk`, `ReportLoaded`, `FileUploaded`, `ScanStarted`, `ScanCancelRequested`, `ScanDeleted`, `PluginsLoaded`, `ErrorMsg`, `StreamStateChanged`) match the spec's data-flow table. The `Pipeline{Name, Source, Content}` shape matches the spec.
- **Git hygiene check:** No mutating git commands appear in any task step. Each task ends at a "STOP — user commit checkpoint" with a suggested commit message in plain text only. Read-only inspection (`git status`, `git diff`) is fine for the agent's situational awareness.
- **Test boundary check:** No task instructs the agent to write tests. Verification per task is `go build` + `golangci-lint run ./...` + behavioral observation against a live server.
