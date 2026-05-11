# g3tui Logs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the inline `LogsPanel` placeholder with a working live preview that auto-tracks the Tasks-panel cursor, and wire the `l` keybinding to a full-screen scan-level logs viewer that displays all tasks for the selected scan, chronologically interleaved with per-line tool-name attribution.

**Architecture:** Four tasks landing as one cohesive change. Task 1 (server) is independent and can ship alone. Task 2 (TUI client surface) depends on Task 1. Task 3 (inline panel) and Task 4 (full-screen viewer) both depend on Task 2 but are independent of each other and could ship in either order.

**Tech Stack:** Go 1.26.2 (per `src/*/go.mod`); existing dependencies — `g3lib`, `bubbles/viewport`, `bubbletea`, `lipgloss`. No new external dependencies.

**Source spec:** [`docs/plans/2026-05-08-g3tui-logs-design.md`](2026-05-08-g3tui-logs-design.md)

**Tests are user-owned** (memory: `feedback_tests_are_user_owned.md`). The plan does not include test-writing or behavioral-testing tasks. **Agent verification per task is strictly `go build ./...` (or `make bin`) + `golangci-lint run ./...`.** No `bin/g3tui` runs, no `docker compose` interactions, no live `/scan/logs` calls.

**Git is user-owned** (memory: `feedback_git_is_user_owned.md`). No mutating git commands in any task. Read-only inspection (`git status`, `git diff`, `git log`) is fine.

**Commit cadence** (memory: `feedback_plan_commit_cadence.md`): tasks list explicit "STOP — user commit checkpoint" boundaries for documentation only. Agents push through without pausing. The user commits at the end of the plan or wherever they choose.

---

## Task overview

| Task | Scope | Depends on |
|---|---|---|
| **1 — Server scan-level mode for `/scan/logs`** | Relax `ReqQueryLog.TaskID` validator; branch handler to return `[]LogEntry` when `TaskID` is empty | None (independent) |
| **2 — TUI client surface** | Split `GetLogs` into `GetTaskLogs` + `GetScanLogs`; add `ScanLogChunk` message type | 1 |
| **3 — Inline `LogsPanel`** | Replace placeholder with viewport-backed live preview; debounced 250 ms binding change; 2 s poll while non-terminal; implicit follow-tail; ANSI strip | 2 |
| **4 — Full-screen `LogsViewer`** | New overlay component opened by `l`, closed by `esc`; scan-level unified stream; `[g3:dispatch]` parser builds `taskID → tool` map; per-line attribution | 2 |

---

## Prerequisites

- A working build environment matching `src/*/go.mod` (Go 1.26.2; `golangci-lint` 2.x).
- Familiarity with the `bubbletea` model/update/view pattern; existing g3tui code follows it consistently.
- Read access to the running stack is **not** required — agent verification is lint + build only.

---

## Task 1: Server scan-level mode for `/scan/logs`

**Intent.** Today `/scan/logs` requires both `ScanID` and `TaskID` — both validated as `uuid`. The TUI's full-screen viewer needs a unified scan-level log fetch in one round-trip. The underlying SQL helper `g3lib.QueryLog(db, cb, scanID)` (sql.go:140) already supports the scan-only mode; we just expose it via the existing endpoint.

**Files:**
- Modify: `src/g3lib/api.go` — relax `ReqQueryLog.TaskID` validator
- Modify: `src/g3api/g3api.go` — branch `/scan/logs` handler

- [ ] **Step 1: Relax `ReqQueryLog.TaskID` validator**

In `src/g3lib/api.go`, locate `ReqQueryLog` (around line 250) and change the `TaskID` validator from `uuid` to `omitempty,uuid` so an empty string passes validation while non-empty values still must be valid UUIDs:

```go
type ReqQueryLog struct {
    ScanID string `json:"scanid"   validate:"uuid"`
    TaskID string `json:"taskid"   validate:"omitempty,uuid"`
}
```

The `Decode` method below it stays unchanged.

- [ ] **Step 2: Branch the `/scan/logs` handler**

In `src/g3api/g3api.go`, locate the `/scan/logs` handler (around line 454). The current body is:

```go
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
```

Replace the body so the handler branches on `TaskID` emptiness. When `TaskID` is empty, accumulate `[]g3lib.LogEntry` via `QueryLog(db, cb, scanID)` and send that array; when non-empty, the existing single-task path is unchanged.

```go
http.HandleFunc(apiPath + "/scan/logs", requireToken(apiToken, func (w http.ResponseWriter, r *http.Request) {
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
        var entries []g3lib.LogEntry
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
```

- [ ] **Step 3: Verify the build**

Run from the repo root:

```
make bin
```

Expected: build succeeds for all six binaries (`g3`, `g3api`, `g3cli`, `g3config`, `g3scanner`, `g3worker`). The `g3cli logs` subcommand always supplies a `TaskID`, so its existing call path is unaffected — the relaxed validator only adds a new accepted shape.

- [ ] **Step 4: Verify the lint**

Run from the repo root:

```
golangci-lint run ./...
```

Expected: no new findings. The branch is straightforward; `entries` is a local slice with no escape and the cb is the same `QueryLogCallback` shape used elsewhere.

**STOP — user commit checkpoint (Task 1).**

---

## Task 2: TUI client surface — split `GetLogs`, add `ScanLogChunk`

**Intent.** Replace `Client.GetLogs(scanID, taskID) → G3TaskLog` with two methods that don't share a polymorphic response, so call sites stay simple. Add a new `ScanLogChunk` message carrier mirroring the existing `LogChunk`. `GetLogs` has no callers in `g3tui` today (verified via grep at planning time), so renaming is safe.

**Files:**
- Modify: `src/g3tui/internal/client/client.go` — replace `GetLogs` with `GetTaskLogs` + `GetScanLogs`
- Modify: `src/g3tui/internal/client/messages.go` — add `ScanLogChunk`

- [ ] **Step 1: Replace `GetLogs` with two methods in `client.go`**

In `src/g3tui/internal/client/client.go`, locate (around line 80):

```go
// GetLogs → /scan/logs for one (scan, task).
func (c *Client) GetLogs(ctx context.Context, scanID, taskID string) (g3lib.G3TaskLog, error) {
    var out g3lib.G3TaskLog
    err := c.call(ctx, "/scan/logs", g3lib.ReqQueryLog{ScanID: scanID, TaskID: taskID}, &out)
    return out, err
}
```

Replace with:

```go
// GetTaskLogs → /scan/logs for one (scan, task). Returns the existing
// G3TaskLog response (top-level taskid, lines:[{timestamp,text}]).
func (c *Client) GetTaskLogs(ctx context.Context, scanID, taskID string) (g3lib.G3TaskLog, error) {
    var out g3lib.G3TaskLog
    err := c.call(ctx, "/scan/logs", g3lib.ReqQueryLog{ScanID: scanID, TaskID: taskID}, &out)
    return out, err
}

// GetScanLogs → /scan/logs with empty TaskID, returning all rows for
// the scan as []LogEntry (chronologically interleaved per the server's
// ORDER BY timestamp,id ASC). Used by the full-screen logs viewer.
func (c *Client) GetScanLogs(ctx context.Context, scanID string) ([]g3lib.LogEntry, error) {
    var out []g3lib.LogEntry
    err := c.call(ctx, "/scan/logs", g3lib.ReqQueryLog{ScanID: scanID}, &out)
    return out, err
}
```

- [ ] **Step 2: Add `ScanLogChunk` message type**

In `src/g3tui/internal/client/messages.go`, locate the existing `LogChunk` (around line 39):

```go
// Per-task log payload from /scan/logs.
type LogChunk struct {
    Log g3lib.G3TaskLog
}
```

Add immediately below it:

```go
// Per-scan log payload from /scan/logs (TaskID="" mode). Carries the raw
// row list; the consumer (full-screen LogsViewer) walks the stream to
// render and to build its taskID→tool map from [g3:dispatch] markers.
type ScanLogChunk struct {
    ScanID  string
    Entries []g3lib.LogEntry
    Err     error
}
```

`Err` is included on the message (rather than routed via `ErrorMsg`) for the same reason `TaskStatusUpdate` carries its error inline: a transient HTTP blip on a per-pane poll should not tear down the polling chain. The receiver re-arms regardless of `Err` and keeps the last successful render visible.

Also add a sibling for the inline panel's per-task fetches. The existing `LogChunk` does not carry `ScanID`/`Err` fields, and the inline panel needs both — `ScanID` to ignore stale ticks from a prior binding, `Err` for the same reason as above. Replace `LogChunk` with:

```go
// Per-task log payload from /scan/logs. ScanID and TaskID identify the
// binding so a stale tick from a previous focus is dropped on receipt.
// Err inline (not routed via ErrorMsg) so a transient HTTP blip can't
// tear down the polling chain — the receiver re-arms regardless.
type LogChunk struct {
    ScanID string
    TaskID string
    Log    g3lib.G3TaskLog
    Err    error
}
```

- [ ] **Step 3: Verify the build**

Run:

```
cd src && make ../bin/g3tui
```

Expected: build succeeds. There are no callers of the removed `GetLogs` in `g3tui` (verified at planning time via grep) so the rename does not cascade.

- [ ] **Step 4: Verify the lint**

Run:

```
golangci-lint run ./...
```

Expected: no new findings.

**STOP — user commit checkpoint (Task 2).**

---

## Task 3: Inline `LogsPanel` implementation

**Intent.** Replace the placeholder body in `src/g3tui/internal/ui/logspanel.go` with a working live preview. The panel binds to `(scanID, taskID)` derived from `(ScanList.SelectedID(), ScanDetail.SelectedTaskID())`, debounces 250 ms on binding changes, then polls every 2 s while the bound scan is non-terminal. Renders `HH:MM:SS  <text>` per line with ANSI stripped; viewport-backed scroll with implicit follow-tail.

**Files:**
- Modify: `src/g3tui/internal/ui/logspanel.go` — full rewrite of the placeholder
- Modify: `src/g3tui/internal/ui/styles.go` — add `LogTimestamp` style
- Modify: `src/g3tui/internal/ui/app.go` — emit `logsBindingChangedMsg` when binding changes; route `LogChunk` and binding messages

- [ ] **Step 1: Add the `LogTimestamp` style**

In `src/g3tui/internal/ui/styles.go`, locate the `ListItemDimmed` declaration and add `LogTimestamp` immediately below the existing `ListItem*` block:

```go
LogTimestamp = lipgloss.NewStyle().Faint(true)
```

Place it after the `ListItem*` group, before `StatusRunning`. Visually it shares the dimmed treatment of `ListItemDimmed` but is named for clarity at call sites.

- [ ] **Step 2: Rewrite `logspanel.go`**

Replace the entire contents of `src/g3tui/internal/ui/logspanel.go` with:

```go
package ui

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/charmbracelet/bubbles/key"
    "github.com/charmbracelet/bubbles/viewport"
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
    "golismero.com/g3lib"
    "golismero.com/g3tui/internal/client"
)

// logsBindingChangedMsg is dispatched by App when the (scanID, taskID)
// binding for the inline Logs panel changes — either because the focused
// scan changed or because the Tasks-panel cursor moved. ScanID can be
// empty (no scan selected); TaskID can be empty (scan has no tasks yet).
type logsBindingChangedMsg struct {
    ScanID     string
    TaskID     string
    ScanStatus g3lib.G3SCANSTATUS
}

// logsDebounceFiredMsg fires 250 ms after a binding change and triggers
// the actual fetch. The Generation field guards against a stale debounce
// timer firing after the binding has changed again — only the latest
// generation triggers a fetch.
type logsDebounceFiredMsg struct {
    Generation int
    ScanID     string
    TaskID     string
}

// logsTickMsg is the periodic 2 s re-poll for the current binding.
// Generation guards against late ticks after a binding change.
type logsTickMsg struct {
    Generation int
    ScanID     string
    TaskID     string
}

// debounceDelay is the design-mandated cursor-thrash mitigation
// (docs/plans/2026-05-08-g3tui-layout-redesign-design.md).
const logsDebounceDelay = 250 * time.Millisecond

// pollInterval matches the cadence used by ScanList and ScanDetail.
const logsPollInterval = 2 * time.Second

// LogsPanel is the dashboard's bottom-right panel. It renders a live
// preview of log output for whichever task the Tasks-panel cursor is
// on. Polling is governed by the App-emitted binding messages; the
// panel never reaches into the client layer outside of the fetch
// commands defined here.
type LogsPanel struct {
    cli *client.Client

    scanID     string
    taskID     string
    scanStatus g3lib.G3SCANSTATUS
    generation int // invalidates pending debounce/tick callbacks on rebind

    lines    []g3lib.TaskLogLine
    viewport viewport.Model

    width   int
    height  int
    focused bool
}

func NewLogsPanel(cli *client.Client) LogsPanel {
    return LogsPanel{cli: cli, viewport: viewport.New(0, 0)}
}

func (l *LogsPanel) SetSize(w, h int) {
    l.width = w
    l.height = h
    inner := w - 4 // border 2 + padding 1+1
    chrome := 2
    titleRow := 1
    spacerRow := 1
    contentHeight := max(1, h-chrome-titleRow-spacerRow)
    l.viewport.Width = inner
    l.viewport.Height = contentHeight
    l.applyContent()
}

func (l *LogsPanel) SetFocused(focused bool) {
    l.focused = focused
}

// Help returns the keybinds shown in the footer when the Logs panel
// has focus. ↑↓/PgUp/PgDn/g/G are the documented in-panel navigation.
func (l LogsPanel) Help() []key.Binding {
    if len(l.lines) == 0 {
        return nil
    }
    return []key.Binding{Keys.Up, Keys.Down, Keys.PgUp, Keys.PgDn, Keys.GotoTop, Keys.GotoBottom}
}

func (l LogsPanel) Update(msg tea.Msg) (LogsPanel, tea.Cmd) {
    switch m := msg.(type) {
    case logsBindingChangedMsg:
        l.generation++
        l.scanID = m.ScanID
        l.taskID = m.TaskID
        l.scanStatus = m.ScanStatus
        l.lines = nil
        l.viewport.GotoTop()
        l.applyContent()
        if l.scanID == "" || l.taskID == "" {
            return l, nil
        }
        // Debounce: schedule the first fetch 250 ms out so rapid cursor
        // movement collapses into a single round-trip.
        gen := l.generation
        sid, tid := l.scanID, l.taskID
        return l, tea.Tick(logsDebounceDelay, func(time.Time) tea.Msg {
            return logsDebounceFiredMsg{Generation: gen, ScanID: sid, TaskID: tid}
        })

    case logsDebounceFiredMsg:
        if m.Generation != l.generation || m.ScanID != l.scanID || m.TaskID != l.taskID {
            return l, nil // stale debounce — binding has changed since
        }
        return l, l.fetchNowCmd()

    case logsTickMsg:
        if m.Generation != l.generation || m.ScanID != l.scanID || m.TaskID != l.taskID {
            return l, nil // stale tick
        }
        if isTerminal(l.scanStatus) {
            return l, nil // terminal scan: one-shot done, no further ticks
        }
        return l, l.fetchNowCmd()

    case client.LogChunk:
        if m.ScanID != l.scanID || m.TaskID != l.taskID {
            return l, nil // stale fetch from a previous binding
        }
        if m.Err != nil {
            // Transient HTTP failure: keep last successful render, re-arm
            // the chain at the regular cadence. App will surface the error
            // banner via ErrorMsg if it wants to (LogsPanel doesn't emit
            // one for poll failures — design rule).
            return l, l.scheduleNextTickCmd()
        }
        wasAtBottom := l.viewport.AtBottom()
        l.lines = m.Log.Lines
        l.applyContent()
        if wasAtBottom {
            l.viewport.GotoBottom()
        }
        if isTerminal(l.scanStatus) {
            return l, nil
        }
        return l, l.scheduleNextTickCmd()

    case tea.KeyMsg:
        if !l.focused || len(l.lines) == 0 {
            return l, nil
        }
        switch {
        case key.Matches(m, Keys.Up):
            l.viewport.LineUp(1)
        case key.Matches(m, Keys.Down):
            l.viewport.LineDown(1)
        case key.Matches(m, Keys.PgUp):
            l.viewport.HalfViewUp()
        case key.Matches(m, Keys.PgDn):
            l.viewport.HalfViewDown()
        case key.Matches(m, Keys.GotoTop):
            l.viewport.GotoTop()
        case key.Matches(m, Keys.GotoBottom):
            l.viewport.GotoBottom()
        }
        return l, nil
    }
    return l, nil
}

func (l LogsPanel) View() string {
    border := PaneBorder
    if l.focused {
        border = PaneBorderFocused
    }
    title := AppTitle.Render(l.renderTitle(l.width - 4))
    body := l.viewport.View()
    return border.Width(l.width - 2).Height(l.height - 2).Render(
        lipgloss.JoinVertical(lipgloss.Left, title, "", body),
    )
}

// renderTitle picks the longest "Logs · <id> · <count>" formulation that
// fits within maxWidth, progressively collapsing the task ID. Same
// pattern as renderDetailTitle in scandetail.go — title must always be
// exactly one row to avoid pushing the panel past its allocated height.
func (l LogsPanel) renderTitle(maxWidth int) string {
    if l.taskID == "" {
        return "Logs"
    }
    count := fmt.Sprintf("%d lines", len(l.lines))
    if len(l.lines) == 1 {
        count = "1 line"
    }
    candidates := []string{
        fmt.Sprintf("Logs · %s · %s", l.taskID, count),
        fmt.Sprintf("Logs · %s · %s", collapseID(l.taskID, colTaskIDMid), count),
        fmt.Sprintf("Logs · %s · %s", collapseID(l.taskID, colTaskIDMin), count),
        fmt.Sprintf("Logs · %s · %s", collapseID(l.taskID, colTaskIDFloor), count),
        fmt.Sprintf("Logs · %s", count),
        "Logs",
    }
    for _, c := range candidates {
        if lipgloss.Width(c) <= maxWidth {
            return c
        }
    }
    runes := []rune("Logs")
    if len(runes) > maxWidth {
        return string(runes[:maxWidth])
    }
    return "Logs"
}

// applyContent rebuilds the viewport's content from the current lines
// slice, applying the per-line formatting and ANSI strip.
func (l *LogsPanel) applyContent() {
    if l.scanID == "" || l.taskID == "" {
        l.viewport.SetContent(ListItemDimmed.Render("(no task selected)"))
        return
    }
    if len(l.lines) == 0 {
        l.viewport.SetContent(ListItemDimmed.Render("(no log lines yet)"))
        return
    }
    var b strings.Builder
    for i, ln := range l.lines {
        if i > 0 {
            b.WriteByte('\n')
        }
        b.WriteString(formatLogLine(ln.Timestamp, ln.Text))
    }
    l.viewport.SetContent(b.String())
}

// formatLogLine renders one line as "HH:MM:SS  <stripped text>". Used
// by both the inline panel and the full-screen viewer (the viewer wraps
// the result with a [tool] prefix on top of this).
func formatLogLine(ts int64, text string) string {
    when := time.Unix(ts, 0).Format("15:04:05")
    return LogTimestamp.Render(when) + "  " + g3lib.StripAnsi(text)
}

func (l LogsPanel) fetchNowCmd() tea.Cmd {
    cli := l.cli
    sid, tid := l.scanID, l.taskID
    return func() tea.Msg {
        // The receiver checks (ScanID, TaskID) on receipt and ignores
        // stale results from a previous binding — no Generation stamp
        // is needed on the chunk itself.
        log, err := cli.GetTaskLogs(context.Background(), sid, tid)
        return client.LogChunk{ScanID: sid, TaskID: tid, Log: log, Err: err}
    }
}

func (l LogsPanel) scheduleNextTickCmd() tea.Cmd {
    gen := l.generation
    sid, tid := l.scanID, l.taskID
    return tea.Tick(logsPollInterval, func(time.Time) tea.Msg {
        return logsTickMsg{Generation: gen, ScanID: sid, TaskID: tid}
    })
}
```

- [ ] **Step 3: Update `App` to construct the panel with the client**

In `src/g3tui/internal/ui/app.go`, locate `NewLogsPanel()` in the `New` function (around line 88):

```go
logsPanel:   NewLogsPanel(),
```

Change to:

```go
logsPanel:   NewLogsPanel(cli),
```

- [ ] **Step 4: Emit `logsBindingChangedMsg` from App when binding changes**

The binding `(scanID, taskID, scanStatus)` is derived from the latest values of `ScanList.SelectedID()`, `ScanDetail.SelectedTaskID()`, and the focused scan's status. The status is read from `ScanList`'s entries via a new accessor.

In `src/g3tui/internal/ui/scanlist.go`, add an accessor that returns the status of the currently-selected scan. Place it next to the existing `SelectedID` method (search for `func (s ScanList) SelectedID()`):

```go
// SelectedStatus returns the status of the currently-highlighted entry,
// or "" when no entry is selected. Used by App to know whether the
// Logs panel should keep polling the binding's task.
func (s ScanList) SelectedStatus() g3lib.G3SCANSTATUS {
    id := s.SelectedID()
    if id == "" {
        return ""
    }
    for _, e := range s.entries {
        if e.ScanID == id {
            return e.Status
        }
    }
    return ""
}
```

If `g3lib` is not yet imported in `scanlist.go`, add it to the import block (the file already uses `g3lib.ScanStatusEntry` for its entries field).

In `src/g3tui/internal/ui/app.go`, add an `App` helper:

```go
// currentLogsBinding computes the inline Logs panel's binding from the
// scan list's selection, the task panel's cursor, and the selected
// scan's status. Empty strings/empty status are valid: the panel
// renders a "no task selected" state and skips polling.
func (a App) currentLogsBinding() logsBindingChangedMsg {
    return logsBindingChangedMsg{
        ScanID:     a.scanList.SelectedID(),
        TaskID:     a.scanDetail.SelectedTaskID(),
        ScanStatus: a.scanList.SelectedStatus(),
    }
}
```

Place it next to `applyFocus` (around app.go:270).

- [ ] **Step 5: Wire binding-change emission**

The binding can change in four places:

1. The scan list selection changes (user picked a different scan).
2. The selected scan's status changes (e.g. RUNNING → FINISHED via a WS push) — same scan, but the panel needs the new status to know whether to keep polling.
3. The Tasks panel cursor moves (`case focusTasks:` in `App.Update`, app.go:198).
4. A `TaskStatusUpdate` arrives and row preservation lands the cursor on a different task ID (`case focusChangedMsg, client.TaskStatusUpdate:`, app.go:220).

Cases 1 and 2 are both handled by `dispatchToScanList`. Modify it (app.go:278) to emit a binding change when **either** the selection changes **or** the selected scan's status changes:

```go
func (a App) dispatchToScanList(msg tea.Msg) (tea.Model, tea.Cmd) {
    prevID := a.scanList.SelectedID()
    prevStatus := a.scanList.SelectedStatus()
    var slCmd tea.Cmd
    a.scanList, slCmd = a.scanList.Update(msg)
    currentID := a.scanList.SelectedID()
    currentStatus := a.scanList.SelectedStatus()
    cmds := []tea.Cmd{slCmd}
    if currentID != prevID {
        var sdCmd tea.Cmd
        a.scanDetail, sdCmd = a.scanDetail.Update(focusChangedMsg{ScanID: currentID})
        cmds = append(cmds, sdCmd)
    }
    if currentID != prevID || currentStatus != prevStatus {
        var lpCmd tea.Cmd
        a.logsPanel, lpCmd = a.logsPanel.Update(a.currentLogsBinding())
        cmds = append(cmds, lpCmd)
    }
    return a, tea.Batch(cmds...)
}
```

Modify the `case focusTasks:` branch in `App.Update` (app.go:198) to emit a binding change after the Tasks panel updates. Replace:

```go
case focusTasks:
    var cmd tea.Cmd
    a.scanDetail, cmd = a.scanDetail.Update(m)
    return a, cmd
```

with:

```go
case focusTasks:
    prevTaskID := a.scanDetail.SelectedTaskID()
    var cmd tea.Cmd
    a.scanDetail, cmd = a.scanDetail.Update(m)
    if a.scanDetail.SelectedTaskID() != prevTaskID {
        var lpCmd tea.Cmd
        a.logsPanel, lpCmd = a.logsPanel.Update(a.currentLogsBinding())
        return a, tea.Batch(cmd, lpCmd)
    }
    return a, cmd
```

Modify the `case focusChangedMsg, client.TaskStatusUpdate:` branch (app.go:220) the same way — the cursor can shift on refresh when row preservation can't find the previous task. Replace:

```go
case focusChangedMsg, client.TaskStatusUpdate:
    var cmd tea.Cmd
    a.scanDetail, cmd = a.scanDetail.Update(m)
    return a, cmd
```

with:

```go
case focusChangedMsg, client.TaskStatusUpdate:
    prevTaskID := a.scanDetail.SelectedTaskID()
    var cmd tea.Cmd
    a.scanDetail, cmd = a.scanDetail.Update(m)
    if a.scanDetail.SelectedTaskID() != prevTaskID {
        var lpCmd tea.Cmd
        a.logsPanel, lpCmd = a.logsPanel.Update(a.currentLogsBinding())
        return a, tea.Batch(cmd, lpCmd)
    }
    return a, cmd
```

- [ ] **Step 6: Route `LogChunk` and the Logs panel's tick/debounce messages to the panel**

In `src/g3tui/internal/ui/app.go`, the panel emits `logsDebounceFiredMsg`, `logsTickMsg`, and the client emits `client.LogChunk`. None are currently routed. Add a single case to `App.Update`'s message switch (next to the existing `case client.StreamStateChanged:` branch around app.go:225):

```go
case client.LogChunk, logsDebounceFiredMsg, logsTickMsg:
    var cmd tea.Cmd
    a.logsPanel, cmd = a.logsPanel.Update(m)
    return a, cmd
```

- [ ] **Step 7: (Initial-binding emission — already covered)**

The first `ScanListSnapshot` after app start changes both `SelectedID` (from "" to the first scan's ID) and `SelectedStatus` (from "" to its status). Step 5's `dispatchToScanList` already emits the binding-change in this case, so no additional wiring is needed here. This step exists in the plan for documentation only — verify by reading the existing `case client.ScanListSnapshot, client.ScanProgressUpdate:` branch (app.go:217) and confirming it just calls `a.dispatchToScanList(m)` (no change needed).

- [ ] **Step 8: Update the focusLogs footer help branch**

In `src/g3tui/internal/ui/app.go`, the `case focusLogs:` branch in `renderFooter` (around app.go:372) currently has only a comment. Replace:

```go
case focusLogs:
    // LogsPanel.Help() returns nil until Tier 3 implements it.
```

with:

```go
case focusLogs:
    bindings = append(bindings, a.logsPanel.Help()...)
```

- [ ] **Step 9: Verify the build**

Run:

```
cd src && make ../bin/g3tui
```

Expected: build succeeds. The new file references `collapseID`, `colTaskIDMid`, `colTaskIDMin`, `colTaskIDFloor`, `isTerminal`, and `g3lib.StripAnsi` — all already in the codebase.

- [ ] **Step 10: Verify the lint**

Run:

```
golangci-lint run ./...
```

Expected: no new findings. The `_ = gen` discard in `fetchNowCmd` is intentional (the closure captures it for clarity even though it isn't used in the current shape) — if `golangci-lint`'s `unused` linter flags it, drop the assignment and the variable; the binding-stale guard already covers correctness.

**STOP — user commit checkpoint (Task 3).**

---

## Task 4: Full-screen `LogsViewer` overlay

**Intent.** New component, parallel in role to `Confirm` and `Wizard`. Opens via `l` for the **selected scan** (focus-independent). Replaces the right pane with a unified scan-level log stream, chronologically interleaved, per-line `HH:MM:SS [tool] text` formatting. The viewer parses `[g3:dispatch] task=<id> tool=<name>` markers as it walks the stream and builds an in-memory `taskID → tool` map. `Esc` closes; focus restores.

**Files:**
- Create: `src/g3tui/internal/ui/logsviewer.go`
- Modify: `src/g3tui/internal/ui/styles.go` — add `LogTool` style
- Modify: `src/g3tui/internal/ui/app.go` — `l` key opens viewer; route `ScanLogChunk` and viewer messages; `Esc` closes

- [ ] **Step 1: Add the `LogTool` style**

In `src/g3tui/internal/ui/styles.go`, add after `LogTimestamp`:

```go
LogTool = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))
```

The color `63` matches `AppTitle` purple — chosen for visual consistency with the focused-pane border.

- [ ] **Step 2: Create `logsviewer.go`**

Create `src/g3tui/internal/ui/logsviewer.go` with:

```go
package ui

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/charmbracelet/bubbles/key"
    "github.com/charmbracelet/bubbles/viewport"
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
    "golismero.com/g3lib"
    "golismero.com/g3tui/internal/client"
)

// logsViewerTickMsg is the periodic 2 s re-poll for the viewer. The
// generation field is reserved for symmetry with LogsPanel; the viewer
// has no in-flight binding changes (its binding is fixed at open) so
// in practice all ticks within one viewer session share generation 0.
type logsViewerTickMsg struct {
    ScanID string
}

// logsViewerClosedMsg fires when the user presses Esc. App tears down
// the overlay and restores focus to the previously-focused panel.
type logsViewerClosedMsg struct{}

// LogsViewer is the full-screen scan-level logs overlay opened by `l`.
// It is constructed each time the user opens the viewer and discarded
// when they Esc out — there is no long-lived state to preserve across
// open/close cycles.
type LogsViewer struct {
    cli *client.Client

    scanID     string
    scanStatus g3lib.G3SCANSTATUS
    entries    []g3lib.LogEntry
    toolByTask map[string]string
    toolWidth  int // cached visual width of the widest known [tool] prefix, capped at 12

    viewport viewport.Model

    width  int
    height int
}

const logsViewerToolCap = 12

func NewLogsViewer(cli *client.Client, scanID string, scanStatus g3lib.G3SCANSTATUS) LogsViewer {
    v := LogsViewer{
        cli:        cli,
        scanID:     scanID,
        scanStatus: scanStatus,
        toolByTask: map[string]string{},
        viewport:   viewport.New(0, 0),
    }
    return v
}

func (v *LogsViewer) SetSize(w, h int) {
    v.width = w
    v.height = h
    inner := w - 4 // border 2 + padding 1+1
    chrome := 2
    titleRow := 1
    spacerRow := 1
    footerRow := 1
    contentHeight := max(1, h-chrome-titleRow-spacerRow-footerRow)
    v.viewport.Width = inner
    v.viewport.Height = contentHeight
    v.applyContent()
}

// InitCmd kicks off the first fetch and (for non-terminal scans)
// schedules the 2 s tick. Called once by App immediately after
// constructing the viewer.
func (v LogsViewer) InitCmd() tea.Cmd {
    return v.fetchNowCmd()
}

func (v LogsViewer) Help() []key.Binding {
    return []key.Binding{Keys.PgUp, Keys.PgDn, Keys.GotoTop, Keys.GotoBottom, Keys.Back}
}

func (v LogsViewer) Update(msg tea.Msg) (LogsViewer, tea.Cmd) {
    switch m := msg.(type) {
    case logsViewerTickMsg:
        if m.ScanID != v.scanID {
            return v, nil // stale
        }
        if isTerminal(v.scanStatus) {
            return v, nil
        }
        return v, v.fetchNowCmd()

    case client.ScanLogChunk:
        if m.ScanID != v.scanID {
            return v, nil
        }
        if m.Err != nil {
            // Keep last successful render; re-arm on the regular cadence.
            return v, v.scheduleNextTickCmd()
        }
        wasAtBottom := v.viewport.AtBottom()
        v.entries = m.Entries
        v.rebuildToolMap()
        v.applyContent()
        if wasAtBottom {
            v.viewport.GotoBottom()
        }
        if isTerminal(v.scanStatus) {
            return v, nil
        }
        return v, v.scheduleNextTickCmd()

    case tea.KeyMsg:
        switch {
        case key.Matches(m, Keys.Back):
            return v, func() tea.Msg { return logsViewerClosedMsg{} }
        case key.Matches(m, Keys.Up):
            v.viewport.LineUp(1)
        case key.Matches(m, Keys.Down):
            v.viewport.LineDown(1)
        case key.Matches(m, Keys.PgUp):
            v.viewport.HalfViewUp()
        case key.Matches(m, Keys.PgDn):
            v.viewport.HalfViewDown()
        case key.Matches(m, Keys.GotoTop):
            v.viewport.GotoTop()
        case key.Matches(m, Keys.GotoBottom):
            v.viewport.GotoBottom()
        }
        return v, nil
    }
    return v, nil
}

func (v LogsViewer) View() string {
    title := AppTitle.Render(v.renderTitle(v.width - 4))
    body := v.viewport.View()
    footer := FooterBar.Render("[PgUp/PgDn] scroll · [g/G] top/bot · [esc] back")
    return PaneBorderFocused.Width(v.width - 2).Height(v.height - 2).Render(
        lipgloss.JoinVertical(lipgloss.Left, title, "", body, footer),
    )
}

func (v LogsViewer) renderTitle(maxWidth int) string {
    status := string(v.scanStatus)
    if status == "" {
        status = "?"
    }
    candidates := []string{
        fmt.Sprintf("Logs · %s · %s", v.scanID, status),
        fmt.Sprintf("Logs · %s · %s", collapseID(v.scanID, colTaskIDMid), status),
        fmt.Sprintf("Logs · %s · %s", collapseID(v.scanID, colTaskIDMin), status),
        fmt.Sprintf("Logs · %s · %s", collapseID(v.scanID, colTaskIDFloor), status),
        fmt.Sprintf("Logs · %s", status),
        "Logs",
    }
    for _, c := range candidates {
        if lipgloss.Width(c) <= maxWidth {
            return c
        }
    }
    runes := []rune("Logs")
    if len(runes) > maxWidth {
        return string(runes[:maxWidth])
    }
    return "Logs"
}

// rebuildToolMap walks the current entries slice and (re)populates the
// taskID → tool map by parsing [g3:dispatch] markers. Defensive: only
// the first dispatch marker per task is treated as authoritative;
// later occurrences are ignored (matches the reconstructor's rule).
// Also updates toolWidth.
func (v *LogsViewer) rebuildToolMap() {
    v.toolByTask = map[string]string{}
    for _, e := range v.entries {
        if !strings.HasPrefix(e.Text, "[g3:dispatch]") {
            continue
        }
        if _, ok := v.toolByTask[e.TaskID]; ok {
            continue
        }
        if tool := parseDispatchTool(e.Text); tool != "" {
            v.toolByTask[e.TaskID] = tool
        }
    }
    v.toolWidth = 1 // at least "?"
    for _, t := range v.toolByTask {
        w := lipgloss.Width(t)
        if w > v.toolWidth {
            v.toolWidth = w
        }
    }
    if v.toolWidth > logsViewerToolCap {
        v.toolWidth = logsViewerToolCap
    }
}

// parseDispatchTool extracts "<name>" from a "[g3:dispatch] task=<id>
// tool=<name>" marker line. Returns "" if the marker is malformed.
// Tool names contain no whitespace, so we read up to the next space.
func parseDispatchTool(text string) string {
    const key = "tool="
    i := strings.Index(text, key)
    if i < 0 {
        return ""
    }
    rest := text[i+len(key):]
    if j := strings.IndexAny(rest, " \t"); j >= 0 {
        return rest[:j]
    }
    return rest
}

// applyContent re-renders the viewport content from the current entries
// slice and tool map. Each line is "HH:MM:SS [tool] <stripped text>"
// where [tool] is end-ellipsised to toolWidth.
func (v *LogsViewer) applyContent() {
    if len(v.entries) == 0 {
        v.viewport.SetContent(ListItemDimmed.Render("(no log lines yet)"))
        return
    }
    var b strings.Builder
    for i, e := range v.entries {
        if i > 0 {
            b.WriteByte('\n')
        }
        b.WriteString(formatViewerLine(e.Timestamp, v.toolFor(e.TaskID), v.toolWidth, e.Text))
    }
    v.viewport.SetContent(b.String())
}

func (v LogsViewer) toolFor(taskID string) string {
    if t, ok := v.toolByTask[taskID]; ok {
        return t
    }
    return "?"
}

// formatViewerLine renders one stream line. tool is the per-task name
// from the map (or "?" for lines whose dispatch marker hasn't been
// seen yet); width is the column the [tool] cell pads to.
func formatViewerLine(ts int64, tool string, width int, text string) string {
    when := time.Unix(ts, 0).Format("15:04:05")
    cell := tool
    if lipgloss.Width(cell) > width {
        runes := []rune(cell)
        if width <= 1 {
            cell = "…"
        } else {
            cell = string(runes[:width-1]) + "…"
        }
    }
    pad := width - lipgloss.Width(cell)
    if pad < 0 {
        pad = 0
    }
    bracketed := "[" + LogTool.Render(cell) + "]" + strings.Repeat(" ", pad)
    return LogTimestamp.Render(when) + " " + bracketed + "  " + g3lib.StripAnsi(text)
}

func (v LogsViewer) fetchNowCmd() tea.Cmd {
    cli := v.cli
    sid := v.scanID
    return func() tea.Msg {
        entries, err := cli.GetScanLogs(context.Background(), sid)
        return client.ScanLogChunk{ScanID: sid, Entries: entries, Err: err}
    }
}

func (v LogsViewer) scheduleNextTickCmd() tea.Cmd {
    sid := v.scanID
    return tea.Tick(logsPollInterval, func(time.Time) tea.Msg {
        return logsViewerTickMsg{ScanID: sid}
    })
}
```

- [ ] **Step 3: Wire viewer open/close into App**

In `src/g3tui/internal/ui/app.go`, add a `logsViewer` field and a `prevFocus` field on `App` to remember where focus was before the viewer opened.

Locate the `App` struct (around app.go:61) and add:

```go
type App struct {
    cfg     Config
    cli     *client.Client
    pipes   []pipelines.Pipeline
    plugins []client.PluginListEntry

    scanList    ScanList
    scanDetail  ScanDetail
    logsPanel   LogsPanel
    logsViewer  *LogsViewer        // overlay; nil when dashboard is showing
    confirm     *Confirm
    wizard      *Wizard
    banner      string
    streamState client.StreamState
    focus       panelFocus
    prevFocus   panelFocus          // restored when the viewer closes

    width  int
    height int
}
```

- [ ] **Step 4: Replace the placeholder `l`-key handler**

In `src/g3tui/internal/ui/app.go`, locate the `case key.Matches(m, Keys.Logs):` block (around app.go:176). Replace the entire block:

```go
case key.Matches(m, Keys.Logs):
    // `l` is the one focus-aware action. Tasks-focused →
    // per-task logs viewer; Scans-focused → multi-task logs
    // for the scan. Both viewers are deferred to a follow-up.
    switch a.focus {
    case focusTasks:
        if tid := a.scanDetail.SelectedTaskID(); tid != "" {
            a.banner = "logs viewer for task " + tid + " — coming in a follow-up release"
            return a, tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpiredMsg{} })
        }
    case focusScans:
        if sid := a.scanList.SelectedID(); sid != "" {
            a.banner = "scan logs viewer — coming in a follow-up release"
            return a, tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpiredMsg{} })
        }
    }
    return a, nil
```

with:

```go
case key.Matches(m, Keys.Logs):
    sid := a.scanList.SelectedID()
    if sid == "" {
        return a, nil
    }
    v := NewLogsViewer(a.cli, sid, a.scanList.SelectedStatus())
    v.SetSize(a.rightPaneWidth(), a.bodyHeight())
    a.logsViewer = &v
    a.prevFocus = a.focus
    return a, v.InitCmd()
```

- [ ] **Step 5: Route messages to the viewer when it's open**

In `src/g3tui/internal/ui/app.go`, the viewer needs to receive `tea.KeyMsg`, `tea.WindowSizeMsg`, `client.ScanLogChunk`, and `logsViewerTickMsg`. It also emits `logsViewerClosedMsg` which the app must handle.

Add overlay-precedence handling at the top of `App.Update`'s `tea.KeyMsg` branch. The existing `if a.wizard != nil` and `if a.confirm != nil` blocks (around app.go:117) are the model. Add a parallel block immediately after them:

```go
if a.logsViewer != nil {
    v, cmd := a.logsViewer.Update(m)
    a.logsViewer = &v
    return a, cmd
}
```

Add the same handling for `tea.WindowSizeMsg` (the viewer needs to track width changes). At the end of the `case tea.WindowSizeMsg:` body (around app.go:114), before `return a, nil`, add:

```go
if a.logsViewer != nil {
    a.logsViewer.SetSize(a.rightPaneWidth(), a.bodyHeight())
}
```

Add a top-level case for the viewer's tick and the chunk message. Place it next to the existing `case client.LogChunk, logsDebounceFiredMsg, logsTickMsg:` from Task 3 (so the routing block stays grouped):

```go
case client.ScanLogChunk, logsViewerTickMsg:
    if a.logsViewer == nil {
        return a, nil // stale message after viewer closed
    }
    v, cmd := a.logsViewer.Update(m)
    a.logsViewer = &v
    return a, cmd

case logsViewerClosedMsg:
    a.logsViewer = nil
    a.focus = a.prevFocus
    a.applyFocus()
    return a, nil
```

- [ ] **Step 6: Render the viewer in `App.View`**

In `src/g3tui/internal/ui/app.go`, locate the body switch in `App.View` (around app.go:304). The current cases are `wizard`, `confirm`, and `default`. Add a `logsViewer` case. Replace:

```go
var body string
switch {
case a.wizard != nil:
    body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Center, lipgloss.Center, a.wizard.View())
case a.confirm != nil:
    body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Center, lipgloss.Center, a.confirm.View())
default:
    rightStack := lipgloss.JoinVertical(
        lipgloss.Left,
        a.scanDetail.View(),
        a.logsPanel.View(),
    )
    body = lipgloss.JoinHorizontal(
        lipgloss.Top,
        a.scanList.View(),
        rightStack,
    )
    body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Left, lipgloss.Top, body)
}
```

with:

```go
var body string
switch {
case a.wizard != nil:
    body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Center, lipgloss.Center, a.wizard.View())
case a.confirm != nil:
    body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Center, lipgloss.Center, a.confirm.View())
case a.logsViewer != nil:
    // Viewer replaces the right pane; scan list stays.
    body = lipgloss.JoinHorizontal(
        lipgloss.Top,
        a.scanList.View(),
        a.logsViewer.View(),
    )
    body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Left, lipgloss.Top, body)
default:
    rightStack := lipgloss.JoinVertical(
        lipgloss.Left,
        a.scanDetail.View(),
        a.logsPanel.View(),
    )
    body = lipgloss.JoinHorizontal(
        lipgloss.Top,
        a.scanList.View(),
        rightStack,
    )
    body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Left, lipgloss.Top, body)
}
```

- [ ] **Step 7: Update the footer for the viewer**

In `src/g3tui/internal/ui/app.go`, the `renderFooter` switch (around app.go:354) currently has three cases (`wizard`, `confirm`, scan-list filtering). Add a `logsViewer` case so the footer shows the viewer's keybinds when it's open. Replace:

```go
case a.wizard != nil:
    bindings = []key.Binding{Keys.Quit}
    bindings = append(bindings, a.wizard.Help()...)
case a.confirm != nil:
    bindings = []key.Binding{Keys.Quit}
    bindings = append(bindings, a.confirm.Help()...)
case a.scanList.Filtering():
    bindings = append(bindings, a.scanList.Help()...)
```

with:

```go
case a.wizard != nil:
    bindings = []key.Binding{Keys.Quit}
    bindings = append(bindings, a.wizard.Help()...)
case a.confirm != nil:
    bindings = []key.Binding{Keys.Quit}
    bindings = append(bindings, a.confirm.Help()...)
case a.logsViewer != nil:
    bindings = []key.Binding{Keys.Quit}
    bindings = append(bindings, a.logsViewer.Help()...)
case a.scanList.Filtering():
    bindings = append(bindings, a.scanList.Help()...)
```

- [ ] **Step 8: Verify the build**

Run:

```
cd src && make ../bin/g3tui
```

Expected: build succeeds.

- [ ] **Step 9: Verify the lint**

Run:

```
golangci-lint run ./...
```

Expected: no new findings.

**STOP — user commit checkpoint (Task 4).**

---

## Risks and edge cases (recap from the design)

The design doc has the full list. The cases worth restating because they affect implementation choices in this plan:

- **Polymorphic `/scan/logs` response.** The TUI's two client methods (`GetTaskLogs` returns `G3TaskLog`, `GetScanLogs` returns `[]LogEntry`) decode into different Go types, so callers never have to switch on shape. External consumers — currently only `g3cli logs` — always supply a non-empty `TaskID`, so they hit the unchanged single-task path.
- **Late `[g3:dispatch]` markers in the unified stream.** A line whose `taskid` is not yet in the viewer's tool map renders as `[?]`. Self-correcting on the next poll. Acceptable behavior; no special handling beyond the rebuild-on-each-fetch already in `rebuildToolMap`.
- **Viewer cadence fixed at open time.** The full-screen viewer captures `scanStatus` at construction and uses it to gate its 2 s ticks. If the scan transitions from RUNNING to FINISHED while the viewer is open, the viewer continues polling at 2 s until the user closes it. Accepted v1 behavior — the polls are cheap (read-only SQL against retained log rows) and viewers are typically closed shortly after a scan finishes. Wiring `client.ScanProgressUpdate` into an open viewer to switch it to one-shot mode mid-session is a future iteration.

## Out of plan

The following remain explicitly deferred per the design doc:

- Save-to-file (`[S]`) for both viewers (needs save-mode `FilePicker`).
- WebSocket log streaming.
- Incremental log cursor (`since=<index>`).
- Per-task filtering inside the full-screen viewer.

## Verification scope (agent-side)

`go build ./...` (or `make bin`) plus `golangci-lint run ./...` after each task. Behavioral verification — multiple terminal widths, real scans with accumulating log lines, debounce under fast cursor movement, dispatch-marker parsing against real `[g3:` content, the "scan logs viewer" interaction across `RUNNING → FINISHED` transitions — is user-owned.
