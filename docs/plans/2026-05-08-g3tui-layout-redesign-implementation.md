# g3tui Layout Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the g3tui dashboard from a fixed-width two-pane layout into a responsive three-panel layout with proper scrolling, lifecycle-aware columns, and a server-side reconstruction fallback so terminated scans remain inspectable.

**Architecture:** Six tasks landing as one cohesive change. Server-side reconstruction (Task 1) is independent and can ship alone; TUI changes (Tasks 2–6) build on each other and should be done in order. The Logs panel slot is structural-only — implementation deferred to a follow-up plan.

**Tech Stack:** Go 1.26.2 (per `src/*/go.mod`); existing dependencies — `g3lib` (project library), `bubbles/viewport`, `bubbletea`, `lipgloss`. No new external dependencies.

**Source spec:** [`docs/plans/2026-05-08-g3tui-layout-redesign-design.md`](2026-05-08-g3tui-layout-redesign-design.md)

**Status:** Implemented and tested 2026-05-08. See "Post-implementation refinements" near the bottom for the additional fixes settled during testing.

**Tests are user-owned** (memory: `feedback_tests_are_user_owned.md`). The plan does not include test-writing or behavioral-testing tasks. **Agent verification per task is strictly `go build` (or `make bin`) + `golangci-lint run ./...`.** No `bin/g3tui` runs, no `docker compose` interactions.

**Git is user-owned** (memory: `feedback_git_is_user_owned.md`). No mutating git commands in any task. Read-only inspection (`git status`, `git diff`, `git log`) is fine.

**Commit cadence** (memory: `feedback_plan_commit_cadence.md`): tasks are listed with explicit "STOP — user commit checkpoint" boundaries for documentation, but agents push through without pausing. The user commits at the end of the plan or wherever they choose.

---

## Task overview

| Task | Scope | Independent? |
|---|---|---|
| **1 — Server-side reconstruction** | `g3lib` helper + `g3api` handler fallback for terminated scans; `STATUS_UNKNOWN` constant | Yes (can ship alone) |
| **2 — Focus FSM + Tab cycling** | Three-panel focus state, Tab/Shift-Tab handling, active-panel border style | No (foundation for 3–6) |
| **3 — Three-panel layout structure** | Split right pane vertically; create inert Logs panel placeholder | Depends on 2 |
| **4 — Scan-list scrolling** | `bubbles/viewport` wrapping for the scan list | Depends on 2 |
| **5 — Tasks-panel cursor + scrolling** | Task selection cursor, viewport, focus-aware navigation | Depends on 2, 3 |
| **6 — Task column redesign** | Six-column layout, P0/P1 priority, progressive collapse, emoji-state map, TIME and LAST SEEN as separate columns | Depends on 5 |

---

## Prerequisites

- A working build environment matching `src/*/go.mod` (Go 1.26.2; `golangci-lint` 2.x).
- Read access to the running stack is **not** required — agent verification is lint + build only.
- Familiarity with `bubbletea` model/update/view pattern; the existing g3tui code follows it consistently.

---

## Task 1: Server-side reconstruction from log markers

**Intent.** When the per-scan task data has expired from Redis, `/scan/tasks/status` currently returns an empty entries list. The fallback: parse the structured `[g3:dispatch]`, `[g3:start]`, `[g3:done]`, `[g3:cancel]` markers that already exist in the SQL `logs` table, and reconstruct enough `TaskStatusEntry` shape to render the post-completion view. No schema change.

**Files:**
- Modify: `src/g3lib/task.go` — add `STATUS_UNKNOWN` constant
- Modify: `src/g3lib/sql.go` — add `ReconstructTaskStatesFromLogs` and helpers
- Modify: `src/g3api/g3api.go` — wire reconstruction fallback into `/scan/tasks/status`

- [ ] **Step 1: Add `STATUS_UNKNOWN` constant to g3lib**

In `src/g3lib/task.go`, locate the `G3SCANSTATUS` const block and add a new entry. The block currently looks like:

```go
const (
	STATUS_WAITING  G3SCANSTATUS = "WAITING"
	STATUS_RUNNING  G3SCANSTATUS = "RUNNING"
	STATUS_ERROR    G3SCANSTATUS = "ERROR"
	STATUS_CANCELED G3SCANSTATUS = "CANCELED"
	STATUS_FINISHED G3SCANSTATUS = "FINISHED"
)
```

Add `STATUS_UNKNOWN`:

```go
const (
	STATUS_WAITING  G3SCANSTATUS = "WAITING"
	STATUS_RUNNING  G3SCANSTATUS = "RUNNING"
	STATUS_ERROR    G3SCANSTATUS = "ERROR"
	STATUS_CANCELED G3SCANSTATUS = "CANCELED"
	STATUS_FINISHED G3SCANSTATUS = "FINISHED"
	STATUS_UNKNOWN  G3SCANSTATUS = "UNKNOWN"
)
```

Also add `STATUS_UNKNOWN` to the `VALID_STATUS` array immediately below the const block:

```go
var VALID_STATUS = [...]G3SCANSTATUS{STATUS_WAITING, STATUS_RUNNING, STATUS_ERROR, STATUS_CANCELED, STATUS_FINISHED, STATUS_UNKNOWN}
```

This represents the worker-crashed-mid-run case in reconstruction (`[g3:start]` present but no `[g3:done]`).

- [ ] **Step 2: Add `ReconstructTaskStatesFromLogs` helper to g3lib/sql.go**

Append this function to `src/g3lib/sql.go`. It runs a single prefix-LIKE query and parses each `[g3:*]` marker into a `TaskStatusEntry`. The function is read-only and safe.

```go
// ReconstructTaskStatesFromLogs walks the structured lifecycle markers
// in the `logs` table and builds a TaskStatusEntry per task. It is the
// fallback path for /scan/tasks/status when Redis-backed task state has
// expired — the structured markers persist in SQL.
//
// Markers it understands:
//   [g3:dispatch] task=<id> tool=<name>   (from scanner)
//   [g3:start]    task=<id> worker=<id>   (from worker)
//   [g3:done]     task=<id> state=<S>     (from worker, or scanner on dispatch-fail)
//   [g3:cancel]   task=<id>               (from scanner)
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
		entry              TaskStatusEntry
		dispatchSeen       bool
		startSeen          bool
		doneSeen           bool
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
			// Cancel signal from scanner. The actual end-state arrives
			// later as [g3:done] with state=CANCELED. We don't update
			// State here — wait for the done line.
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Promote partial states to UNKNOWN when start was seen but done
	// never arrived (worker crashed mid-run).
	out := make([]TaskStatusEntry, 0, len(byTask))
	for _, a := range byTask {
		if a.startSeen && !a.doneSeen {
			a.entry.State = string(STATUS_UNKNOWN)
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
```

The `sort` and `strings` packages are already imported in `sql.go` — no import changes needed.

- [ ] **Step 3: Wire the fallback into `/scan/tasks/status`**

In `src/g3api/g3api.go`, locate the `/scan/tasks/status` handler (currently around line 477). Find the block that builds `entries` from `taskStates`:

```go
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
```

Add a fallback right after this block. If `entries` is empty (Redis returned nothing), call the new reconstructor and merge its output with the SQL log aggregates already in `logByTask`:

```go
// If Redis has expired the per-task state, fall back to reconstructing
// from structured log markers. SQL `logs` is durable, so this works
// for terminated scans whose Redis keys have been cleaned up.
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
```

Note: the comment from the original handler ("we deliberately do NOT reconstruct task state from logs in that case") is now stale. Replace that comment block earlier in the handler with:

```go
// Redis is authoritative for live per-task state. When Redis has
// expired the data (terminated scan, after cleanup), we fall back to
// reconstructing from structured log markers — see the fallback
// further down. The SQL logs table supplies timestamps and line
// counts as augmentation.
```

- [ ] **Step 4: Build and lint**

```bash
cd /home/crapula/code/g3
make bin 2>&1 | tail -10
cd src/g3lib && golangci-lint run ./...
cd ../g3api && golangci-lint run ./...
```

Expected: all binaries build clean, `0 issues.` from each lint run.

- [ ] **Step 5: STOP — user commit checkpoint**

Working tree at this point:
- Modified: `src/g3lib/task.go` (one-line addition)
- Modified: `src/g3lib/sql.go` (~80 lines added)
- Modified: `src/g3api/g3api.go` (handler fallback)

Suggested commit message: `g3api: reconstruct task states from log markers when redis expired`

---

## Task 2: Focus FSM + Tab cycling + active-panel border

**Intent.** Introduce the three-panel focus model on `App`, wire Tab/Shift-Tab to cycle between panels, and add a brighter border style for the focused panel. The Logs panel slot exists in the focus enum but has no model attached yet (Task 3 attaches a placeholder).

**Files:**
- Modify: `src/g3tui/internal/ui/styles.go` — add `PaneBorderFocused`, `StatusUnknown`
- Modify: `src/g3tui/internal/ui/keys.go` — add `PgUp`, `PgDn`, `GotoTop`, `GotoBottom` bindings (used by Tasks 4 and 5)
- Modify: `src/g3tui/internal/ui/app.go` — focus enum, Tab handling

- [ ] **Step 1: Add styles for focused border and unknown state**

In `src/g3tui/internal/ui/styles.go`, locate the `PaneBorder` declaration:

```go
PaneBorder = lipgloss.NewStyle().
    Border(lipgloss.RoundedBorder()).
    BorderForeground(lipgloss.Color("240")).
    Padding(0, 1)
```

Immediately after it, add the focused variant:

```go
PaneBorderFocused = lipgloss.NewStyle().
    Border(lipgloss.RoundedBorder()).
    BorderForeground(lipgloss.Color("63")). // matches AppTitle purple
    Padding(0, 1)
```

In the same file, locate the `Status*` style block:

```go
StatusRunning    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
StatusWaiting    = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
StatusFinished   = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))
StatusError      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
StatusCanceled   = lipgloss.NewStyle().Faint(true)
StatusDispatched = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
```

Add `StatusUnknown` for the worker-crashed-mid-run case:

```go
StatusUnknown    = lipgloss.NewStyle().Faint(true).Italic(true)
```

- [ ] **Step 2: Add new key bindings**

In `src/g3tui/internal/ui/keys.go`, add four new fields to the `KeyMap` struct (place them alphabetically near the navigation cluster):

```go
type KeyMap struct {
	Up         key.Binding
	Down       key.Binding
	Left       key.Binding
	Right      key.Binding
	PgUp       key.Binding
	PgDn       key.Binding
	GotoTop    key.Binding
	GotoBottom key.Binding
	Enter      key.Binding
	// ... existing fields ...
}
```

And add their initializations to the `Keys` value:

```go
PgUp:       key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "page up")),
PgDn:       key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "page down")),
GotoTop:    key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
GotoBottom: key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
```

These are used by Tasks 4 and 5 for in-pane navigation.

- [ ] **Step 3: Add focus enum and field to `App`**

In `src/g3tui/internal/ui/app.go`, add the focus enum near the top of the file (after the imports, before the `App` struct):

```go
// panelFocus identifies which of the three dashboard panels owns
// keyboard focus. Tab cycles forward through these values; Shift-Tab
// cycles backward.
type panelFocus int

const (
	focusScans panelFocus = iota
	focusTasks
	focusLogs

	panelFocusCount = 3
)
```

Add a `focus` field to the `App` struct (insert in the existing struct definition, near `streamState`):

```go
type App struct {
	cfg     Config
	cli     *client.Client
	pipes   []pipelines.Pipeline
	plugins []client.PluginListEntry

	scanList    ScanList
	scanDetail  ScanDetail
	confirm     *Confirm
	wizard      *Wizard
	banner      string
	streamState client.StreamState
	focus       panelFocus

	width  int
	height int
}
```

In `New()`, initialize `focus`:

```go
return App{
	// ... existing fields ...
	scanList:    NewScanList(),
	scanDetail:  NewScanDetail(cli),
	streamState: client.StreamConnecting,
	focus:       focusScans,
}
```

- [ ] **Step 4: Wire Tab/Shift-Tab handling in `App.Update`**

In `App.Update`, the `tea.KeyMsg` case handles modal-first routing. Add Tab handling right after the modal checks but before the global `Quit`/`New`/`Cancel`/`Delete` keys. The branch on `Filtering()` for the scan list also needs to allow Tab through:

Replace the existing key-handling sequence:

```go
case tea.KeyMsg:
    if a.wizard != nil { ... }
    if a.confirm != nil { ... }
    if a.scanList.Filtering() { /* old: forward all keys */ }
    switch {
    case key.Matches(m, Keys.Quit): ...
    case key.Matches(m, Keys.New): ...
    case key.Matches(m, Keys.Cancel): ...
    case key.Matches(m, Keys.Delete): ...
    }
    return a.dispatchToScanList(m)
```

with:

```go
case tea.KeyMsg:
    // Modals own all keystrokes when active.
    if a.wizard != nil {
        w, cmd := a.wizard.Update(m)
        a.wizard = &w
        return a, cmd
    }
    if a.confirm != nil {
        c, cmd := a.confirm.Update(m)
        a.confirm = &c
        return a, cmd
    }
    // Tab cycling is global to the dashboard (not captured by the
    // filter input — see spec section "Active-panel focus").
    switch {
    case key.Matches(m, Keys.Tab):
        a.focus = (a.focus + 1) % panelFocusCount
        return a, nil
    case key.Matches(m, Keys.ShiftTab):
        a.focus = (a.focus + panelFocusCount - 1) % panelFocusCount
        return a, nil
    }
    // Scan list filter mode owns letter keys (but not Tab — handled
    // above). Other panels never enter "input mode."
    if a.focus == focusScans && a.scanList.Filtering() {
        var cmd tea.Cmd
        a.scanList, cmd = a.scanList.Update(m)
        return a, cmd
    }
    switch {
    case key.Matches(m, Keys.Quit):
        return a, tea.Quit
    case key.Matches(m, Keys.New):
        w := NewWizard(a.cfg, a.cli, a.pipes, a.plugins)
        w.SetSize(a.width, a.bodyHeight())
        a.wizard = &w
        return a, nil
    case key.Matches(m, Keys.Cancel):
        if id := a.scanList.SelectedID(); id != "" {
            c := NewConfirm(
                "Cancel scan?",
                "Scan "+id+" will be stopped.",
                cancelScanCmd(a.cli, id),
            )
            a.confirm = &c
        }
        return a, nil
    case key.Matches(m, Keys.Delete):
        if id := a.scanList.SelectedID(); id != "" {
            c := NewConfirm(
                "Delete scan?",
                "Scan "+id+" will be stopped and removed. This cannot be undone.",
                deleteScanCmd(a.cli, id),
            )
            a.confirm = &c
        }
        return a, nil
    }
    // Routing per focused panel. Tasks 5 will extend this to forward
    // navigation keys to ScanDetail when focusTasks is active.
    return a.dispatchToScanList(m)
```

The two `c`/`d` action keys remain scan-scoped (per spec — there is no per-task cancel API). `l` and `r` will be focus-aware in Task 5 and Task 6's follow-on; for now the existing scan-scoped behavior is unchanged via `dispatchToScanList`.

- [ ] **Step 5: Render the focused-panel border**

ScanList and ScanDetail currently both use `PaneBorder` unconditionally. Pass focus information through `SetSize` is intrusive; cleaner is a public setter that toggles the border style each frame from `App.View`. Add this method to each:

In `src/g3tui/internal/ui/scanlist.go`, near `SetSize`:

```go
func (s *ScanList) SetFocused(focused bool) {
    s.focused = focused
}
```

And add the field to the struct:

```go
type ScanList struct {
    // ... existing fields ...
    focused bool
}
```

Then change every `PaneBorder.Width(...)` reference inside `ScanList.View()` to:

```go
border := PaneBorder
if s.focused {
    border = PaneBorderFocused
}
return border.Width(s.width - 2).Render(...)
```

Apply the same pattern to `ScanDetail` in `src/g3tui/internal/ui/scandetail.go`:

```go
type ScanDetail struct {
    // ... existing fields ...
    focused bool
}

func (sd *ScanDetail) SetFocused(focused bool) {
    sd.focused = focused
}
```

And in `ScanDetail.View()`, replace `PaneBorder.Width(...)` with:

```go
border := PaneBorder
if sd.focused {
    border = PaneBorderFocused
}
return border.Width(sd.width - 2).Height(sd.height - 2).Render(...)
```

Apply this to both code paths in `ScanDetail.View()` (the empty-state path and the populated path).

In `App.Update`'s `tea.WindowSizeMsg` handler (or any place size is reapplied), call `SetFocused` to reflect the current focus on each panel:

```go
case tea.WindowSizeMsg:
    a.width = m.Width
    a.height = m.Height
    a.scanList.SetSize(a.leftPaneWidth(), a.bodyHeight())
    a.scanDetail.SetSize(a.rightPaneWidth(), a.bodyHeight())
    a.applyFocus()
    if a.wizard != nil {
        a.wizard.SetSize(a.width, a.bodyHeight())
    }
    return a, nil
```

And add the helper:

```go
func (a *App) applyFocus() {
    a.scanList.SetFocused(a.focus == focusScans)
    a.scanDetail.SetFocused(a.focus == focusTasks)
    // focusLogs handled in Task 3.
}
```

Also call `a.applyFocus()` after every focus change in `Update` (the two Tab cases). Since `Update` works on a value receiver, you can either use `(&a).applyFocus()` or expand inline. The cleanest pattern:

```go
case key.Matches(m, Keys.Tab):
    a.focus = (a.focus + 1) % panelFocusCount
    a.applyFocus()
    return a, nil
case key.Matches(m, Keys.ShiftTab):
    a.focus = (a.focus + panelFocusCount - 1) % panelFocusCount
    a.applyFocus()
    return a, nil
```

Note that `applyFocus` takes a pointer receiver, so calling it on a value `a` works because Go automatically takes the address — but this only works because `a` is a local addressable value. The pattern is consistent with how `dispatchToScanList` is called in the same function.

- [ ] **Step 6: Build and lint**

```bash
cd /home/crapula/code/g3/src/g3tui
go build ./...
golangci-lint run ./...
```

Expected: clean build, `0 issues.`. The lint may complain that `focusLogs` is "unused" — that's expected and resolved in Task 3.

If lint flags `focusLogs`, add a `//nolint:unused` comment for now or temporarily remove the constant; restore in Task 3. The cleanest path: keep `focusLogs` as a defined constant but don't reference it yet. If lint flags it, accept the warning until Task 3.

- [ ] **Step 7: STOP — user commit checkpoint**

Suggested commit message: `g3tui: focus FSM with Tab cycling between panels; focused-border style`

---

## Task 3: Three-panel layout structure with placeholder Logs panel

**Intent.** Split the right side of the dashboard into Tasks (top) and Logs (bottom) panels. The Logs panel is inert in this work — it renders a panel-shaped placeholder and accepts focus, but has no content or interactions. Tier 3 will fill it in.

**Files:**
- Create: `src/g3tui/internal/ui/logspanel.go` — placeholder Logs panel model
- Modify: `src/g3tui/internal/ui/app.go` — vertical split rendering, route Logs focus

- [ ] **Step 1: Create `logspanel.go`**

Create `src/g3tui/internal/ui/logspanel.go`:

```go
package ui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// LogsPanel is the bottom-right panel reserved for live log preview of
// the focused task. In this iteration it is structural-only — the
// panel renders a placeholder, accepts focus, and discards keystrokes.
// Tier 3 fills in: live log fetching with debounce, scrollable
// viewport, follow-tail toggle, save-to-file.
type LogsPanel struct {
	width   int
	height  int
	focused bool
}

func NewLogsPanel() LogsPanel {
	return LogsPanel{}
}

func (l *LogsPanel) SetSize(w, h int) {
	l.width = w
	l.height = h
}

func (l *LogsPanel) SetFocused(focused bool) {
	l.focused = focused
}

func (l LogsPanel) Update(msg tea.Msg) (LogsPanel, tea.Cmd) {
	// Inert in this iteration — discards all keystrokes.
	return l, nil
}

func (l LogsPanel) View() string {
	border := PaneBorder
	if l.focused {
		border = PaneBorderFocused
	}
	title := AppTitle.Render("Logs")
	body := ListItemDimmed.Render("(log preview — coming in a follow-up release)")
	return border.Width(l.width - 2).Height(l.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, title, "", body),
	)
}

func (l LogsPanel) Help() []key.Binding {
	return nil
}
```

- [ ] **Step 2: Add `LogsPanel` to `App` and wire it in**

In `src/g3tui/internal/ui/app.go`, add the field to `App`:

```go
type App struct {
    // ... existing fields ...
    scanList    ScanList
    scanDetail  ScanDetail
    logsPanel   LogsPanel
    // ...
}
```

Initialize in `New()`:

```go
return App{
    // ... existing fields ...
    scanDetail:  NewScanDetail(cli),
    logsPanel:   NewLogsPanel(),
    // ...
}
```

- [ ] **Step 3: Replace the right-pane rendering in `App.View`**

Current right-pane rendering joins ScanList horizontally with ScanDetail (full-height). Change to: ScanDetail (top half) joined vertically with LogsPanel (bottom half), then that stack joined horizontally with ScanList.

Locate the body rendering block in `App.View`:

```go
default:
    body = lipgloss.JoinHorizontal(
        lipgloss.Top,
        a.scanList.View(),
        a.scanDetail.View(),
    )
    body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Left, lipgloss.Top, body)
```

Replace with:

```go
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
```

- [ ] **Step 4: Update `WindowSizeMsg` to size all three panels**

In the resize handler, the right-pane height is now split between ScanDetail and LogsPanel. Add the helpers:

```go
func (a App) tasksPaneHeight() int {
    return a.bodyHeight() / 2
}

func (a App) logsPaneHeight() int {
    return a.bodyHeight() - a.tasksPaneHeight()
}
```

Update the resize handler:

```go
case tea.WindowSizeMsg:
    a.width = m.Width
    a.height = m.Height
    a.scanList.SetSize(a.leftPaneWidth(), a.bodyHeight())
    a.scanDetail.SetSize(a.rightPaneWidth(), a.tasksPaneHeight())
    a.logsPanel.SetSize(a.rightPaneWidth(), a.logsPaneHeight())
    a.applyFocus()
    if a.wizard != nil {
        a.wizard.SetSize(a.width, a.bodyHeight())
    }
    return a, nil
```

- [ ] **Step 5: Update `applyFocus` to drive the Logs panel border**

In `applyFocus`:

```go
func (a *App) applyFocus() {
    a.scanList.SetFocused(a.focus == focusScans)
    a.scanDetail.SetFocused(a.focus == focusTasks)
    a.logsPanel.SetFocused(a.focus == focusLogs)
}
```

The `focusLogs` "unused" warning from Task 2 should now resolve.

- [ ] **Step 6: Build and lint**

```bash
cd /home/crapula/code/g3/src/g3tui
go build ./...
golangci-lint run ./...
```

Expected: clean build, `0 issues.`.

- [ ] **Step 7: STOP — user commit checkpoint**

Suggested commit message: `g3tui: three-panel layout with placeholder logs pane`

---

## Task 4: Scan-list scrolling via `bubbles/viewport`

**Intent.** Wrap the existing scan-list rendering in a `bubbles/viewport` so long lists scroll instead of clipping. Cursor stays in view; PgUp/PgDn page; g/G jump.

**Files:**
- Modify: `src/g3tui/internal/ui/scanlist.go`

- [ ] **Step 1: Add viewport import and field**

In `src/g3tui/internal/ui/scanlist.go`, add the import:

```go
import (
    "fmt"
    "sort"
    "strings"

    "github.com/charmbracelet/bubbles/key"
    "github.com/charmbracelet/bubbles/textinput"
    "github.com/charmbracelet/bubbles/viewport"
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
    "golismero.com/g3lib"
    "golismero.com/g3tui/internal/client"
)
```

Add the viewport field to the `ScanList` struct:

```go
type ScanList struct {
    entries  []g3lib.ScanStatusEntry
    filtered []g3lib.ScanStatusEntry
    cursor   int

    filtering bool
    filter    textinput.Model
    viewport  viewport.Model

    width   int
    height  int
    focused bool
}
```

- [ ] **Step 2: Initialize viewport in `NewScanList`**

```go
func NewScanList() ScanList {
    ti := textinput.New()
    ti.Placeholder = "filter (id prefix or status)"
    ti.Prompt = "/ "
    ti.CharLimit = 64
    return ScanList{filter: ti, viewport: viewport.New(0, 0)}
}
```

- [ ] **Step 3: Update `SetSize` to size the viewport**

The scan list panel reserves rows for: title (1), spacer (1), filter input (2 when active). Everything else is the scrollable list region.

```go
func (s *ScanList) SetSize(w, h int) {
    s.width = w
    s.height = h
    s.filter.Width = max(0, w-3)

    // Viewport content area: total panel height minus chrome (border 2,
    // padding 0 vertical) minus title (1) minus spacer (1) minus
    // optional filter input (2 when filtering).
    chrome := 2
    titleAndSpacer := 2
    filterRows := 0
    if s.filtering {
        filterRows = 2
    }
    inner := w - 4 // border 2 + padding 1+1
    contentHeight := max(1, h-chrome-titleAndSpacer-filterRows)
    s.viewport.Width = inner
    s.viewport.Height = contentHeight
}
```

- [ ] **Step 4: Add page/jump handling in `Update`**

In `ScanList.Update`'s `tea.KeyMsg` branch (the non-filtering switch), add cases for the new bindings:

```go
case key.Matches(m, Keys.PgUp):
    s.viewport.HalfViewUp()
    s.cursor = max(0, s.cursor-s.viewport.Height/2)
case key.Matches(m, Keys.PgDn):
    s.viewport.HalfViewDown()
    s.cursor = min(len(s.filtered)-1, s.cursor+s.viewport.Height/2)
    if s.cursor < 0 {
        s.cursor = 0
    }
case key.Matches(m, Keys.GotoTop):
    s.cursor = 0
    s.viewport.GotoTop()
case key.Matches(m, Keys.GotoBottom):
    if len(s.filtered) > 0 {
        s.cursor = len(s.filtered) - 1
    }
    s.viewport.GotoBottom()
```

For the existing `Up`/`Down` cases, ensure the viewport scrolls to keep the cursor in view. After updating `s.cursor`, add `s.ensureCursorVisible()` calls. Define the helper at the bottom of the file:

```go
// ensureCursorVisible scrolls the viewport so the cursor row stays
// within view. Each scan renders as 2 rows (id line + status line), so
// the cursor's pixel-row is cursor*2.
func (s *ScanList) ensureCursorVisible() {
    if len(s.filtered) == 0 {
        return
    }
    rowsPerEntry := 2
    cursorTop := s.cursor * rowsPerEntry
    cursorBottom := cursorTop + rowsPerEntry - 1

    if cursorTop < s.viewport.YOffset {
        s.viewport.SetYOffset(cursorTop)
    } else if cursorBottom >= s.viewport.YOffset+s.viewport.Height {
        s.viewport.SetYOffset(cursorBottom - s.viewport.Height + 1)
    }
}
```

In each `Up`/`Down` case body, append `s.ensureCursorVisible()`. For example:

```go
case key.Matches(m, Keys.Up):
    if s.cursor > 0 {
        s.cursor--
    }
    s.ensureCursorVisible()
case key.Matches(m, Keys.Down):
    if s.cursor < len(s.filtered)-1 {
        s.cursor++
    }
    s.ensureCursorVisible()
```

Also call `s.ensureCursorVisible()` after the cursor moves in `applyFilter` and after `ScanListSnapshot` / `ScanProgressUpdate` handling.

- [ ] **Step 5: Render entries into the viewport**

Refactor `ScanList.View` to push the entry rendering through the viewport:

```go
func (s ScanList) View() string {
    title := AppTitle.Render("Scans")

    var content string
    if len(s.filtered) == 0 {
        content = ListItemDimmed.Render("No scans yet — press [N] to start one")
    } else {
        var rows []string
        for i, e := range s.filtered {
            idLine, statusLine := formatScanRow(e, i == s.cursor)
            rows = append(rows, idLine, statusLine)
        }
        content = lipgloss.JoinVertical(lipgloss.Left, rows...)
    }
    s.viewport.SetContent(content)

    parts := []string{title, "", s.viewport.View()}
    if s.filtering {
        parts = append(parts, "", s.filter.View())
    }

    border := PaneBorder
    if s.focused {
        border = PaneBorderFocused
    }
    return border.Width(s.width - 2).Render(
        lipgloss.JoinVertical(lipgloss.Left, parts...),
    )
}
```

Note that `s.viewport.SetContent(content)` is called inside `View` — it's idempotent. If you prefer to keep `View` pure, move `SetContent` into `Update` whenever the entries change (after `applyFilter`).

- [ ] **Step 6: Build and lint**

```bash
cd /home/crapula/code/g3/src/g3tui
go build ./...
golangci-lint run ./...
```

Expected: clean build, `0 issues.`. `bubbles/viewport` is already in `go.mod` (transitively via other charmbracelet imports); `go mod tidy` may add it as a direct dep — that's fine.

- [ ] **Step 7: STOP — user commit checkpoint**

Suggested commit message: `g3tui: scrolling for scan list with cursor-keep-in-view`

---

## Task 5: Tasks-panel cursor + scrolling

**Intent.** Add a row cursor to the task table, wrap rendering in a viewport, and forward navigation keys to ScanDetail when Tasks panel is focused. The cursor's selected task ID becomes the implicit target for the future per-task `l` action (Task 6 wires it in).

**Files:**
- Modify: `src/g3tui/internal/ui/scandetail.go` — cursor field, viewport, navigation
- Modify: `src/g3tui/internal/ui/app.go` — forward keys to ScanDetail when focused

- [ ] **Step 1: Add viewport import, cursor and viewport fields**

In `src/g3tui/internal/ui/scandetail.go`, ensure the import block contains `viewport`:

```go
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
```

Add fields to the `ScanDetail` struct:

```go
type ScanDetail struct {
    cli *client.Client

    scanID     string
    scanStatus g3lib.G3SCANSTATUS
    tasks      []g3lib.TaskStatusEntry
    cursor     int
    viewport   viewport.Model

    width   int
    height  int
    focused bool
}
```

- [ ] **Step 2: Initialize viewport in `NewScanDetail`**

```go
func NewScanDetail(cli *client.Client) ScanDetail {
    return ScanDetail{cli: cli, viewport: viewport.New(0, 0)}
}
```

- [ ] **Step 3: Update `SetSize` to size the viewport**

```go
func (sd *ScanDetail) SetSize(w, h int) {
    sd.width = w
    sd.height = h
    inner := w - 4 // border 2 + padding 1+1
    chrome := 2
    titleRow := 1
    spacerRow := 1
    headerRow := 1 // task table header
    contentHeight := max(1, h-chrome-titleRow-spacerRow-headerRow)
    sd.viewport.Width = inner
    sd.viewport.Height = contentHeight
}
```

- [ ] **Step 4: Reset cursor on focus change; preserve on refresh**

In `ScanDetail.Update`, the `focusChangedMsg` already resets state. Update the `client.TaskStatusUpdate` handler to preserve cursor by task ID (or fall back to clamped index):

```go
case client.TaskStatusUpdate:
    if m.ScanID != sd.scanID {
        return sd, nil
    }
    if m.Err != nil {
        return sd, sd.fetchLaterCmd(2 * time.Second)
    }
    // Preserve cursor across refreshes by task ID where possible.
    var prevID string
    if sd.cursor >= 0 && sd.cursor < len(sd.tasks) {
        prevID = sd.tasks[sd.cursor].TaskID
    }
    sd.scanStatus = m.Response.ScanStatus
    sd.tasks = m.Response.Tasks
    if prevID != "" {
        sd.cursor = -1
        for i, t := range sd.tasks {
            if t.TaskID == prevID {
                sd.cursor = i
                break
            }
        }
    }
    if sd.cursor < 0 {
        if len(sd.tasks) == 0 {
            sd.cursor = 0
        } else if sd.cursor >= len(sd.tasks) {
            sd.cursor = len(sd.tasks) - 1
        } else {
            sd.cursor = 0
        }
    }
    sd.ensureCursorVisible()
    if isTerminal(sd.scanStatus) {
        return sd, nil
    }
    return sd, sd.fetchLaterCmd(2 * time.Second)
```

In `focusChangedMsg`, reset cursor:

```go
case focusChangedMsg:
    sd.scanID = m.ScanID
    sd.tasks = nil
    sd.scanStatus = ""
    sd.cursor = 0
    sd.viewport.GotoTop()
    if sd.scanID == "" {
        return sd, nil
    }
    return sd, sd.fetchNowCmd()
```

- [ ] **Step 5: Add navigation handling**

Add a navigation switch to `ScanDetail.Update` for keys (this case is reached only when Task 6's app.go routing forwards keys here):

```go
case tea.KeyMsg:
    if len(sd.tasks) == 0 {
        return sd, nil
    }
    switch {
    case key.Matches(m, Keys.Up):
        if sd.cursor > 0 {
            sd.cursor--
        }
        sd.ensureCursorVisible()
    case key.Matches(m, Keys.Down):
        if sd.cursor < len(sd.tasks)-1 {
            sd.cursor++
        }
        sd.ensureCursorVisible()
    case key.Matches(m, Keys.PgUp):
        sd.cursor = max(0, sd.cursor-sd.viewport.Height/2)
        sd.ensureCursorVisible()
    case key.Matches(m, Keys.PgDn):
        sd.cursor = min(len(sd.tasks)-1, sd.cursor+sd.viewport.Height/2)
        sd.ensureCursorVisible()
    case key.Matches(m, Keys.GotoTop):
        sd.cursor = 0
        sd.viewport.GotoTop()
    case key.Matches(m, Keys.GotoBottom):
        sd.cursor = len(sd.tasks) - 1
        sd.viewport.GotoBottom()
    }
    return sd, nil
```

The case statement should be added to the existing `switch m := msg.(type)` block.

Add the helper at the bottom of the file:

```go
func (sd *ScanDetail) ensureCursorVisible() {
    if len(sd.tasks) == 0 {
        return
    }
    if sd.cursor < sd.viewport.YOffset {
        sd.viewport.SetYOffset(sd.cursor)
    } else if sd.cursor >= sd.viewport.YOffset+sd.viewport.Height {
        sd.viewport.SetYOffset(sd.cursor - sd.viewport.Height + 1)
    }
}
```

The cursor here is one-row-per-task (unlike ScanList's two-rows-per-scan).

- [ ] **Step 6: Render task rows into the viewport**

Replace `ScanDetail.View` (the populated-tasks branch) to push rows through the viewport:

```go
func (sd ScanDetail) View() string {
    border := PaneBorder
    if sd.focused {
        border = PaneBorderFocused
    }
    if sd.scanID == "" {
        return border.Width(sd.width - 2).Height(sd.height - 2).Render(
            ListItemDimmed.Render("Select a scan to see its tasks"),
        )
    }
    header := AppTitle.Render(fmt.Sprintf("Detail · %s · %s", sd.scanID, string(sd.scanStatus)))
    if len(sd.tasks) == 0 {
        body := ListItemDimmed.Render(emptyTaskMessage(sd.scanStatus))
        return border.Width(sd.width - 2).Height(sd.height - 2).Render(
            lipgloss.JoinVertical(lipgloss.Left, header, "", body),
        )
    }

    rows := make([]string, 0, len(sd.tasks))
    for i, t := range sd.tasks {
        rows = append(rows, taskTableRow(t, i == sd.cursor))
    }
    sd.viewport.SetContent(lipgloss.JoinVertical(lipgloss.Left, rows...))

    return border.Width(sd.width - 2).Height(sd.height - 2).Render(
        lipgloss.JoinVertical(lipgloss.Left,
            header,
            "",
            taskTableHeader(),
            sd.viewport.View(),
        ),
    )
}
```

Update `taskTableRow` to accept a `selected` flag (the existing signature has only the entry):

```go
func taskTableRow(t g3lib.TaskStatusEntry, selected bool) string {
    state := taskStateStyle(t.State).Render(padRight(t.State, colState))
    row := fmt.Sprintf(
        "%-*s %s %-*s %-*s %8s %8s %6d",
        colTaskID, t.TaskID,
        state,
        colTool, padRight(t.Tool, colTool),
        colWorker, padRight(t.Worker, colWorker),
        humanAgo(t.LastLogTS),
        humanDuration(t.AgeSeconds),
        t.LineCount,
    )
    if selected {
        return ListItemSelected.Render(row)
    }
    return row
}
```

Task 6 will rewrite `taskTableRow` and `taskTableHeader` more substantially for the new column shape; this step keeps the existing column shape but adds the cursor styling.

- [ ] **Step 7: Forward keys to ScanDetail when Tasks panel is focused**

In `src/g3tui/internal/ui/app.go`, the existing `dispatchToScanList` is called for any non-handled key. Replace the final `return a.dispatchToScanList(m)` with focus-aware routing:

```go
// Routing per focused panel.
switch a.focus {
case focusScans:
    return a.dispatchToScanList(m)
case focusTasks:
    var cmd tea.Cmd
    a.scanDetail, cmd = a.scanDetail.Update(m)
    return a, cmd
case focusLogs:
    var cmd tea.Cmd
    a.logsPanel, cmd = a.logsPanel.Update(m)
    return a, cmd
}
return a, nil
```

This replaces the unconditional `return a.dispatchToScanList(m)` at the bottom of the `tea.KeyMsg` branch.

- [ ] **Step 8: Build and lint**

```bash
cd /home/crapula/code/g3/src/g3tui
go build ./...
golangci-lint run ./...
```

Expected: clean build, `0 issues.`.

- [ ] **Step 9: STOP — user commit checkpoint**

Suggested commit message: `g3tui: tasks panel cursor + viewport scrolling; focus-aware key routing`

---

## Task 6: Task column redesign

**Intent.** Replace the existing task table layout with the spec's six-column shape, priority-driven auto-hide for WORKER, progressive collapse for P0 columns, the state-emoji map, and TIME / LAST SEEN as separate columns with the correct semantics per scan state.

**Files:**
- Modify: `src/g3tui/internal/ui/scandetail.go` — column constants, layout decision, render helpers, emoji state map

- [ ] **Step 1: Replace column constants with priority/range model**

In `src/g3tui/internal/ui/scandetail.go`, locate the column constants block:

```go
const (
    colTaskID = 36
    colState  = 10
    colTool   = 12
    colWorker = 16
)
```

Replace with the new model. Each column has a default width and a collapse plan:

```go
// Column geometry. Order is the visual order. Priority 0 columns
// collapse before being hidden (they always render, even if just as
// "…"); priority 1 columns hide entirely when the panel is too narrow.
//
// IDs are 36-char UUIDs; STATE is a single emoji glyph (1 col) when
// collapsed but its expanded form fits in 10 cols. TIME and LAST SEEN
// each fit "12h 30m"-style values in 8 cols. WORKER is a g3worker name
// up to ~16 cols.
const (
    colTaskIDFull    = 36
    colTaskIDMid     = 15 // first 8 + ellipsis + last 6
    colTaskIDMin     = 9  // first 4 + ellipsis + last 4
    colTaskIDFloor   = 6  // first 2 + ellipsis + last 2

    colStateFull     = 10
    colStateFloor    = 1 // emoji glyph

    colToolFull      = 12
    colToolFloor     = 1

    colTimeFull      = 8
    colTimeFloor     = 1

    colLastSeenFull  = 8
    colLastSeenFloor = 1

    colWorkerFull    = 16
    // WORKER has no floor — it hides entirely.
)
```

- [ ] **Step 2: Add the state-emoji map**

Add a function near `taskStateStyle` (which currently maps state strings to lipgloss styles):

```go
// taskStateGlyph returns the single-character lifecycle indicator for
// a state. Combined with taskStateStyle's color, it conveys state in
// 1 col when the layout is constrained.
func taskStateGlyph(state string) string {
    switch strings.ToUpper(state) {
    case "RUNNING":
        return "▶"
    case "DONE":
        return "✓"
    case "ERROR":
        return "✗"
    case "CANCELED":
        return "⊘"
    case "WAITING":
        return "⌛"
    case "DISPATCHED":
        return "…"
    case "UNKNOWN":
        return "?"
    }
    return "·"
}
```

Update `taskStateStyle` to handle UNKNOWN:

```go
func taskStateStyle(state string) lipgloss.Style {
    switch strings.ToUpper(state) {
    case "RUNNING":
        return StatusRunning
    case "DONE":
        return StatusFinished
    case "ERROR":
        return StatusError
    case "CANCELED":
        return StatusCanceled
    case "DISPATCHED":
        return StatusDispatched
    case "WAITING":
        return StatusWaiting
    case "UNKNOWN":
        return StatusUnknown
    }
    return TableRow
}
```

- [ ] **Step 3: Add a layout decision struct**

Add this struct and helper near the top of the file:

```go
// taskLayout is the resolved per-frame column geometry chosen by
// pickTaskLayout based on available content width.
type taskLayout struct {
    idWidth        int  // colTaskIDFull / Mid / Min / Floor
    stateExpanded  bool // false = single-glyph
    toolWidth      int
    timeWidth      int
    lastSeenWidth  int
    workerVisible  bool
}

// pickTaskLayout chooses column widths to fit the available content
// area (excluding pane border + padding). Order of operations:
//   1. Hide WORKER if the full layout doesn't fit.
//   2. Progressively collapse P0 columns: TIME → LAST SEEN → TOOL → STATE → TASK ID.
//   3. If still wider than available, accept clipping (we're below
//      minimum supported terminal width).
//
// Each column's "narrow" width is its floor; all P0 columns ultimately
// collapse to a 1-char ellipsis. STATE is special — it collapses to
// the single emoji glyph rather than "…".
func pickTaskLayout(contentWidth int) taskLayout {
    // Five separators (one space between each pair of six visible
    // columns; four when WORKER is hidden).
    const sepFull = 5
    const sepNoWorker = 4

    full := taskLayout{
        idWidth:       colTaskIDFull,
        stateExpanded: true,
        toolWidth:     colToolFull,
        timeWidth:     colTimeFull,
        lastSeenWidth: colLastSeenFull,
        workerVisible: true,
    }
    if total := full.idWidth + colStateFull + full.toolWidth + full.timeWidth + full.lastSeenWidth + colWorkerFull + sepFull; total <= contentWidth {
        return full
    }

    // Hide WORKER.
    full.workerVisible = false
    if total := full.idWidth + colStateFull + full.toolWidth + full.timeWidth + full.lastSeenWidth + sepNoWorker; total <= contentWidth {
        return full
    }

    // Collapse columns in order: TIME → LAST SEEN → TOOL → STATE → TASK ID.
    full.timeWidth = colTimeFloor
    if total := full.idWidth + colStateFull + full.toolWidth + full.timeWidth + full.lastSeenWidth + sepNoWorker; total <= contentWidth {
        return full
    }
    full.lastSeenWidth = colLastSeenFloor
    if total := full.idWidth + colStateFull + full.toolWidth + full.timeWidth + full.lastSeenWidth + sepNoWorker; total <= contentWidth {
        return full
    }
    full.toolWidth = colToolFloor
    if total := full.idWidth + colStateFull + full.toolWidth + full.timeWidth + full.lastSeenWidth + sepNoWorker; total <= contentWidth {
        return full
    }
    full.stateExpanded = false
    if total := full.idWidth + colStateFloor + full.toolWidth + full.timeWidth + full.lastSeenWidth + sepNoWorker; total <= contentWidth {
        return full
    }

    // Step the TASK ID through its three intermediate widths.
    full.idWidth = colTaskIDMid
    if total := full.idWidth + colStateFloor + full.toolWidth + full.timeWidth + full.lastSeenWidth + sepNoWorker; total <= contentWidth {
        return full
    }
    full.idWidth = colTaskIDMin
    if total := full.idWidth + colStateFloor + full.toolWidth + full.timeWidth + full.lastSeenWidth + sepNoWorker; total <= contentWidth {
        return full
    }
    full.idWidth = colTaskIDFloor
    return full // floor reached; may still overflow if contentWidth is below minimum supported
}
```

- [ ] **Step 4: Add formatters for collapsed values**

Add three helpers near `padRight`:

```go
// collapseID applies middle-ellipsis truncation, preserving prefix and
// suffix per the spec. Width must be ≥ colTaskIDFloor (6); for shorter
// widths we floor to the same shape.
func collapseID(id string, width int) string {
    if len(id) <= width {
        return padRight(id, width)
    }
    if width >= len(id) {
        return id
    }
    if width < 5 {
        return id[:width]
    }
    // Split keep-room evenly between prefix and suffix, with one char
    // of ellipsis in the middle.
    keep := width - 1
    prefix := keep / 2
    suffix := keep - prefix
    return id[:prefix] + "…" + id[len(id)-suffix:]
}

// collapseEnd returns s padded or truncated-with-end-ellipsis to width.
// At width 1, returns "…" with the value entirely hidden — the
// floor-collapse signal that there's information here you can resize
// the terminal to see.
func collapseEnd(s string, width int) string {
    if width <= 0 {
        return ""
    }
    if width == 1 {
        if s == "" || s == "-" {
            return s
        }
        return "…"
    }
    if len(s) <= width {
        return padRight(s, width)
    }
    return s[:width-1] + "…"
}
```

- [ ] **Step 5: Compute TIME and LAST SEEN per row state**

Add a helper that derives the two time values for a row, given the spec's state-aware rules:

```go
// taskTimeFields returns (TIME, LAST SEEN) display strings per the
// spec's state-aware rules:
//   RUNNING:    TIME = active-since-start; LAST SEEN = since last log
//   terminal:   TIME = StartTS → CompleteTS duration; LAST SEEN = "-"
//   DISPATCHED: TIME = "-"; LAST SEEN = "-"
//   UNKNOWN:    TIME = StartTS → now (best-effort); LAST SEEN = since last log
func taskTimeFields(t g3lib.TaskStatusEntry) (timeStr, lastSeenStr string) {
    state := strings.ToUpper(t.State)
    switch state {
    case "RUNNING":
        if t.StartTS > 0 {
            timeStr = humanDurationFromDur(time.Since(time.Unix(t.StartTS, 0)))
        } else {
            timeStr = "-"
        }
        lastSeenStr = humanAgo(t.LastLogTS)
    case "DONE", "ERROR", "CANCELED", "FINISHED":
        if t.StartTS > 0 && t.CompleteTS > 0 {
            timeStr = humanDurationFromDur(time.Duration(t.CompleteTS-t.StartTS) * time.Second)
        } else if t.StartTS > 0 && t.LastLogTS > 0 {
            // Reconstructed path: no CompleteTS, approximate from logs.
            timeStr = humanDurationFromDur(time.Duration(t.LastLogTS-t.StartTS) * time.Second)
        } else {
            timeStr = "-"
        }
        lastSeenStr = "-"
    case "DISPATCHED", "WAITING":
        timeStr = "-"
        lastSeenStr = "-"
    case "UNKNOWN":
        if t.StartTS > 0 {
            timeStr = humanDurationFromDur(time.Since(time.Unix(t.StartTS, 0)))
        } else {
            timeStr = "-"
        }
        lastSeenStr = humanAgo(t.LastLogTS)
    default:
        timeStr = "-"
        lastSeenStr = "-"
    }
    return
}
```

- [ ] **Step 6: Rewrite `taskTableHeader` and `taskTableRow` against the layout**

Replace `taskTableHeader`:

```go
func taskTableHeader(layout taskLayout) string {
    parts := []string{
        padRight("TASK ID", layout.idWidth),
    }
    if layout.stateExpanded {
        parts = append(parts, padRight("STATE", colStateFull))
    } else {
        parts = append(parts, " ")
    }
    parts = append(parts, padRight("TOOL", layout.toolWidth))
    parts = append(parts, padRight("TIME", layout.timeWidth))
    parts = append(parts, padRight("LAST SEEN", layout.lastSeenWidth))
    if layout.workerVisible {
        parts = append(parts, padRight("WORKER", colWorkerFull))
    }
    return TableHeader.Render(strings.Join(parts, " "))
}
```

Replace `taskTableRow`:

```go
func taskTableRow(t g3lib.TaskStatusEntry, selected bool, layout taskLayout) string {
    timeStr, lastSeenStr := taskTimeFields(t)

    idCell := collapseID(t.TaskID, layout.idWidth)

    var stateCell string
    if layout.stateExpanded {
        stateCell = taskStateStyle(t.State).Render(padRight(strings.ToUpper(t.State), colStateFull))
    } else {
        stateCell = taskStateStyle(t.State).Render(taskStateGlyph(t.State))
    }

    parts := []string{
        idCell,
        stateCell,
        collapseEnd(t.Tool, layout.toolWidth),
        collapseEnd(timeStr, layout.timeWidth),
        collapseEnd(lastSeenStr, layout.lastSeenWidth),
    }
    if layout.workerVisible {
        parts = append(parts, padRight(t.Worker, colWorkerFull))
    }
    row := strings.Join(parts, " ")
    if selected {
        return ListItemSelected.Render(row)
    }
    return row
}
```

- [ ] **Step 7: Plumb the layout through `View`**

Update `ScanDetail.View` (the populated-tasks branch) to compute the layout once per frame and pass it to header and row formatters:

```go
// Populated-tasks branch:
inner := sd.width - 4 // border 2 + padding 1+1
layout := pickTaskLayout(inner)

rows := make([]string, 0, len(sd.tasks))
for i, t := range sd.tasks {
    rows = append(rows, taskTableRow(t, i == sd.cursor, layout))
}
sd.viewport.SetContent(lipgloss.JoinVertical(lipgloss.Left, rows...))

return border.Width(sd.width - 2).Height(sd.height - 2).Render(
    lipgloss.JoinVertical(lipgloss.Left,
        header,
        "",
        taskTableHeader(layout),
        sd.viewport.View(),
    ),
)
```

- [ ] **Step 8: Make `l` (logs) focus-aware**

In `src/g3tui/internal/ui/app.go`, the global keys section currently has no `l` handler at App level (it's per-panel). Add task-scoped logs handling: when Tasks panel is focused, pressing `l` opens the logs viewer for the currently-selected task. The logs viewer is Tier 3 work — for now, this just tracks the intent; we add the case but emit a banner rather than a full viewer:

In the global keys switch, after the `Delete` case:

```go
case key.Matches(m, Keys.Logs):
    switch a.focus {
    case focusTasks:
        if sid := a.scanList.SelectedID(); sid != "" {
            if tid := a.scanDetail.SelectedTaskID(); tid != "" {
                a.banner = "logs viewer for task " + tid + " — coming in a follow-up release"
                return a, tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpiredMsg{} })
            }
        }
    case focusScans:
        // Existing scan-scoped logs behavior — also Tier 3.
        a.banner = "scan logs viewer — coming in a follow-up release"
        return a, tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpiredMsg{} })
    }
    return a, nil
```

Add `Logs` to the `Keys` map's actively-bound entries if it isn't already; the existing `Keys.Logs` should be there from the original implementation (verify via grep). If it isn't, add:

```go
Logs: key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "logs")),
```

In `ScanDetail`, expose the selected task ID:

```go
func (sd ScanDetail) SelectedTaskID() string {
    if sd.cursor < 0 || sd.cursor >= len(sd.tasks) {
        return ""
    }
    return sd.tasks[sd.cursor].TaskID
}
```

- [ ] **Step 9: Update footer to show focus-aware keybinds**

In `App.renderFooter`, the binding selection currently keys off `a.confirm != nil` / `a.scanList.Filtering()`. Add a focus-based branch:

```go
func (a App) renderFooter() string {
    bindings := []key.Binding{Keys.Quit, Keys.New, Keys.Help, Keys.Tab}
    switch {
    case a.wizard != nil:
        bindings = []key.Binding{Keys.Quit}
        bindings = append(bindings, a.wizard.Help()...)
    case a.confirm != nil:
        bindings = append(bindings, a.confirm.Help()...)
    case a.scanList.Filtering():
        bindings = append(bindings, a.scanList.Help()...)
    default:
        switch a.focus {
        case focusScans:
            bindings = append(bindings, a.scanList.Help()...)
            if a.scanList.SelectedID() != "" {
                bindings = append(bindings, Keys.Logs, Keys.Report, Keys.Cancel, Keys.Delete)
            }
        case focusTasks:
            bindings = append(bindings, Keys.Up, Keys.Down, Keys.PgUp, Keys.PgDn)
            if a.scanDetail.SelectedTaskID() != "" {
                bindings = append(bindings, Keys.Logs)
            }
        case focusLogs:
            // No bindings until Tier 3 implements the panel.
        }
    }
    parts := make([]string, 0, len(bindings))
    for _, b := range bindings {
        h := b.Help()
        parts = append(parts, h.Key+" "+h.Desc)
    }
    return FooterBar.Render(strings.Join(parts, " · "))
}
```

- [ ] **Step 10: Verify the full repo builds**

```bash
cd /home/crapula/code/g3
make bin 2>&1 | tail -10
cd src/g3tui
golangci-lint run ./...
```

Expected: all binaries build clean, `0 issues.`.

- [ ] **Step 11: STOP — user commit checkpoint (plan complete)**

Working tree at this point includes all changes from Tasks 1–6.

Suggested commit message: `g3tui: lifecycle-aware column redesign with progressive collapse and emoji states`

If the user prefers, the entire plan can be a single commit: `g3tui: layout redesign — three panels, scrolling, lifecycle-aware columns, server-side reconstruction`

---

## Out of plan: deferred work

- **Logs panel implementation** (live log preview with debounced fetch). Reserved as a follow-up plan; the structural slot exists from Task 3.
- **Movable panel boundaries + preference persistence**. Tracked as future iteration.
- **Per-task cancel** action. Waits on server-side `/scan/task/stop` API (separate cross-component change).
- **`bubbles/list` migration for the scan list**. Either viable; sticking with viewport-wrapping for this work to minimize churn against the existing custom rendering. Reconsider if list-specific features (sort, multi-select) become useful.

---

## Post-implementation refinements

The original 6 tasks landed cleanly, but real-terminal testing surfaced a handful of edges that weren't covered by the original spec. These are documented here so the design ↔ code stays in sync; the design doc has been updated alongside.

| Refinement | What | Why |
|---|---|---|
| Floor headers (per-column emoji-bearing abbreviations) | Added `hdrTaskIDFloor=ID📎`, `hdrStateFloor=▶`, `hdrToolFloor=⚙`, `hdrTimeFloor=⏰`, `hdrLastSeenFloor=👀`. The original Task 6 had `padRight("LAST SEEN", layout.lastSeenWidth)` — at floor (1 col) the text leaked into next column and wrapped to a 2nd row. | Same row-wrap propagation that pushed the title bar off-screen. Header text must collapse alongside column width. |
| `headerForColumn(width, full, floor)` helper | Picks full vs floor header based on whether the column's allocated width is ≥ `lipgloss.Width(full)`. | Column widths can fall below the full-header text length even at "full" tier (e.g. `LAST SEEN` is 9 visual cols but `colLastSeenFull` was 8). |
| `colLastSeenFull`: 8 → 10 | Bumped so it's ≥ visual width of `LAST SEEN` (9). Otherwise the header collapses prematurely. | Latent bug exposed by the new collapse rule. |
| `colLastSeenFloor`: 1 → 2 (then header changed from `LAST👀` to just `👀`) | First testing pass had `LAST👀` at 6 cols floor; user feedback simplified to just the eyes emoji at 2 cols. | UX preference — single-emoji floor is cleaner for the "secondary" columns. |
| `colStateFloor` / `colToolFloor` / `colTimeFloor`: 1 → 2 | All three emoji-only floors bumped to 2 cols to accommodate the wide emoji rendering on terminals where the glyph takes 2 visual cols. | Some terminals render `⏰` as 2 cols; 1-col floor would mis-align value padding. |
| `padRight` switched from `len(s)` to `lipgloss.Width(s)` | Byte-length padding under-pads emoji content (4 bytes per glyph but 1–2 visual cols) and over-pads multibyte non-emoji content. | Correctness with emoji-bearing headers and any future multibyte content. |
| `renderDetailTitle(scanID, status, maxWidth)` | Progressive collapse of the Detail pane title: full UUID → mid → min → floor → status only → "Detail" → rune-truncated. | The Detail title was wrapping to 2–3 visual rows on narrow panes, growing the pane past its allocated height (lipgloss `Height` is a min not max), propagating overflow upward, and pushing the top header bar off-screen. |
| Scan-list UUID progressive collapse | `formatScanRow` now takes an `idWidth` and runs the UUID through `collapseID(scanID, idWidth)`. Same middle-ellipsis breakpoints (36 → 15 → 9 → 6) as the task table. | Original `Task 4` left UUIDs full-width even when the scan-list panel narrowed; on narrow terminals (panel = `width/2`) they wrapped or truncated unpredictably. |
| Minimum-size guard | `App.View` short-circuits to a centered `⚠ terminal too small` (rendered with `BannerWarn`) when `width < 60` or `height < 14`. | Below those thresholds the per-panel content row counts exceed allocated heights regardless of column collapse. The overflow propagates and pushes the top bar off-screen. Drawing the line is cleaner than chasing more degradation tiers. |
| Explicit `.Height(s.height-2)` on `ScanList.View` | Without it, the scan-list panel border was content-sized rather than allocation-sized — visibly shorter than the right-stack at most terminal sizes. | Bug only visible to keen-eyed reviewer: borders looked inconsistent. |

All of these were caught by behavioral testing in real terminals, not by lint or build. None changed the public design contract — they're refinements to make the spec actually hold under non-trivial size variation.

---

## Self-review

**Spec coverage:**
- Three-panel structure with placeholder Logs → Task 3 ✓
- Six-column responsive layout w/ priorities and progressive collapse → Task 6 ✓
- TIME and LAST SEEN as separate columns with state-aware semantics → Task 6 ✓
- Emoji state map → Task 6 ✓
- Focus FSM + Tab cycling + active-panel border → Task 2 ✓
- Per-panel keybind scoping (`l` task-scoped vs. scan-scoped, `c`/`d` always scan-scoped) → Tasks 2, 6 ✓
- Filter-mode behavior on focus change → Task 2 ✓
- Scrolling for both ScanList and ScanDetail → Tasks 4, 5 ✓
- Cursor preservation across task list refresh → Task 5 ✓
- Server-side reconstruction for terminated scans → Task 1 ✓
- `STATUS_UNKNOWN` for worker-crashed-mid-run → Task 1 (constant) + Task 6 (rendering) ✓
- Defensive parsing (first-occurrence-per-task) → Task 1 ✓

**Placeholder scan:** No `TBD`, `TODO`, "implement later", or "similar to Task N" references in the steps. Each code-touching step has a complete code block.

**Type consistency:** `taskTableRow`'s signature changes between Task 5 and Task 6 (the layout argument is added). Both versions are explicitly shown. `pickTaskLayout`, `taskLayout`, `collapseID`, `collapseEnd`, `taskTimeFields`, and `taskStateGlyph` are all defined in Task 6 before being called. `SelectedTaskID()` is defined in Task 6 Step 8 before Step 9 references it. `ensureCursorVisible()` is defined in Task 4 (ScanList) and Task 5 (ScanDetail) — separate methods on different types, no collision.

**Scope:** Single coherent change (layout redesign + supporting server fallback). Not split across tiers because the work is small enough that further tiering would be artificial.
