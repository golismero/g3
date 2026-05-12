# g3tui Tier 3 Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the remaining Tier 3 pieces — the Markdown report viewer (with Glamour rendering, `[S]` save, and `[E]` JSON export), a save-mode extension to the existing `FilePicker`, the `[S]` integration in the existing `LogsViewer`, and the `src/g3tui/README.md`.

**Architecture:** Seven tasks. Task 1 (save-mode picker) and Task 2 (client surface for JSON export) are the shared infrastructure; both are independent of each other. Task 3 (ReportPane skeleton) and Task 4 (App integration) build the new viewer without save/export; Task 5 adds the `[S]` and `[E]` flows on top of it. Task 6 wires `[S]` into the existing `LogsViewer`. Task 7 writes the README last, against shipped behavior.

**Tech Stack:** Go 1.26.2 (per `src/*/go.mod`); existing dependencies — `g3lib`, `bubbles/viewport`, `bubbles/textinput`, `bubbles/spinner`, `bubbletea`, `lipgloss`. **New dependency:** `github.com/charmbracelet/glamour` for Markdown rendering.

**Source spec:** [`docs/plans/2026-05-11-g3tui-tier3-completion-design.md`](2026-05-11-g3tui-tier3-completion-design.md)

**Status:** Implemented and tested 2026-05-12. All seven tasks shipped via `e095126` (initial impl through Refinement C); `a1ea2d6` (Refinements D + E + the `q`-in-viewers fix); `fab3f68` (Refinement F — `[E]` JSON export routing). The user's behavioral testing surfaced six refinements (A-F) plus the global-Quit guard, all documented in **Post-implementation refinements** below. Two follow-ups remain deferred — see the section at the bottom.

**Tests are user-owned** (memory: `feedback_tests_are_user_owned.md`). The plan does not include test-writing or behavioral-testing tasks. **Agent verification per task is strictly `go build ./...` (or `make bin`) + `golangci-lint run ./...`.** No `bin/g3tui` runs, no `docker compose` interactions, no live API calls.

**Git is user-owned** (memory: `feedback_git_is_user_owned.md`). No mutating git commands in any task. Read-only inspection (`git status`, `git diff`, `git log`) is fine.

**Commit cadence** (memory: `feedback_plan_commit_cadence.md`): tasks list explicit "STOP — user commit checkpoint" boundaries for documentation only. Agents push through without pausing. The user commits at the end of the plan or wherever they choose.

---

## Task overview

| Task | Scope | Depends on |
|---|---|---|
| **1 — FilePicker save-mode** | Add `PickerMode` enum, `NewSaveFilePicker` constructor, save-mode `Update`/`View` branches with inline overwrite-confirm; add `Keys.Save`, `Keys.Export`; add `BannerSuccess` style; new `pickerSaveConfirmedMsg` type | None |
| **2 — Client surface for JSON export** | Add `GetScanDataList`, `GetScanData` methods to `client.Client`; add export-related message types | None |
| **3 — ReportPane (skeleton + Glamour render)** | Create `report.go`; state machine (loading/loaded/error); Glamour rendering with width-aware re-render; caveats banner; loading spinner; error retry | None (uses existing `GetReport` and `ReportLoaded`) |
| **4 — Wire ReportPane into App** | Add `reportPane` field; `[R]` handler with terminal gating; message routing; view composition; `SetScanStatus` sync from `dispatchToScanList` | 3 |
| **5 — `[S]` Markdown save and `[E]` JSON export in ReportPane** | Compose save-mode picker; `[S]` writes raw markdown sync; `[E]` runs goroutine with temp+rename + cancelable spinner overlay | 1, 2, 3, 4 |
| **6 — LogsViewer `[S]` integration** | Compose save-mode picker on `LogsViewer`; add `renderForSave` plain-text emitter; wire pickerSaveConfirmedMsg → `os.WriteFile`; update `Help()` | 1 |
| **7 — README** | Write `src/g3tui/README.md` per design outline | 1–6 (documents shipped behavior) |

---

## Prerequisites

- Go toolchain matching `src/*/go.mod` (currently 1.26.2).
- `golangci-lint` 2.x.
- Network access for `go get github.com/charmbracelet/glamour` in Task 3. If the environment is offline, vendor the dependency or pre-populate `GOMODCACHE`.

---

## Task 1: FilePicker save-mode

**Intent.** Extend the existing `FilePicker` with an opt-in save-mode that reuses directory navigation, replaces multi-select with a single filename textinput, and handles file-exists overwrite confirmation inline. Add the `Keys.Save` and `Keys.Export` bindings and the `BannerSuccess` style that downstream tasks will use.

**Files:**
- Modify: `src/g3tui/internal/ui/keys.go` — add `Keys.Save`, `Keys.Export`
- Modify: `src/g3tui/internal/ui/styles.go` — add `BannerSuccess`
- Modify: `src/g3tui/internal/ui/picker.go` — add `PickerMode`, fields, save-mode behavior, overwrite-confirm state, `pickerSaveConfirmedMsg` type

- [ ] **Step 1: Add `Keys.Save` and `Keys.Export` to `KeyMap`**

In `src/g3tui/internal/ui/keys.go`, add two fields to the `KeyMap` struct and two bindings in the global `Keys` initializer. `Keys.Yes` and `Keys.No` already exist with the right key mappings (`y`/`Y` and `n`/`N`/`esc`); no new entries needed for the overwrite-confirm prompt.

Add to the `KeyMap` struct (alongside `Report`, `Yes`, `No`):

```go
Save       key.Binding
Export     key.Binding
```

Add to the `Keys` initializer (place near `Report`, `Yes`, `No`):

```go
Save:       key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "save")),
Export:     key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "export")),
```

- [ ] **Step 2: Add `BannerSuccess` style to `styles.go`**

In `src/g3tui/internal/ui/styles.go`, add the success-banner style next to the existing `BannerError` and `BannerWarn`:

```go
BannerSuccess = lipgloss.NewStyle().
        Foreground(lipgloss.Color("232")).
        Background(lipgloss.Color("42")).
        Padding(0, 1)
```

Color `42` is the green used for `StatusRunning` and `DotConnected`, so the success banner matches the existing palette.

- [ ] **Step 3: Add `PickerMode` enum, fields, and `NewSaveFilePicker` constructor**

In `src/g3tui/internal/ui/picker.go`, add imports for `bubbles/textinput` and `os`, then declare the new types and constructor. Place these immediately above the existing `FilePicker` struct definition:

```go
// PickerMode selects between the multi-select open-mode used by the
// wizard's imports flow and the single-target save-mode used by
// ReportPane and LogsViewer to pick a save destination.
type PickerMode int

const (
    PickerOpen PickerMode = iota // existing behavior: space-toggle multi-select
    PickerSave                    // new: filename textinput + inline overwrite confirm
)

// pickerSaveConfirmedMsg fires when the user confirms a save destination
// in save-mode (including after an overwrite-confirm prompt if the path
// already existed). Path is absolute and fully resolved.
type pickerSaveConfirmedMsg struct {
    Path string
}
```

Add three new fields to the `FilePicker` struct (after `err string`):

```go
mode       PickerMode
title      string
filename   textinput.Model
confirming bool
```

Update the import block at the top to include:

```go
"github.com/charmbracelet/bubbles/textinput"
```

Add the new constructor below the existing `NewFilePicker`:

```go
// NewSaveFilePicker builds a save-mode picker. The textinput is
// pre-populated with defaultFilename; the picker still permits
// directory navigation, but Space-toggle multi-select is replaced by
// the textinput. On confirm, if the resolved path exists, an inline
// overwrite-confirm prompt is shown; on accept the picker emits
// pickerSaveConfirmedMsg{Path}. On cancel, pickerCanceledMsg.
func NewSaveFilePicker(initialDir, defaultFilename, title string) FilePicker {
    ti := textinput.New()
    ti.Prompt = ""
    ti.SetValue(defaultFilename)
    ti.CharLimit = 256
    ti.Focus()

    p := FilePicker{
        dir:      initialDir,
        selected: map[string]bool{},
        mode:     PickerSave,
        title:    title,
        filename: ti,
    }
    p.refresh()
    return p
}
```

The existing `NewFilePicker(initialDir string) FilePicker` is unchanged.

- [ ] **Step 4: Update `FilePicker.Update` to handle save-mode keystrokes**

In `src/g3tui/internal/ui/picker.go`, replace the existing `Update` method (lines 95-147 in the current file) with the version below. The open-mode behavior is unchanged; save-mode adds a new branch that handles the overwrite-confirm sub-state, then textinput editing, then list navigation, then Enter resolution:

```go
func (p FilePicker) Update(msg tea.Msg) (FilePicker, tea.Cmd) {
    km, ok := msg.(tea.KeyMsg)
    if !ok {
        return p, nil
    }

    if p.mode == PickerSave {
        // Overwrite-confirm sub-state: only y/n/esc matter.
        if p.confirming {
            switch {
            case key.Matches(km, Keys.Yes):
                return p, p.saveConfirmCmd()
            case key.Matches(km, Keys.No):
                p.confirming = false
                return p, nil
            }
            return p, nil
        }

        // Picking state: route Enter and the navigation keys to the
        // picker; everything else goes to the textinput.
        switch {
        case key.Matches(km, Keys.Back):
            return p, func() tea.Msg { return pickerCanceledMsg{} }

        case key.Matches(km, Keys.Enter):
            // On a directory: descend. Anywhere else: confirm save.
            if p.cursor < len(p.entries) && p.entries[p.cursor].IsDir {
                p.dir = p.entries[p.cursor].Path
                p.cursor = 0
                p.refresh()
                return p, nil
            }
            return p.attemptSave()

        case key.Matches(km, Keys.Up):
            if p.cursor > 0 {
                p.cursor--
                p.syncFilenameFromCursor()
            }
            return p, nil

        case key.Matches(km, Keys.Down):
            if p.cursor < len(p.entries)-1 {
                p.cursor++
                p.syncFilenameFromCursor()
            }
            return p, nil
        }

        // Everything else routes to the textinput.
        var cmd tea.Cmd
        p.filename, cmd = p.filename.Update(msg)
        return p, cmd
    }

    // Open-mode behavior (unchanged).
    switch {
    case key.Matches(km, Keys.Back):
        return p, func() tea.Msg { return pickerCanceledMsg{} }
    case key.Matches(km, Keys.Enter):
        if p.cursor < len(p.entries) && p.entries[p.cursor].IsDir {
            p.dir = p.entries[p.cursor].Path
            p.cursor = 0
            p.refresh()
            return p, nil
        }
        return p, p.confirmCmd()
    case key.Matches(km, Keys.Up):
        if p.cursor > 0 {
            p.cursor--
        }
    case key.Matches(km, Keys.Down):
        if p.cursor < len(p.entries)-1 {
            p.cursor++
        }
    case key.Matches(km, Keys.Right):
        if p.cursor < len(p.entries) && p.entries[p.cursor].IsDir {
            p.dir = p.entries[p.cursor].Path
            p.cursor = 0
            p.refresh()
        }
    case key.Matches(km, Keys.Left):
        if parent := filepath.Dir(p.dir); parent != p.dir {
            p.dir = parent
            p.cursor = 0
            p.refresh()
        }
    case key.Matches(km, Keys.Space):
        if p.cursor < len(p.entries) {
            e := p.entries[p.cursor]
            if !e.IsDir {
                if p.selected[e.Path] {
                    delete(p.selected, e.Path)
                } else {
                    p.selected[e.Path] = true
                }
            }
        }
    }
    return p, nil
}
```

- [ ] **Step 5: Add the save-mode helpers `syncFilenameFromCursor`, `resolvePath`, `attemptSave`, and `saveConfirmCmd`**

Add these methods below the existing `confirmCmd` in `picker.go`:

```go
// syncFilenameFromCursor copies the filename of the currently-highlighted
// file (not directory) into the textinput. Lets the user navigate to
// an existing filename with ↑↓ to overwrite it without retyping.
func (p *FilePicker) syncFilenameFromCursor() {
    if p.cursor >= len(p.entries) {
        return
    }
    e := p.entries[p.cursor]
    if e.IsDir {
        return
    }
    p.filename.SetValue(e.Name)
    p.filename.CursorEnd()
}

// resolvePath resolves the textinput value to an absolute path. An
// absolute value is used verbatim; a relative one is joined to the
// current directory. No tilde or environment-variable expansion.
func (p FilePicker) resolvePath() string {
    value := strings.TrimSpace(p.filename.Value())
    if value == "" {
        return ""
    }
    if filepath.IsAbs(value) {
        return value
    }
    return filepath.Join(p.dir, value)
}

// attemptSave checks whether the resolved path already exists. If so,
// the picker enters the overwrite-confirming sub-state and waits for
// y/n. Otherwise, emit the confirmed message immediately.
func (p FilePicker) attemptSave() (FilePicker, tea.Cmd) {
    path := p.resolvePath()
    if path == "" {
        return p, nil // empty filename: no-op, stay in the picker
    }
    if _, err := os.Stat(path); err == nil {
        p.confirming = true
        return p, nil
    }
    return p, func() tea.Msg { return pickerSaveConfirmedMsg{Path: path} }
}

// saveConfirmCmd emits the confirmed message after the user accepts
// the overwrite prompt.
func (p FilePicker) saveConfirmCmd() tea.Cmd {
    path := p.resolvePath()
    return func() tea.Msg { return pickerSaveConfirmedMsg{Path: path} }
}
```

Add `strings` to the import block at the top of the file if it isn't already present.

- [ ] **Step 6: Update `FilePicker.View` to render save-mode**

Replace the existing `View` method (lines 158-209) with the version below. The open-mode block matches the original output exactly; the save-mode block renders the directory listing, the filename row, and either the navigation hint or the overwrite-confirm prompt:

```go
func (p FilePicker) View() string {
    inner := max(50, min(p.width-4, 80))
    box := lipgloss.NewStyle().
        Border(lipgloss.RoundedBorder()).
        BorderForeground(lipgloss.Color("214")).
        Padding(1, 2).
        Width(inner)

    titleText := "Select files (multi)"
    if p.mode == PickerSave {
        titleText = p.title
        if titleText == "" {
            titleText = "Save file"
        }
    }
    title := AppTitle.Render(titleText)
    pathLine := ListItemDimmed.Render(p.dir)
    rows := []string{title, pathLine, ""}
    if p.err != "" {
        rows = append(rows, BannerError.Width(inner-4).Render(p.err), "")
    }

    const visible = 12
    start := 0
    if p.cursor >= visible {
        start = p.cursor - visible + 1
    }
    end := min(start+visible, len(p.entries))
    for i := start; i < end; i++ {
        e := p.entries[i]
        cursor := "  "
        if i == p.cursor {
            cursor = "▸ "
        }
        var row string
        if p.mode == PickerSave {
            name := e.Name
            if e.IsDir {
                name += "/"
            }
            row = fmt.Sprintf("%s  %s", cursor, name)
        } else {
            check := "[ ]"
            switch {
            case e.IsDir:
                check = "   "
            case p.selected[e.Path]:
                check = "[x]"
            }
            name := e.Name
            if e.IsDir {
                name += "/"
            }
            row = fmt.Sprintf("%s%s %s", cursor, check, name)
        }
        if i == p.cursor {
            row = ListItemSelected.Render(row)
        }
        rows = append(rows, row)
    }

    rows = append(rows, "")

    if p.mode == PickerSave {
        rows = append(rows, "Filename: "+p.filename.View(), "")
        if p.confirming {
            base := filepath.Base(p.resolvePath())
            warn := fmt.Sprintf("[!] %s exists. Overwrite? [y/n]", base)
            rows = append(rows, BannerWarn.Render(warn))
        } else {
            footer := "[↑↓] nav  [enter] save / open dir  [esc] cancel"
            rows = append(rows, FooterBar.Render(footer))
        }
    } else {
        footer := fmt.Sprintf(
            "[↑↓] move  [→/enter] open dir  [←] up  [space] toggle file  [enter] confirm  [esc] cancel  ·  %d selected",
            len(p.selected),
        )
        rows = append(rows, FooterBar.Render(footer))
    }

    return box.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}
```

- [ ] **Step 7: Update `FilePicker.Help` to advertise the right keys per mode**

Replace the existing `Help` method (lines 211-213) with:

```go
func (p FilePicker) Help() []key.Binding {
    if p.mode == PickerSave {
        return []key.Binding{Keys.Up, Keys.Down, Keys.Enter, Keys.Back}
    }
    return []key.Binding{Keys.Up, Keys.Down, Keys.Left, Keys.Right, Keys.Space, Keys.Enter, Keys.Back}
}
```

- [ ] **Step 8: Verify the change builds and lints**

Run: `cd src/g3tui && go build ./...`
Expected: success, no output.

Run: `cd src/g3tui && golangci-lint run ./...`
Expected: clean.

If the lint complains about the picker.go file's growing size (it goes from 213 lines to ~310 lines), that's expected and below typical thresholds. The file's single responsibility ("FilePicker component, open and save modes") is preserved.

STOP — user commit checkpoint. (Suggested message: "Add save-mode to FilePicker with inline overwrite-confirm.")

---

## Task 2: Client surface for JSON export

**Intent.** Add `GetScanDataList` and `GetScanData` to `client.Client` so ReportPane's `[E]` can drive the same two-call export pattern that `g3cli export` uses today. Add the export-related `tea.Msg` envelopes.

**Files:**
- Modify: `src/g3tui/internal/client/client.go` — add `GetScanDataList`, `GetScanData`
- Modify: `src/g3tui/internal/client/messages.go` — add export message types

- [ ] **Step 1: Add `GetScanDataList` and `GetScanData` to `client.go`**

In `src/g3tui/internal/client/client.go`, add two methods after the existing `GetReport` (around line 108). Both use the standard `call` helper:

```go
// GetScanDataList → /scan/datalist. Returns all data object IDs for the
// scan. Used by [E] export to enumerate IDs before batch-fetching the
// objects themselves.
func (c *Client) GetScanDataList(ctx context.Context, scanID string) ([]string, error) {
    var out []string
    if err := c.call(ctx, "/scan/datalist", g3lib.ReqGetScanDataIDs{ScanID: scanID}, &out); err != nil {
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
    err := c.call(ctx, "/scan/data", g3lib.ReqLoadData{ScanID: scanID, DataIDs: dataIDs}, &out)
    return out, err
}
```

- [ ] **Step 2: Add export message types to `messages.go`**

In `src/g3tui/internal/client/messages.go`, add the following message types at the bottom of the file (after `ErrorMsg`):

```go
// ReportSaved is emitted on a successful [S] in the report viewer.
// Path is the absolute path the report was written to.
type ReportSaved struct {
    Path string
}

// ReportSaveError is emitted when [S] in the report viewer fails to
// write the file (permission denied, no space, etc.).
type ReportSaveError struct {
    Err error
}

// ExportProgress is emitted by the JSON export goroutine after each
// /scan/data batch returns, so the spinner overlay can show "Done/Total".
type ExportProgress struct {
    Done  int
    Total int
}

// ExportDone is emitted when the JSON export goroutine finishes a
// successful temp+rename. Path is the final destination.
type ExportDone struct {
    Path  string
    Count int
}

// ExportError is emitted when the export goroutine fails (network,
// disk full, cancellation). The temp file has been removed; Path is
// the original target the user picked, useful for the error banner.
type ExportError struct {
    Path string
    Err  error
}
```

- [ ] **Step 3: Verify**

Run: `cd src/g3tui && go build ./...`
Expected: success.

Run: `cd src/g3tui && golangci-lint run ./...`
Expected: clean.

STOP — user commit checkpoint. (Suggested message: "Add client wrappers and message envelopes for JSON export.")

---

## Task 3: ReportPane skeleton with Glamour rendering

**Intent.** Create `src/g3tui/internal/ui/report.go` as a self-contained component that fetches `/scan/report` once on open, renders the Markdown via Glamour, and supports scrolling. No save or export yet — those land in Task 5. Add the `glamour` dependency.

**Files:**
- Modify: `src/g3tui/go.mod`, `src/g3tui/go.sum` — add `github.com/charmbracelet/glamour`
- Create: `src/g3tui/internal/ui/report.go`

- [ ] **Step 1: Add the Glamour dependency**

From the repo root, run:

```bash
cd src/g3tui && go get github.com/charmbracelet/glamour@latest && go mod tidy
```

Verify the new line in `src/g3tui/go.mod`'s `require` block:

```
github.com/charmbracelet/glamour vX.Y.Z
```

(Exact version is whatever the latest minor release pins to at the time of execution.)

- [ ] **Step 2: Create the `ReportPane` struct, constants, and constructor**

Create `src/g3tui/internal/ui/report.go` with the following content. This is the full file at the end of this task — later tasks (5) modify it; Task 4 references it as-is:

```go
package ui

import (
    "context"
    "fmt"

    "github.com/charmbracelet/bubbles/key"
    "github.com/charmbracelet/bubbles/spinner"
    "github.com/charmbracelet/bubbles/viewport"
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/glamour"
    "github.com/charmbracelet/lipgloss"
    "golismero.com/g3lib"
    "golismero.com/g3tui/internal/client"
)

// reportPaneGenCounter is a process-wide monotonic counter mirroring
// the LogsViewer pattern: it stamps each ReportPane and its async
// messages so a late-arriving fetch result for a previously-closed pane
// cannot be misrouted to a freshly-opened one for the same scanID.
var reportPaneGenCounter int

type reportState int

const (
    reportLoading reportState = iota
    reportLoaded
    reportError
)

// reportFetchedMsg carries the one-shot /scan/report result back to the
// pane. Generation guards against late deliveries.
type reportFetchedMsg struct {
    Generation int
    Markdown   string
    Errors     string
    Err        error
}

// reportPaneClosedMsg fires on Esc. App tears down the overlay.
type reportPaneClosedMsg struct{}

// ReportPane is the full-screen Markdown report overlay opened by `r`.
// Parallel in role and lifecycle to LogsViewer: instantiated each open,
// discarded on close, no long-lived state.
type ReportPane struct {
    cli *client.Client

    scanID     string
    scanStatus g3lib.G3SCANSTATUS
    generation int

    state    reportState
    markdown string // raw markdown from /scan/report
    rendered string // glamour-rendered output cached at viewport width
    errors   string // server-side parse-error blob (caveats banner)
    err      error  // load error → state == reportError

    viewport viewport.Model
    spinner  spinner.Model

    width  int
    height int
}

func NewReportPane(cli *client.Client, scanID string, scanStatus g3lib.G3SCANSTATUS) ReportPane {
    reportPaneGenCounter++
    sp := spinner.New()
    sp.Spinner = spinner.Dot
    return ReportPane{
        cli:        cli,
        scanID:     scanID,
        scanStatus: scanStatus,
        generation: reportPaneGenCounter,
        state:      reportLoading,
        viewport:   viewport.New(0, 0),
        spinner:    sp,
    }
}

// SetScanStatus keeps the pane's title in sync with the dashboard's
// scan list. Mirrors LogsViewer.SetScanStatus.
func (p *ReportPane) SetScanStatus(status g3lib.G3SCANSTATUS) {
    p.scanStatus = status
}

func (p *ReportPane) SetSize(w, h int) {
    p.width = w
    p.height = h
    inner := w - 4 // border 2 + padding 1+1
    chrome := 2
    titleRow := 1
    spacerRow := 1
    bannerRow := 0
    if p.errors != "" {
        bannerRow = 2 // banner + spacer
    }
    contentHeight := max(1, h-chrome-titleRow-spacerRow-bannerRow)
    p.viewport.Width = inner
    p.viewport.Height = contentHeight
    if p.state == reportLoaded {
        p.renderAndApply()
    }
}

func (p ReportPane) InitCmd() tea.Cmd {
    return tea.Batch(p.fetchCmd(), p.spinner.Tick)
}

func (p ReportPane) Help() []key.Binding {
    return []key.Binding{Keys.Back}
}

func (p ReportPane) Update(msg tea.Msg) (ReportPane, tea.Cmd) {
    switch m := msg.(type) {
    case reportFetchedMsg:
        if m.Generation != p.generation {
            return p, nil // stale
        }
        if m.Err != nil {
            p.state = reportError
            p.err = m.Err
            return p, nil
        }
        p.markdown = m.Markdown
        p.errors = m.Errors
        p.state = reportLoaded
        // banner row recomputes the body height.
        p.SetSize(p.width, p.height)
        p.renderAndApply()
        p.viewport.GotoTop()
        return p, nil

    case spinner.TickMsg:
        if p.state != reportLoading {
            return p, nil
        }
        var cmd tea.Cmd
        p.spinner, cmd = p.spinner.Update(m)
        return p, cmd

    case tea.KeyMsg:
        switch {
        case key.Matches(m, Keys.Back):
            return p, func() tea.Msg { return reportPaneClosedMsg{} }
        case key.Matches(m, Keys.Retry):
            if p.state == reportError {
                p.state = reportLoading
                p.err = nil
                return p, tea.Batch(p.fetchCmd(), p.spinner.Tick)
            }
        case key.Matches(m, Keys.Up):
            p.viewport.ScrollUp(1)
        case key.Matches(m, Keys.Down):
            p.viewport.ScrollDown(1)
        case key.Matches(m, Keys.PgUp):
            p.viewport.HalfPageUp()
        case key.Matches(m, Keys.PgDn):
            p.viewport.HalfPageDown()
        case key.Matches(m, Keys.GotoTop):
            p.viewport.GotoTop()
        case key.Matches(m, Keys.GotoBottom):
            p.viewport.GotoBottom()
        }
        return p, nil
    }
    return p, nil
}

func (p ReportPane) View() string {
    title := AppTitle.Render(p.renderTitle(p.width - 4))

    var body string
    switch p.state {
    case reportLoading:
        body = lipgloss.Place(
            p.viewport.Width, p.viewport.Height,
            lipgloss.Center, lipgloss.Center,
            p.spinner.View()+"  Loading report…",
        )
    case reportError:
        msg := fmt.Sprintf("Failed to load report: %v\n\n[r] retry  [esc] back", p.err)
        body = lipgloss.Place(
            p.viewport.Width, p.viewport.Height,
            lipgloss.Center, lipgloss.Center,
            BannerError.Render(msg),
        )
    case reportLoaded:
        body = p.viewport.View()
    }

    parts := []string{title, ""}
    if p.errors != "" {
        first := firstLine(p.errors)
        parts = append(parts, BannerWarn.Width(p.viewport.Width).Render(
            "Report generated with caveats: "+first,
        ))
    }
    parts = append(parts, body)

    return PaneBorderFocused.Width(p.width - 2).Height(p.height - 2).Render(
        lipgloss.JoinVertical(lipgloss.Left, parts...),
    )
}

func (p ReportPane) renderTitle(maxWidth int) string {
    status := string(p.scanStatus)
    if status == "" {
        status = "?"
    }
    candidates := []string{
        fmt.Sprintf("Report · %s · %s", p.scanID, status),
        fmt.Sprintf("Report · %s · %s", collapseID(p.scanID, colTaskIDMid), status),
        fmt.Sprintf("Report · %s · %s", collapseID(p.scanID, colTaskIDMin), status),
        fmt.Sprintf("Report · %s · %s", collapseID(p.scanID, colTaskIDFloor), status),
        fmt.Sprintf("Report · %s", status),
        "Report",
    }
    for _, c := range candidates {
        if lipgloss.Width(c) <= maxWidth {
            return c
        }
    }
    runes := []rune("Report")
    if len(runes) > maxWidth {
        return string(runes[:maxWidth])
    }
    return "Report"
}

// renderAndApply re-renders the cached markdown through Glamour at the
// current viewport width and pushes the result into the viewport.
// Called on initial load and on every resize.
func (p *ReportPane) renderAndApply() {
    width := p.viewport.Width
    if width < 1 {
        width = 1
    }
    r, err := glamour.NewTermRenderer(
        glamour.WithAutoStyle(),
        glamour.WithWordWrap(width),
    )
    if err != nil {
        // Defensive: fall back to raw markdown if Glamour can't initialize
        // (e.g., unsupported terminal). Better to show the markdown
        // than a blank pane.
        p.rendered = p.markdown
        p.viewport.SetContent(p.rendered)
        return
    }
    out, err := r.Render(p.markdown)
    if err != nil {
        p.rendered = p.markdown
        p.viewport.SetContent(p.rendered)
        return
    }
    p.rendered = out
    p.viewport.SetContent(out)
}

func (p ReportPane) fetchCmd() tea.Cmd {
    cli := p.cli
    sid := p.scanID
    gen := p.generation
    return func() tea.Msg {
        md, errs, err := cli.GetReport(context.Background(), sid)
        return reportFetchedMsg{
            Generation: gen,
            Markdown:   md,
            Errors:     errs,
            Err:        err,
        }
    }
}

// firstLine returns the substring of s up to (but not including) the
// first newline. Used for the caveats banner so a multi-line error
// blob doesn't blow up the title row.
func firstLine(s string) string {
    for i, r := range s {
        if r == '\n' {
            return s[:i]
        }
    }
    return s
}
```

- [ ] **Step 3: Verify**

Run: `cd src/g3tui && go build ./...`
Expected: success. The new file compiles; `glamour` resolves; the constants `colTaskIDMid`, `colTaskIDMin`, `colTaskIDFloor` are inherited from existing `ui` package files (they are already defined for `LogsViewer.renderTitle`).

Run: `cd src/g3tui && golangci-lint run ./...`
Expected: clean.

STOP — user commit checkpoint. (Suggested message: "Add ReportPane skeleton with Glamour rendering.")

---

## Task 4: Wire ReportPane into App

**Intent.** Add the `reportPane` field on `App`, hook `Keys.Report` to instantiate it, route messages and view composition the same way `LogsViewer` is wired, and add a `SetScanStatus` sync line in `dispatchToScanList`.

**Files:**
- Modify: `src/g3tui/internal/ui/app.go`

- [ ] **Step 1: Add the `reportPane *ReportPane` field on `App`**

In `src/g3tui/internal/ui/app.go`, locate the `App` struct (around line 60). Find the existing `logsViewer *LogsViewer` field at line 70 and add `reportPane *ReportPane` immediately below it:

```go
logsViewer *LogsViewer
reportPane *ReportPane
```

- [ ] **Step 2: Add `Keys.Report` handler in the dashboard key-dispatch switch**

In `app.go`, locate the existing `Keys.Logs` handler (around line 186). Add a parallel `Keys.Report` case immediately below it. The handler gates on `isTerminal` for the same reason the footer-hint does — a running scan has no report yet:

```go
case key.Matches(m, Keys.Report):
    sid := a.scanList.SelectedID()
    if sid == "" || !isTerminal(a.scanList.SelectedStatus()) {
        return a, nil
    }
    p := NewReportPane(a.cli, sid, a.scanList.SelectedStatus())
    p.SetSize(a.rightPaneWidth(), a.bodyHeight())
    a.reportPane = &p
    a.prevFocus = a.focus
    return a, p.InitCmd()
```

- [ ] **Step 3: Route report-related messages through `ReportPane` in `App.Update`**

Find the existing `logsViewerChunkMsg, logsViewerTickMsg` case (around line 245) and the `logsViewerClosedMsg` case (around line 253). Add parallel cases for the report pane immediately after them:

```go
case reportFetchedMsg, spinner.TickMsg:
    if a.reportPane == nil {
        return a, nil
    }
    p, cmd := a.reportPane.Update(m)
    a.reportPane = &p
    return a, cmd

case reportPaneClosedMsg:
    a.reportPane = nil
    return a, nil
```

If `spinner` isn't already imported in `app.go`, add `"github.com/charmbracelet/bubbles/spinner"` to the import block.

**Edge case:** `spinner.TickMsg` is routed unconditionally to the report pane. That is fine because the only spinner in the app right now is the report pane's loading spinner — but if a future viewer adds a second spinner, this routing needs to disambiguate. Documented as a known constraint, not a present bug.

- [ ] **Step 4: Forward key events to `ReportPane` when it owns focus**

Find the early-return block around line 133 that forwards messages to `logsViewer` when non-nil:

```go
if a.logsViewer != nil {
    v, cmd := a.logsViewer.Update(m)
    a.logsViewer = &v
    return a, cmd
}
```

Add the parallel block immediately above it (so the report pane gets first claim, mirroring how the wizard/confirm overlays work today):

```go
if a.reportPane != nil {
    p, cmd := a.reportPane.Update(m)
    a.reportPane = &p
    return a, cmd
}
```

- [ ] **Step 5: Handle window resize for the report pane**

Find the existing resize block around line 116 that calls `a.logsViewer.SetSize(...)`. Add the parallel call for the report pane in the same block:

```go
if a.reportPane != nil {
    a.reportPane.SetSize(a.rightPaneWidth(), a.bodyHeight())
}
```

- [ ] **Step 6: Add the report pane to `App.View`'s composition switch**

In `app.go`, locate the `View()` body around line 354 with the `switch` statement that picks the right pane. Find the existing `case a.logsViewer != nil:` branch (around line 373):

```go
case a.logsViewer != nil:
    // Viewer replaces the right pane; scan list stays.
    body = lipgloss.JoinHorizontal(
        lipgloss.Top,
        a.scanList.View(),
        a.logsViewer.View(),
    )
```

Add the parallel branch for the report pane immediately above it:

```go
case a.reportPane != nil:
    body = lipgloss.JoinHorizontal(
        lipgloss.Top,
        a.scanList.View(),
        a.reportPane.View(),
    )
```

- [ ] **Step 7: Sync scan status into the open report pane from `dispatchToScanList`**

Find `dispatchToScanList` around line 322. After the existing `if a.logsViewer != nil { ... SetScanStatus(...) ... }` block (around line 346-350), add the parallel block for the report pane:

```go
if a.reportPane != nil {
    if newStatus := a.scanList.StatusByID(a.reportPane.scanID); newStatus != "" && newStatus != a.reportPane.scanStatus {
        a.reportPane.SetScanStatus(newStatus)
    }
}
```

Note this directly accesses `a.reportPane.scanID` and `a.reportPane.scanStatus` — both are unexported fields on a struct in the same package, mirroring how `dispatchToScanList` accesses `a.logsViewer.scanID` and `a.logsViewer.scanStatus` today.

- [ ] **Step 8: Verify**

Run: `cd src/g3tui && go build ./...`
Expected: success.

Run: `cd src/g3tui && golangci-lint run ./...`
Expected: clean.

STOP — user commit checkpoint. (Suggested message: "Wire ReportPane into App for [R] keybind.")

---

## Task 5: `[S]` Markdown save and `[E]` JSON export in ReportPane

**Intent.** Compose the save-mode `FilePicker` from Task 1 on top of `ReportPane`. `[S]` writes the raw markdown synchronously and shows a success banner. `[E]` runs a background goroutine that drives `GetScanDataList` + `GetScanData` in batches of 20, streams beautified JSON to a temp file, then atomically renames into place. The export is cancelable via `Esc` and shows a spinner overlay during run.

**Files:**
- Modify: `src/g3tui/internal/ui/report.go`

- [ ] **Step 1: Extend `reportState` with `reportSaving` and `reportExporting`**

In `src/g3tui/internal/ui/report.go`, replace the existing `reportState` constants block with:

```go
type reportState int

const (
    reportLoading reportState = iota
    reportLoaded
    reportSaving    // brief; sync write completes before next render in practice
    reportExporting // multi-call data fetch; spinner overlay active
    reportError
)
```

- [ ] **Step 2: Add picker, banner, and export-progress fields to `ReportPane`**

Add the following fields to the `ReportPane` struct in `report.go` (after the existing `spinner` field):

```go
picker *FilePicker // non-nil while save-mode picker is open

banner        string    // transient success/error toast text
bannerStyle   lipgloss.Style
bannerExpires time.Time

exportCtx       context.Context
exportCancel    context.CancelFunc
exportPath      string
exportProgress  struct{ Done, Total int }
```

Add `time` and `context` to the import block at the top of `report.go` if not already present. Also add `"strings"` (used by the export goroutine in Step 5).

- [ ] **Step 3: Handle `[S]` and `[E]` keystrokes in `Update`**

In the `tea.KeyMsg` case of `ReportPane.Update`, add the picker-composition branch at the very top of the switch (it must intercept keystrokes when the picker is open), and add `[S]`/`[E]` handlers alongside the existing scroll/back keys. Replace the existing `tea.KeyMsg` case with:

```go
case tea.KeyMsg:
    // While the picker is open, all keystrokes route to it.
    if p.picker != nil {
        np, cmd := p.picker.Update(m)
        p.picker = &np
        return p, cmd
    }
    // While exporting, only Esc is meaningful (cancel).
    if p.state == reportExporting {
        if key.Matches(m, Keys.Back) {
            if p.exportCancel != nil {
                p.exportCancel()
            }
            return p, nil
        }
        return p, nil
    }
    switch {
    case key.Matches(m, Keys.Back):
        return p, func() tea.Msg { return reportPaneClosedMsg{} }
    case key.Matches(m, Keys.Retry):
        if p.state == reportError {
            p.state = reportLoading
            p.err = nil
            return p, tea.Batch(p.fetchCmd(), p.spinner.Tick)
        }
    case key.Matches(m, Keys.Save):
        if p.state == reportLoaded {
            return p.openSavePicker()
        }
    case key.Matches(m, Keys.Export):
        if p.state == reportLoaded && isTerminal(p.scanStatus) {
            return p.openExportPicker()
        }
    case key.Matches(m, Keys.Up):
        p.viewport.ScrollUp(1)
    case key.Matches(m, Keys.Down):
        p.viewport.ScrollDown(1)
    case key.Matches(m, Keys.PgUp):
        p.viewport.HalfPageUp()
    case key.Matches(m, Keys.PgDn):
        p.viewport.HalfPageDown()
    case key.Matches(m, Keys.GotoTop):
        p.viewport.GotoTop()
    case key.Matches(m, Keys.GotoBottom):
        p.viewport.GotoBottom()
    }
    return p, nil
```

- [ ] **Step 4: Add the picker openers and the picker-message routing**

In the `Update` method, after the `tea.KeyMsg` case, add cases that handle the picker's confirm/cancel messages. Place these between `spinner.TickMsg` and the closing brace of the switch:

```go
case pickerSaveConfirmedMsg:
    if p.picker == nil {
        return p, nil
    }
    path := m.Path
    p.picker = nil
    if p.state == reportLoaded {
        return p.writeMarkdown(path)
    }
    // The [E] flow uses the same picker but completes async — start
    // the export goroutine.
    return p.startExport(path)

case pickerCanceledMsg:
    p.picker = nil
    return p, nil

case client.ReportSaved:
    p.state = reportLoaded
    p.setBanner(BannerSuccess, fmt.Sprintf("Saved to %s", m.Path))
    return p, p.expireBannerCmd()

case client.ReportSaveError:
    p.state = reportLoaded
    p.setBanner(BannerError, fmt.Sprintf("Save failed: %v", m.Err))
    return p, p.expireBannerCmd()

case client.ExportProgress:
    if p.state != reportExporting {
        return p, nil
    }
    p.exportProgress.Done = m.Done
    p.exportProgress.Total = m.Total
    return p, nil

case client.ExportDone:
    p.state = reportLoaded
    p.exportCancel = nil
    p.setBanner(BannerSuccess, fmt.Sprintf("Exported %d objects to %s", m.Count, m.Path))
    return p, p.expireBannerCmd()

case client.ExportError:
    p.state = reportLoaded
    p.exportCancel = nil
    p.setBanner(BannerError, fmt.Sprintf("Export failed: %v", m.Err))
    return p, p.expireBannerCmd()

case bannerExpireMsg:
    if !p.bannerExpires.IsZero() && time.Now().After(p.bannerExpires) {
        p.banner = ""
        p.bannerExpires = time.Time{}
    }
    return p, nil
```

Track that we'll add: `openSavePicker`, `openExportPicker`, `writeMarkdown`, `startExport`, `setBanner`, `expireBannerCmd`, and `bannerExpireMsg` below.

- [ ] **Step 5: Add the helpers and the export goroutine**

At the end of `report.go`, add the helper methods and supporting message type. The export goroutine is the meaty part: temp file in `filepath.Dir(path)`, beautified JSON array streamed in batches of 20, atomic `os.Rename` at the end, full cleanup on any error or cancel:

```go
// bannerExpireMsg fires 5 seconds after a banner is shown to clear it.
type bannerExpireMsg struct{}

func (p ReportPane) openSavePicker() (ReportPane, tea.Cmd) {
    cwd, _ := os.Getwd()
    if cwd == "" {
        cwd = "."
    }
    short := p.scanID
    if len(short) > 8 {
        short = short[:8]
    }
    pk := NewSaveFilePicker(cwd, fmt.Sprintf("%s-report.md", short), "Save report (Markdown)")
    pk.SetSize(p.viewport.Width, p.viewport.Height)
    p.picker = &pk
    return p, nil
}

func (p ReportPane) openExportPicker() (ReportPane, tea.Cmd) {
    cwd, _ := os.Getwd()
    if cwd == "" {
        cwd = "."
    }
    short := p.scanID
    if len(short) > 8 {
        short = short[:8]
    }
    pk := NewSaveFilePicker(cwd, fmt.Sprintf("%s-export.json", short), "Export scan data (JSON)")
    pk.SetSize(p.viewport.Width, p.viewport.Height)
    p.picker = &pk
    return p, nil
}

func (p ReportPane) writeMarkdown(path string) (ReportPane, tea.Cmd) {
    p.state = reportSaving
    md := []byte(p.markdown)
    return p, func() tea.Msg {
        if err := os.WriteFile(path, md, 0o644); err != nil {
            return client.ReportSaveError{Err: err}
        }
        return client.ReportSaved{Path: path}
    }
}

func (p ReportPane) startExport(path string) (ReportPane, tea.Cmd) {
    ctx, cancel := context.WithCancel(context.Background())
    p.exportCtx = ctx
    p.exportCancel = cancel
    p.exportPath = path
    p.exportProgress.Done = 0
    p.exportProgress.Total = 0
    p.state = reportExporting

    cli := p.cli
    sid := p.scanID
    return p, tea.Batch(
        p.spinner.Tick,
        runJSONExportCmd(ctx, cli, sid, path),
    )
}

func (p *ReportPane) setBanner(style lipgloss.Style, text string) {
    p.banner = text
    p.bannerStyle = style
    p.bannerExpires = time.Now().Add(5 * time.Second)
}

func (p ReportPane) expireBannerCmd() tea.Cmd {
    return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpireMsg{} })
}

// runJSONExportCmd drives the two-call export pattern: /scan/datalist
// then batched /scan/data, writing a beautified JSON array to a temp
// file alongside the target and renaming atomically on completion.
//
// v1 limitation: this returns a single tea.Cmd that yields the terminal
// message (ExportDone or ExportError). Mid-run ExportProgress messages
// are NOT posted — Bubble Tea's tea.Cmd is one-shot, and posting
// progress would require either (a) plumbing tea.Program.Send into the
// command factory, or (b) a channel-reading Cmd composition. The
// spinner overlay still ticks visually; the "X / N" counter just
// remains at 0 / 0 throughout the run. Acceptable for v1; if user
// feedback wants a live counter, see the TODO below for the fix.
//
// TODO(g3tui-tier3): wire tea.Program.Send through NewReportPane to
// enable mid-run ExportProgress posts. Adds one constructor parameter
// and a single Send call per batch boundary.
func runJSONExportCmd(ctx context.Context, cli *client.Client, scanID, path string) tea.Cmd {
    return func() tea.Msg {
        ids, err := cli.GetScanDataList(ctx, scanID)
        if err != nil {
            return client.ExportError{Path: path, Err: err}
        }
        if ctx.Err() != nil {
            return client.ExportError{Path: path, Err: ctx.Err()}
        }
        if len(ids) == 0 {
            // Empty scan: write an empty array atomically.
            if err := writeExportFile(path, nil); err != nil {
                return client.ExportError{Path: path, Err: err}
            }
            return client.ExportDone{Path: path, Count: 0}
        }

        // Stream to temp file.
        tmp := path + ".tmp"
        fd, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
        if err != nil {
            return client.ExportError{Path: path, Err: err}
        }
        cleanup := func() {
            _ = fd.Close()
            _ = os.Remove(tmp)
        }

        if _, err := fd.WriteString("[\n"); err != nil {
            cleanup()
            return client.ExportError{Path: path, Err: err}
        }

        const batchSize = 20
        firstWritten := false
        count := 0
        for start := 0; start < len(ids); start += batchSize {
            if ctx.Err() != nil {
                cleanup()
                return client.ExportError{Path: path, Err: ctx.Err()}
            }
            end := start + batchSize
            if end > len(ids) {
                end = len(ids)
            }
            batch := ids[start:end]
            objs, err := cli.GetScanData(ctx, scanID, batch)
            if err != nil {
                cleanup()
                return client.ExportError{Path: path, Err: err}
            }
            for _, obj := range objs {
                jb, err := jsonMarshalIndent(obj)
                if err != nil {
                    cleanup()
                    return client.ExportError{Path: path, Err: err}
                }
                if firstWritten {
                    if _, err := fd.WriteString(",\n"); err != nil {
                        cleanup()
                        return client.ExportError{Path: path, Err: err}
                    }
                }
                if _, err := fd.WriteString("  "); err != nil {
                    cleanup()
                    return client.ExportError{Path: path, Err: err}
                }
                if _, err := fd.Write(jb); err != nil {
                    cleanup()
                    return client.ExportError{Path: path, Err: err}
                }
                firstWritten = true
                count++
            }
        }

        if _, err := fd.WriteString("\n]\n"); err != nil {
            cleanup()
            return client.ExportError{Path: path, Err: err}
        }
        if err := fd.Close(); err != nil {
            _ = os.Remove(tmp)
            return client.ExportError{Path: path, Err: err}
        }
        if err := os.Rename(tmp, path); err != nil {
            _ = os.Remove(tmp)
            return client.ExportError{Path: path, Err: err}
        }
        return client.ExportDone{Path: path, Count: count}
    }
}

// writeExportFile writes the empty-array case atomically. Kept as a
// helper so the empty-scan path mirrors the temp+rename shape.
func writeExportFile(path string, objs []map[string]any) error {
    tmp := path + ".tmp"
    body := []byte("[]\n")
    if len(objs) > 0 {
        var sb strings.Builder
        sb.WriteString("[\n")
        for i, obj := range objs {
            jb, err := jsonMarshalIndent(obj)
            if err != nil {
                return err
            }
            if i > 0 {
                sb.WriteString(",\n")
            }
            sb.WriteString("  ")
            sb.Write(jb)
        }
        sb.WriteString("\n]\n")
        body = []byte(sb.String())
    }
    if err := os.WriteFile(tmp, body, 0o644); err != nil {
        return err
    }
    return os.Rename(tmp, path)
}

// jsonMarshalIndent marshals one data object with two-space indent.
// Two-space matches g3cli export --beautify.
func jsonMarshalIndent(obj map[string]any) ([]byte, error) {
    return jsonMarshalIndentImpl(obj)
}
```

Add the JSON helper at the top of `report.go` with its own import (or inline it where used). Add this to the imports block:

```go
"encoding/json"
"os"
"path/filepath"
"strings"
```

And the helper near the file's bottom:

```go
func jsonMarshalIndentImpl(obj map[string]any) ([]byte, error) {
    return json.MarshalIndent(obj, "  ", "  ")
}
```

(The wrapper `jsonMarshalIndent` exists so a future test could intercept; keep it for now even though it's a thin pass-through.)

**Note on `filepath`:** Step 5 uses `path + ".tmp"` for the temp path, which assumes `path` is in the same directory as the target. `os.Rename` will succeed across the same filesystem; if the user picks a path on a different mount than cwd, the temp ends up alongside the target (since the temp's directory is `filepath.Dir(path)`), which is correct. No code change needed — the `path + ".tmp"` form is already correct because `filepath.Dir(path + ".tmp") == filepath.Dir(path)`.

- [ ] **Step 6: Update `View` to render the picker overlay, banner row, and export spinner**

Replace the existing `View` method with the version below. The picker overlay sits on top of the right pane (lipgloss center placement). The export spinner overlay sits on top of the report body. The banner appears as a single row below the title for either error/success toasts or the caveats warning:

```go
func (p ReportPane) View() string {
    title := AppTitle.Render(p.renderTitle(p.width - 4))

    var body string
    switch p.state {
    case reportLoading:
        body = lipgloss.Place(
            p.viewport.Width, p.viewport.Height,
            lipgloss.Center, lipgloss.Center,
            p.spinner.View()+"  Loading report…",
        )
    case reportError:
        msg := fmt.Sprintf("Failed to load report: %v\n\n[r] retry  [esc] back", p.err)
        body = lipgloss.Place(
            p.viewport.Width, p.viewport.Height,
            lipgloss.Center, lipgloss.Center,
            BannerError.Render(msg),
        )
    case reportLoaded, reportSaving:
        body = p.viewport.View()
    case reportExporting:
        overlay := p.spinner.View() + "  Exporting scan data…"
        if p.exportProgress.Total > 0 {
            overlay = fmt.Sprintf("%s\n    %d / %d objects\n\n    [esc] cancel",
                overlay, p.exportProgress.Done, p.exportProgress.Total)
        } else {
            overlay = overlay + "\n\n    [esc] cancel"
        }
        body = lipgloss.Place(
            p.viewport.Width, p.viewport.Height,
            lipgloss.Center, lipgloss.Center,
            BannerWarn.Render(overlay),
        )
    }

    parts := []string{title, ""}
    if p.banner != "" {
        parts = append(parts, p.bannerStyle.Width(p.viewport.Width).Render(p.banner))
    } else if p.errors != "" {
        first := firstLine(p.errors)
        parts = append(parts, BannerWarn.Width(p.viewport.Width).Render(
            "Report generated with caveats: "+first,
        ))
    }
    parts = append(parts, body)

    rendered := PaneBorderFocused.Width(p.width - 2).Height(p.height - 2).Render(
        lipgloss.JoinVertical(lipgloss.Left, parts...),
    )

    if p.picker != nil {
        return lipgloss.Place(
            p.width, p.height,
            lipgloss.Center, lipgloss.Center,
            p.picker.View(),
        )
    }
    return rendered
}
```

- [ ] **Step 7: Update `SetSize` to also size the picker when present**

Replace the existing `SetSize` method with the version below — it now also propagates size to the picker overlay if open:

```go
func (p *ReportPane) SetSize(w, h int) {
    p.width = w
    p.height = h
    inner := w - 4
    chrome := 2
    titleRow := 1
    spacerRow := 1
    bannerRow := 0
    if p.errors != "" || p.banner != "" {
        bannerRow = 2
    }
    contentHeight := max(1, h-chrome-titleRow-spacerRow-bannerRow)
    p.viewport.Width = inner
    p.viewport.Height = contentHeight
    if p.picker != nil {
        p.picker.SetSize(w, h)
    }
    if p.state == reportLoaded {
        p.renderAndApply()
    }
}
```

- [ ] **Step 8: Update `Help` to advertise `s save` and `e export` when relevant**

Replace `Help`:

```go
func (p ReportPane) Help() []key.Binding {
    if p.state != reportLoaded {
        return []key.Binding{Keys.Back}
    }
    bindings := []key.Binding{Keys.Save}
    if isTerminal(p.scanStatus) {
        bindings = append(bindings, Keys.Export)
    }
    bindings = append(bindings, Keys.Back)
    return bindings
}
```

`Keys.Export` is gated on `isTerminal` for the same reason the export operation is gated — exporting a running scan would race with new objects landing.

- [ ] **Step 9: Verify**

Run: `cd src/g3tui && go build ./...`
Expected: success.

Run: `cd src/g3tui && golangci-lint run ./...`
Expected: clean. The export goroutine is intentionally one shot with no mid-run progress message channel (documented inline). If the linter flags `jsonMarshalIndent` as unnecessary wrapping, leave it — the indirection is for future testability and removing it would force a re-edit later.

STOP — user commit checkpoint. (Suggested message: "Add [S] save and [E] JSON export to ReportPane.")

---

## Task 6: LogsViewer `[S]` integration

**Intent.** Compose the save-mode `FilePicker` onto the existing `LogsViewer`. Save format matches the on-screen rendering (timestamp + tool + stripped body), minus ANSI. Add a `renderForSave` method that re-emits the lines as plain text.

**Files:**
- Modify: `src/g3tui/internal/ui/logsviewer.go`

- [ ] **Step 1: Add picker and banner fields to `LogsViewer`**

In `src/g3tui/internal/ui/logsviewer.go`, add fields to the `LogsViewer` struct (after the existing `wrap bool` field around line 60):

```go
picker        *FilePicker
banner        string
bannerStyle   lipgloss.Style
bannerExpires time.Time
```

- [ ] **Step 2: Add the `renderForSave` method**

Add this method below `applyContent` (around line 277):

```go
// renderForSave returns the viewer's current entries formatted as
// plain text for [S] save. Same line shape as applyContent (timestamp,
// tool, body) but with no Lipgloss styling, no ANSI in the body, no
// hanging-indent line wrapping. Used by the [S] save handler.
func (v LogsViewer) renderForSave() string {
    if len(v.entries) == 0 {
        return ""
    }
    var b strings.Builder
    for i, e := range v.entries {
        if i > 0 {
            b.WriteByte('\n')
        }
        when := time.Unix(e.Timestamp, 0).Format("15:04:05")
        tool := v.toolFor(e.TaskID)
        // Match applyContent's tool-cell width (capped at logsViewerToolCap),
        // end-ellipsis when too wide.
        cell := tool
        width := v.toolWidth
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
        b.WriteString(when)
        b.WriteString(" [")
        b.WriteString(cell)
        b.WriteString("]")
        b.WriteString(strings.Repeat(" ", pad))
        b.WriteString("  ")
        b.WriteString(g3lib.StripAnsi(e.Text))
    }
    return b.String()
}
```

- [ ] **Step 3: Handle `[S]` and picker messages in `Update`**

Find the `tea.KeyMsg` case in `LogsViewer.Update` (around line 150). Insert a picker-routing block at the top of the switch (before any key handlers fire), and add a `Keys.Save` case after the existing `Keys.WrapToggle` case:

```go
case tea.KeyMsg:
    if v.picker != nil {
        np, cmd := v.picker.Update(m)
        v.picker = &np
        return v, cmd
    }
    switch {
    case key.Matches(m, Keys.Back):
        return v, func() tea.Msg { return logsViewerClosedMsg{} }
    case key.Matches(m, Keys.Up):
        v.viewport.ScrollUp(1)
    case key.Matches(m, Keys.Down):
        v.viewport.ScrollDown(1)
    case key.Matches(m, Keys.PgUp):
        v.viewport.HalfPageUp()
    case key.Matches(m, Keys.PgDn):
        v.viewport.HalfPageDown()
    case key.Matches(m, Keys.GotoTop):
        v.viewport.GotoTop()
    case key.Matches(m, Keys.GotoBottom):
        v.viewport.GotoBottom()
    case key.Matches(m, Keys.WrapToggle):
        wasAtBottom := v.viewport.AtBottom()
        v.wrap = !v.wrap
        v.applyContent()
        if wasAtBottom {
            v.viewport.GotoBottom()
        }
    case key.Matches(m, Keys.Save):
        return v.openSavePicker()
    }
    return v, nil
```

Add cases for picker messages and banner expiration immediately after the `tea.KeyMsg` case:

```go
case pickerSaveConfirmedMsg:
    if v.picker == nil {
        return v, nil
    }
    path := m.Path
    v.picker = nil
    return v.writeLogs(path)

case pickerCanceledMsg:
    v.picker = nil
    return v, nil

case logsViewerSavedMsg:
    v.setBanner(BannerSuccess, fmt.Sprintf("Saved to %s", m.Path))
    return v, v.expireBannerCmd()

case logsViewerSaveErrorMsg:
    v.setBanner(BannerError, fmt.Sprintf("Save failed: %v", m.Err))
    return v, v.expireBannerCmd()

case logsViewerBannerExpireMsg:
    if !v.bannerExpires.IsZero() && time.Now().After(v.bannerExpires) {
        v.banner = ""
        v.bannerExpires = time.Time{}
    }
    return v, nil
```

- [ ] **Step 4: Add the helpers and message types**

At the bottom of `logsviewer.go`, add:

```go
// logsViewerSavedMsg / logsViewerSaveErrorMsg / logsViewerBannerExpireMsg
// are local to this file because they are not part of the client
// transport — they are internal UI events emitted by the save handler
// running as a tea.Cmd.
type logsViewerSavedMsg struct{ Path string }
type logsViewerSaveErrorMsg struct{ Err error }
type logsViewerBannerExpireMsg struct{}

func (v LogsViewer) openSavePicker() (LogsViewer, tea.Cmd) {
    cwd, _ := os.Getwd()
    if cwd == "" {
        cwd = "."
    }
    short := v.scanID
    if len(short) > 8 {
        short = short[:8]
    }
    pk := NewSaveFilePicker(cwd, fmt.Sprintf("%s-logs.log", short), "Save scan logs")
    pk.SetSize(v.width, v.height)
    v.picker = &pk
    return v, nil
}

func (v LogsViewer) writeLogs(path string) (LogsViewer, tea.Cmd) {
    body := []byte(v.renderForSave())
    return v, func() tea.Msg {
        if err := os.WriteFile(path, body, 0o644); err != nil {
            return logsViewerSaveErrorMsg{Err: err}
        }
        return logsViewerSavedMsg{Path: path}
    }
}

func (v *LogsViewer) setBanner(style lipgloss.Style, text string) {
    v.banner = text
    v.bannerStyle = style
    v.bannerExpires = time.Now().Add(5 * time.Second)
}

func (v LogsViewer) expireBannerCmd() tea.Cmd {
    return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return logsViewerBannerExpireMsg{} })
}
```

Add `"os"` to the import block at the top of `logsviewer.go`.

- [ ] **Step 5: Update `View` and `Help` for picker overlay and the new banner row**

Replace `View` with:

```go
func (v LogsViewer) View() string {
    title := AppTitle.Render(v.renderTitle(v.width - 4))
    body := v.viewport.View()

    parts := []string{title, ""}
    if v.banner != "" {
        parts = append(parts, v.bannerStyle.Width(v.width-4).Render(v.banner))
    }
    parts = append(parts, body)

    rendered := PaneBorderFocused.Width(v.width - 2).Height(v.height - 2).Render(
        lipgloss.JoinVertical(lipgloss.Left, parts...),
    )

    if v.picker != nil {
        return lipgloss.Place(
            v.width, v.height,
            lipgloss.Center, lipgloss.Center,
            v.picker.View(),
        )
    }
    return rendered
}
```

Update `Help` to include `Keys.Save`:

```go
func (v LogsViewer) Help() []key.Binding {
    return []key.Binding{Keys.Save, Keys.GotoTop, Keys.GotoBottom, Keys.WrapToggle, Keys.Back}
}
```

- [ ] **Step 6: Verify**

Run: `cd src/g3tui && go build ./...`
Expected: success.

Run: `cd src/g3tui && golangci-lint run ./...`
Expected: clean.

STOP — user commit checkpoint. (Suggested message: "Add [S] save to LogsViewer.")

---

## Task 7: README

**Intent.** Write `src/g3tui/README.md` documenting env vars, build/install, the six workflows including the shipped `[S]`/`[E]`, custom scan types, and pointers to the design docs. Written last so it documents finished behavior.

**Files:**
- Create: `src/g3tui/README.md`

- [ ] **Step 1: Write `src/g3tui/README.md`**

Create `src/g3tui/README.md` with the following content. Adjust wording lightly if you have a stylistic preference; the structure should match this outline.

````markdown
# g3tui — Interactive Terminal UI for Golismero3

`g3tui` is the interactive companion to `g3cli`. It keeps the operator inside one persistent session for the six common workflows — create scan, monitor live, view logs, view report, cancel, delete — while `g3cli` continues to cover scripting and one-off automation. Both talk to the same `g3api` and share the same `.env`.

## What is g3tui?

A single static Go binary. Three internal packages — `client/` (HTTP and WebSocket), `pipelines/` (embedded and user-supplied scan types), `ui/` (Bubble Tea models). No persistent local state; the server is the source of truth for everything.

`g3tui` exists alongside `g3cli`, not in place of it:

- Reach for `g3cli` when you want to script, pipe JSON, or run one-off commands.
- Reach for `g3tui` when you want to watch a scan run, drill into a task's logs, or read a finished report.

## Building and installing

From the repository root:

```bash
make bin        # builds bin/g3tui (along with the rest)
make install    # symlinks /usr/bin/g3tui (run with sudo)
```

To build only `g3tui`:

```bash
cd src && make ../bin/g3tui
```

`g3tui` follows the rest of the project's Go version (currently 1.26.2, set in `src/g3tui/go.mod`).

## Configuration

`g3tui` reads `.env` on startup via `g3lib.LoadDotEnvFile()`, so the same `.env` that works for `g3cli` works for `g3tui` with no additional setup.

**Required:**

| Variable | Purpose |
|---|---|
| `G3_API_BASEURL` | HTTP base URL of `g3api`, e.g. `https://g3.lab/api`. |
| `G3_API_WSURL` | WebSocket URL of `g3api`, e.g. `wss://g3.lab/ws`. |
| `G3_API_TOKEN` | Bearer token. Internal-only auth per the project's architectural direction. |

**Optional:**

| Variable | Purpose |
|---|---|
| `G3_PIPELINES_DIR` | Override for the user-supplied scan-types directory (default `~/.config/g3tui/pipelines/`). |
| `G3_CMD_LOG_LEVEL` | Log verbosity, matches `g3cli`. |

The binary hard-fails at launch with a clear message if any required variable is missing.

## Dashboard tour

```
┌─ g3tui ─────────────────────────────────  ● connected · srv=g3.lab ─┐
│ Scans         │ Tasks                                              │
│               │  ID  STATE  TOOL  TIME  LAST SEEN  WORKER          │
│ ▸ <scan-1>    │  …                                                 │
│   RUNNING  42 │                                                    │
│   <scan-2>    │                                                    │
│   FINISHED 100├────────────────────────────────────────────────────│
│   …           │ Logs · <task-id> · <line-count>                    │
│               │   14:42:03  Host is up (0.00033s latency).         │
│               │   14:42:04  PORT    STATE SERVICE                  │
├───────────────┴────────────────────────────────────────────────────┤
│ tab cycle · n new · l logs · r report · c cancel · d delete · q   │
└────────────────────────────────────────────────────────────────────┘
```

Three panels with `Tab`/`Shift-Tab` cycling: **Scans** (live via WebSocket `scanprogress`, polling fallback at 3s), **Tasks** (per-task table for the selected scan, 2s poll while focused, server-side reconstruction for terminated scans), **Logs** (live inline preview bound to the focused task, 2s poll, 250ms debounce on cursor changes).

The footer always shows the keys that apply to the current focus and selection. The connection dot in the header is green when WebSocket is connected, yellow during reconnect (polling fallback active), red when both are down.

If the terminal is smaller than 60×14, the dashboard short-circuits to a "terminal too small" warning. Resize and the UI re-renders.

## The six workflows

### Create scan (`n`)

Opens the wizard overlay. Fill in targets one per line, add imports (tool-first batch picker), choose sequential or parallel mode, pick a scan type — embedded (`network`, `web`) or one of your own. `Custom…` accepts pasted pipeline-only content (`target`, `mode`, and `import` are added for you by the wizard). Submit uploads imports in parallel (cap 4), POSTs `/scan/start`, and the new scan appears in the left panel via the WebSocket push.

### Monitor live (default)

The dashboard updates itself. The Scans panel reflects each `scanprogress` push; the Tasks panel polls `/scan/tasks/status` for the selected scan; the Logs preview polls `/scan/logs` for the task under the Tasks cursor. Everything stops polling when the scan reaches a terminal state.

### View logs (`l`)

Opens the full-screen logs viewer for the selected scan. Lines are chronologically interleaved across tasks with per-line tool attribution parsed from `[g3:dispatch]` markers. Scroll with `↑↓`, `pgup`/`pgdn`, `g`/`G`. Press `w` to toggle word-wrap. Press `s` to save the displayed buffer to a file (plain text, ANSI stripped, default filename `<scanid>-logs.log`). Press `esc` to return.

### View report (`r`)

Opens the full-screen Markdown report viewer for the selected scan (terminal scans only). Fetches `/scan/report` once on open, renders via Glamour (auto light/dark). Press `s` to save the raw Markdown verbatim (default filename `<scanid>-report.md`). Press `e` to export the underlying scan data as a beautified JSON array (matches `g3cli export --beautify`); this runs as a cancelable background operation with a temp-and-rename for atomicity. Press `esc` to return.

If the server reports parse errors during report generation, a yellow caveats banner appears at the top of the pane. The full error blob is dropped; the first line is shown.

### Cancel scan (`c`)

Confirms with an overlay, sends `/scan/stop`. The scan transitions to `CANCELED`; the dashboard updates via the next `scanprogress` push.

### Delete scan (`d`)

Confirms with an overlay, sends `/scan/stop` followed by `/scan/delete`. Mirrors `g3cli rm`.

## Custom scan types

`g3tui` ships with two embedded scan types — `network` and `web` — packed via `//go:embed` from `internal/pipelines/*.pipeline`. To add your own, drop a `*.pipeline` file into:

- `$G3_PIPELINES_DIR` (if set), or
- `~/.config/g3tui/pipelines/` (default).

The file's basename (without `.pipeline`) becomes the scan-type name in the wizard. Content is pipeline-only — `tool | tool | tool` lines, plus comments — with no `target`, `mode`, or `import` lines. The wizard adds those at submit time.

Invalid files (broken pipeline syntax) are logged and skipped at startup; they do not prevent the TUI from launching. User-supplied files with the same basename as an embedded one override the embedded version.

## Save paths and file safety

Save destinations are picked through a small file browser with a filename field at the bottom. Type the filename, or `↑↓` to a file you want to overwrite and the filename auto-fills. `Enter` confirms — if the file already exists, you'll be prompted to confirm with `y`/`n`.

JSON export writes to a temporary file in the destination directory and atomically renames into place on success. A cancel (`esc`) or error removes the temp file cleanly — you never get a half-written JSON file at the target path.

Save paths do not perform shell-style expansion: `~` and `$HOME` are taken literally. Use absolute paths or relative paths from the directory shown at the top of the picker.

## Coexisting with g3cli

| Task | g3cli | g3tui |
|---|---|---|
| One-off scan from a script | `g3cli scan -i my.script` | wizard's `Custom…` |
| Watch a scan that's running | (re-invoke periodically) | dashboard (default) |
| Read logs for one task | `g3cli logs <scanid> <taskid>` | Tasks panel + inline Logs preview |
| Read logs for whole scan | `g3cli logs <scanid>` | `l` (full-screen viewer) |
| Get the Markdown report | `g3cli report <scanid> -o report.md` | `r`, then `s` to save |
| Get the raw JSON data | `g3cli export <scanid> -o data.json` | `r`, then `e` to export |
| Pipe to another tool | `g3cli export <scanid> -o -` | use g3cli |
| Cancel a scan | `g3cli cancel <scanid>` | `c` |
| Delete a scan | `g3cli rm <scanid>` | `d` |

Both speak to the same `g3api` and see the same scans.

## Design docs

The design rationale behind each iteration of `g3tui` lives in [`../../docs/plans/`](../../docs/plans/):

- [`2026-05-06-g3tui-design.md`](../../docs/plans/2026-05-06-g3tui-design.md) — original three-tier design.
- [`2026-05-08-g3tui-layout-redesign-design.md`](../../docs/plans/2026-05-08-g3tui-layout-redesign-design.md) — three-panel layout, responsive columns, terminated-scan reconstruction.
- [`2026-05-08-g3tui-logs-design.md`](../../docs/plans/2026-05-08-g3tui-logs-design.md) — inline logs panel and full-screen scan-level viewer.
- [`2026-05-11-g3tui-tier3-completion-design.md`](../../docs/plans/2026-05-11-g3tui-tier3-completion-design.md) — report viewer, save-mode FilePicker, JSON export.
````

- [ ] **Step 2: Verify**

Run: `ls -la /home/crapula/code/g3/src/g3tui/README.md`
Expected: file exists, non-empty.

Run: `cd src/g3tui && go build ./...`
Expected: success (README is not a Go file; included here only to confirm the tree still builds).

Run: `cd src/g3tui && golangci-lint run ./...`
Expected: clean.

STOP — user commit checkpoint. (Suggested message: "Add g3tui README.")

---

## Post-implementation refinements

User testing of the shipped binary surfaced four follow-on changes. Each was applied as a distinct edit cycle after Task 7 with the same agent-side verification scope (lint + build).

### Refinement A — Drop in-flight export progress; keep simple spinner

**Files:** `src/g3tui/internal/ui/report.go`, `src/g3tui/internal/client/messages.go`

The user observed the JSON export against real scans was effectively instantaneous — the "X / N objects" counter never had time to render a meaningful intermediate state. The infrastructure to support it (a `client.ExportProgress` message type, an `exportProgress` field on `ReportPane`, the `client.ExportProgress` case in `Update`, and the deferred `TODO(g3tui-tier3)` for plumbing `tea.Program.Send`) added complexity that v1 doesn't need.

Removed:
- `client.ExportProgress` message type from `messages.go`.
- `exportProgress struct{ Done, Total int }` and `exportPath string` fields from `ReportPane`.
- The `client.ExportProgress` case from `ReportPane.Update`.
- The conditional "X / N objects" branch in the exporting overlay; now a single-line "Exporting scan data… [esc] cancel" overlay above the spinner.
- The `TODO(g3tui-tier3)` comment block in `runJSONExportCmd`; the comment now describes the cancelable-temp+rename behavior in 4 lines.

Kept: spinner animation, cancelable goroutine via `[Esc]`, atomic temp+rename, `client.ExportDone`/`client.ExportError` envelopes (still useful as terminal messages).

### Refinement B — Full-screen modals for Report and Logs viewers

**Files:** `src/g3tui/internal/ui/app.go`

The user noted the scan list column rendered alongside both viewers was non-interactive while an overlay was active — purely decorative. Converted both viewers to full-screen modals.

Changes:
- `tea.WindowSizeMsg` handler: `SetSize` calls for `reportPane` and `logsViewer` now use `a.width` instead of `a.rightPaneWidth()`.
- `Keys.Logs` and `Keys.Report` handlers: same change at viewer-construction time.
- `View()` composition switch: replaced `lipgloss.JoinHorizontal(scanList.View(), pane.View())` with `body = pane.View()` for both viewer cases.

Side effect: the prior bug where the underlying ScanList rendered with `PaneBorderFocused` (blue) while a viewer was active is automatically resolved — the ScanList isn't rendered at all during overlay display.

### Bonus fix — Global Quit (`q`) escapes from inside viewers

**File:** `src/g3tui/internal/ui/app.go`

Reported during Refinement B testing: pressing `q` while the Report or Logs viewer was open did nothing. Root cause: the `tea.KeyMsg` modal forward block at the top of `App.Update` unconditionally forwards every key to the active overlay. Viewers have no `Keys.Quit` handler, so the keystroke is silently consumed.

Fix: added an early-exit guard at the very top of the `tea.KeyMsg` case. When `Keys.Quit` is pressed AND no text-accepting overlay is active (wizard always counts; viewers count only when their `picker` is non-nil), return `tea.Quit` directly. Otherwise the existing modal forward logic runs unchanged.

The "text-accepting" check correctly preserves the wizard's ability to type `q` in textareas/inputs, and preserves the picker's ability to type `q` in a filename.

### Refinement C — Two-panel picker with Tab navigation

**File:** `src/g3tui/internal/ui/picker.go`

The user identified the original save-mode picker as a clear design issue. Three concrete problems:

1. `Keys.Up`/`Keys.Down`/`Keys.Left`/`Keys.Right` include the vi-style aliases `k`/`j`/`h`/`l`. Typing those letters in a filename triggered list navigation instead of editing the textinput.
2. `syncFilenameFromCursor` overwrote the textinput whenever `↑↓` landed on a file. A user who had typed a fresh filename and then accidentally hit an arrow key lost what they'd typed.
3. No clear way to "select" the textinput as the active surface. Two visual cursors (list `▸` and textinput cursor) confused which was active.

Replaced the save-mode interaction model with two distinct focus surfaces (`saveFocusList`, `saveFocusInput`) cycled via `Tab`/`Shift-Tab`:

| Focus | Behavior |
|---|---|
| **Input** (default on open) | All keys edit the textinput. `Tab` switches to list. `Enter` saves using textinput value (overwrite confirm if exists). `Esc` cancels. |
| **List** | Arrow `↑`/`↓` (no j/k) navigates rows. `Enter` on directory descends + clears filter. `Enter` on file saves using that file's path (always triggers overwrite confirm). `Tab` switches to input. Printable keystrokes append to a case-insensitive substring filter that re-narrows the listing. `Backspace` shrinks filter. `Esc` clears filter if active, else cancels. |
| **Confirming** | `y` confirms; `n`/`Esc` returns to picking with prior focus. |

Visual: each surface renders as a sub-box inside the picker; the focused one uses `PaneBorderFocused` (purple), the unfocused uses `PaneBorder` (gray) — same idiom as the three-panel dashboard. Filter shows inline in the Files title (e.g., `Files / "rep"`) when active.

Implementation details:
- New `saveFocus` enum and constants `saveFocusInput` (zero value = default) / `saveFocusList`.
- New `FilePicker` fields: `focus saveFocus`, `filter string`, `pendingSavePath string`.
- New `attemptSavePath(path string)` helper replacing the old `attemptSave()`. Takes an explicit path so list-focus Enter (file's path) and input-focus Enter (resolved textinput) share one code path.
- `saveConfirmCmd` reads the pending path from `pendingSavePath` (set when `confirming` was entered) instead of recomputing from the textinput.
- `refresh()` applies the filter when `mode == PickerSave && filter != ""`. The `..` entry is always retained.
- New `isPrintableFilterRune(s string)` helper distinguishes single-printable-character keystrokes from named keys (`shift+down`, `f1`, etc.).
- Removed `syncFilenameFromCursor` (no longer used).

Open-mode behavior (used by the wizard's imports flow) is unchanged — the redesign is gated on `mode == PickerSave`.

picker.go: 411 → 357 lines (the more disciplined save-mode branch is leaner than the previous overloaded one).

### Refinement D — Detect terminal background at startup (fix Glamour OSC 11 leak)

**Files:** `src/g3tui/main.go`, `src/g3tui/internal/ui/app.go`, `src/g3tui/internal/ui/report.go`, `src/g3tui/go.mod`

The user tested the redesigned picker and reported the filename textinput accumulating garbage like `]11;rgb:0c0c/0cc/0c0c\` interleaved with their typed input. The output doubled on a window resize.

Diagnosis: this is an OSC 11 "query background color" terminal response that Glamour's `WithAutoStyle()` triggered. Glamour calls `termenv.HasDarkBackground()` which writes `ESC]11;?ESC\` to stdout and blocks on a stdin read. On Windows Terminal+WSL the response arrives asynchronously, AFTER the read times out. By that time Bubble Tea has taken over stdin and the response is dispatched as keystrokes to the focused component — the picker's filename textinput.

Fix: detect the background ONCE in `main.go` BEFORE `tea.Program.Run()` takes over stdin, cache the result as a style name string ("dark" or "light"), and pass it through `ui.Config` → `App.cfg` → `NewReportPane(...)` → `ReportPane.glamourStyle`. `renderAndApply` now uses `glamour.WithStylePath(p.glamourStyle)` instead of `glamour.WithAutoStyle()`. Glamour never probes during the event loop.

Resize handling is unaffected: `renderAndApply` still constructs a fresh renderer with `WithWordWrap(currentWidth)` on every resize. Only the style detection moved off the dynamic path.

Concrete changes:
- `main.go`: imported `github.com/muesli/termenv`; added a probe block (`termenv.NewOutput(os.Stdout).HasDarkBackground()`) before `context.WithCancel`; stored result as `"dark"`/`"light"` string; passed via the new `GlamourStyle` field of `ui.Config`.
- `app.go`: added `GlamourStyle string` field to `Config`; passed `a.cfg.GlamourStyle` as the fourth argument to `NewReportPane`.
- `report.go`: added `glamourStyle string` field to `ReportPane`; constructor signature changed to `NewReportPane(cli, scanID, scanStatus, glamourStyle)` with a fallback to `"dark"` on empty string; `renderAndApply` replaced `glamour.WithAutoStyle()` with `glamour.WithStylePath(p.glamourStyle)`.
- `go.mod`: `github.com/muesli/termenv` promoted from indirect to direct dependency.

Conceptual takeaway: terminal capabilities split into static (color depth, supports-OSC-8, dark/light background) and dynamic (size, focus state). Static properties get detected once and cached; dynamic properties are re-queried per frame. The original `WithAutoStyle` mistakenly put background on the dynamic path. The fix is architectural — moving background to where it belongs — not a workaround.

### Refinement E — Picker too-small guard + bounded list height

**File:** `src/g3tui/internal/ui/picker.go`

The user reported that on a smaller terminal, the picker's top (title, `..` entry) was cut off — the picker's natural rendered height exceeded the terminal height, and `lipgloss.Place` pushed the top off-screen rather than scaling down.

Diagnosis: the save-mode picker had a hardcoded `const visible = 10` for file list entries. Combined with the outer orange box's title/path/spacers, the Files sub-box's border+title, the Filename sub-box's border+title+content, and the footer, the picker's natural height was ~22-26 rows. Smaller terminals overflow.

Fix:

1. **Too-small guard** in `View()`'s save-mode branch: when `p.width < 60 || p.height < 20`, return `BannerWarn.Render("⚠  terminal too small for save picker")` directly, bypassing the outer orange box. Mirrors the dashboard's existing 60×14 minimum-size guard.

2. **Bounded `visible`** in `renderSave`: replaced `const visible = 10` with a dynamic computation `visible := p.height - 17` (rough chrome row count), capped at 10 and floored at 3. The 3-row floor is defensive — the too-small guard would have already fired below the threshold; this just ensures the value is never silly.

Effect: on a 22-row terminal the file list shows 5 entries instead of 10; the picker fits within the terminal; `lipgloss.Place` can center it properly. On a 30-row terminal the cap kicks in at 10 entries (existing behavior). Below 20 rows the user sees a clear warning rather than a broken layout.

The picker thresholds (60×20) are higher than the dashboard's (60×14) because the save-mode picker has more internal chrome (two nested sub-boxes vs the dashboard's flat panels).

### Refinement F — `[E]` export writes JSON, not Markdown (intent flag)

**File:** `src/g3tui/internal/ui/report.go`

The user tested `[E]` and got a `.json` file containing the Markdown report. Root cause: the `pickerSaveConfirmedMsg` handler dispatched based on `p.state == reportLoaded` to choose between `writeMarkdown` and `startExport`. But the picker can only be opened FROM `reportLoaded`, and state doesn't transition until inside `writeMarkdown` or `startExport`. So the condition was always true at confirm time, and `startExport` was unreachable — both `[S]` and `[E]` flowed into `writeMarkdown`. The filename suffix from `openExportPicker` (`.json`) was preserved, but the bytes written were the Markdown report.

Fix: replaced the state-based dispatch with an explicit intent flag.

- Added `exportPending bool` field to `ReportPane`.
- `openExportPicker` sets `p.exportPending = true` before constructing the picker.
- `openSavePicker` sets `p.exportPending = false` (defensive — clears any leftover state from a canceled export).
- `pickerSaveConfirmedMsg` checks `p.exportPending`: when true, clears the flag and calls `startExport`; otherwise calls `writeMarkdown`.
- `pickerCanceledMsg` clears the flag so a canceled export doesn't bleed intent into a subsequent save.

Lesson: this is a state-machine bug both reviewers missed because each reviewed an individual path (writeMarkdown OK; startExport OK) without asking the meta-question "can both branches actually fire?" The original spec conflated "where am I now" (state) with "what was I about to do" (intent) — two different concepts that need separate variables. Behavioral testing (the user actually running `[E]` and opening the produced file) caught what neither static review did.

## Deferred follow-ups

These were surfaced during behavioral testing of the Tier 3 work but explicitly deferred — they require additional research or live outside the Tier 3 scope.

### Markdown image placeholders in Glamour-rendered reports

The user added pie-chart alt text at the report-generation layer (commit `cbc8480`, touches `i18n/en.json`). Confirmed afterwards that Glamour still does not produce a visible placeholder in the rendered output even when alt text is present in the source Markdown — the image element seems to be silently dropped or rendered without the alt text being preserved.

Investigation needed before a fix can be specified:

- Does Glamour's renderer support image element rendering at all in its current version, or does it strip them?
- If it strips them, can a Glamour `StyleConfig` override the `Image` rule to render alt text? Or is preprocessing the Markdown (replacing `![alt](url)` with `[Image: alt — url]` text before passing to `glamour.Render`) the simpler path?
- The server's report generator currently embeds an image; should it be changed to emit a text fallback alongside the image for terminal renderers, controlled by a request flag?

Not blocking. The report still renders correctly otherwise; just the image is invisible.

### Hyperlink behavior (OSC 8) in Glamour-rendered reports

User observed during testing: some hyperlinks in rendered reports show in custom styling, others render as raw `[text](url)` Markdown source — but strangely *are* clickable in the latter form. The first form's clickability is unclear.

Investigation needed before a fix can be specified:

- Why does Glamour render some links one way and others another? Is it a function of the link target (relative vs absolute, scheme), the surrounding context (heading vs paragraph vs list item), or a bug in the current Glamour version pinned in `go.mod`?
- For the cases that render as raw `[text](url)` — what's making them clickable? Modern terminals (Windows Terminal, iTerm2) auto-detect URLs in plain text and make them clickable; that explains the raw-form behavior. The custom-styled form must be emitting OSC 8 or be relying on auto-detection of the styled text — needs tracing.
- Should we standardize on Glamour emitting OSC 8 for all links, or rely on terminal auto-detection of URLs? OSC 8 is more reliable cross-terminal but Glamour's defaults don't emit it.

Not blocking. Links are usable today; the inconsistency is cosmetic.
