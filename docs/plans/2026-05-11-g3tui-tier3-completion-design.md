# g3tui Tier 3 Completion — Report Viewer, Save-mode FilePicker, README

**Status:** Design approved 2026-05-11. Implementation plan: [`2026-05-11-g3tui-tier3-completion-implementation.md`](2026-05-11-g3tui-tier3-completion-implementation.md) (to follow).

**Scope:** Close out the original Tier 3 of [`2026-05-06-g3tui-implementation.md`](2026-05-06-g3tui-implementation.md). The logs viewer half of Tier 3 shipped via the 2026-05-08 split; this design covers the remaining pieces: the Markdown report viewer with Glamour rendering, a save-mode extension to the existing `FilePicker` that unblocks both `[S]` flows, a JSON export action `[E]` on the report viewer, the `[S]` integration in the existing `LogsViewer`, and the subcomponent README.

**Predecessors:**
- [`2026-05-06-g3tui-design.md`](2026-05-06-g3tui-design.md) — original g3tui design; specified the report viewer and per-task save-to-file at a high level.
- [`2026-05-06-g3tui-implementation.md`](2026-05-06-g3tui-implementation.md) — master tier roadmap; Tier 3 was outlined only.
- [`2026-05-08-g3tui-layout-redesign-design.md`](2026-05-08-g3tui-layout-redesign-design.md) — three-panel dashboard and column model that the report viewer overlays.
- [`2026-05-08-g3tui-logs-design.md`](2026-05-08-g3tui-logs-design.md) — the full-screen `LogsViewer` composition pattern this design mirrors; deferred `[S]` to "its own work that also unblocks the Report viewer's `[S]`" — that work is this design.

This document supersedes the **Report viewer** section of the 2026-05-06 design (adds `[E]` JSON export, drops the per-format dropdown idea in favor of two distinct keybinds).

---

## Problem statement

Three pieces of Tier 3 still ship as placeholders or are missing entirely:

1. **`[R]` keybinding** in `App.Update` shows a "coming soon" banner. There is no `ReportPane` model.
2. **`[S]` keybinding** in `LogsViewer` was deferred in the 2026-05-08 logs work because the existing `FilePicker` is multi-select-only — no save-mode, no filename textinput, no overwrite confirmation. Saving from logs and report both block on the same missing infrastructure.
3. **`src/g3tui/README.md`** does not exist. Operators discover the binary's capabilities by running it.

A fourth concern surfaced during scope review: raw scan data is downloadable via `g3cli export` (multi-call `/scan/datalist` + `/scan/data` with batch size 20), but there is no in-TUI way to get JSON data after reading a report. The natural place for that is a sibling to `[S]` on the report viewer.

## Goals and non-goals

**Goals**

- Stand up a working `ReportPane` that fetches `/scan/report` once on open, renders the returned Markdown via Glamour with `auto` style, surfaces server-side parse errors via a yellow caveats banner, and supports scrolling.
- Extend `FilePicker` with a save-mode that keeps directory navigation, replaces multi-select with a single filename textinput, and handles file-exists overwrite confirmation inline (no nested overlays).
- Add `[S]` to the report viewer (save raw Markdown verbatim) and to `LogsViewer` (save the displayed scan-level log buffer in plain text).
- Add `[E]` to the report viewer (export the scan's raw data objects as a beautified JSON array, matching `g3cli export` semantics, with cancelability and atomic write).
- Ship `src/g3tui/README.md` covering env vars, build/install, the six workflows, and pipelines-directory overrides.

**Non-goals**

- **Report formats beyond Markdown and JSON.** PDF, HTML, Obsidian-flavored Markdown remain future work.
- **Streaming JSON export to a pipe.** `g3cli export -o -` covers that case.
- **Tilde or `$VAR` expansion in save paths.** No shell-style expansion in the textinput.
- **Filename collision auto-suffix.** Overwrite-confirm only; the user picks the disambiguation.
- **Background saves with notification.** Saves are modal; the user waits.
- **Per-task save from the inline `LogsPanel`.** Save lives only on the full-screen viewer.
- **Save history / "repeat last save."** Each save starts fresh.
- **Mouse support.** Keyboard-only per existing convention.
- **A `?` help overlay.** Footer hints remain the only on-screen documentation surface.

## Architecture

Four units, each minimal:

1. **FilePicker save-mode** — additive extension to the existing picker.
2. **ReportPane** — new component, full-screen overlay paralleling `LogsViewer`.
3. **LogsViewer `[S]` integration** — composition wiring, no new state.
4. **README** — written last, after behavior is final.

### FilePicker save-mode

The existing `FilePicker` in `src/g3tui/internal/ui/picker.go` is 213 lines and multi-select-only. Save-mode is added as an opt-in mode flag, sharing all the directory-navigation code.

```go
type PickerMode int

const (
    PickerOpen PickerMode = iota // existing multi-select behavior
    PickerSave                    // new single-target behavior
)

type FilePicker struct {
    // ... existing fields ...
    mode     PickerMode
    filename textinput.Model // populated only when mode == PickerSave
    title    string          // configurable header text
    confirming bool          // overwrite-confirm sub-state
}

func NewFilePicker(initialDir string) FilePicker        // unchanged signature
func NewSaveFilePicker(initialDir, defaultFilename, title string) FilePicker
```

#### Save-mode interaction model

| Key | Behavior |
|---|---|
| `↑` `↓` | Move list cursor. If cursor lands on a file (not directory), sync `filename` textinput value to that filename. |
| Letters / digits / punctuation | Edit textinput. List cursor stays put. |
| `Enter` on directory | Descend into directory. Textinput untouched. |
| `Enter` elsewhere | Confirm. If the resolved path exists, enter `confirming` state. Otherwise emit `pickerSaveConfirmedMsg{Path}`. |
| `y` while `confirming` | Confirm overwrite; emit `pickerSaveConfirmedMsg{Path}`. |
| `n` or `Esc` while `confirming` | Return to `picking` state; do not save. |
| `Esc` | Cancel. Emit `pickerCanceledMsg`. |

`y`/`n` are only meaningful inside the picker's `confirming` substate. The picker absorbs all keystrokes while it owns focus, so the global `n` (new scan) shortcut cannot fire from within a picker. This is the same routing pattern the wizard uses to absorb letters that would otherwise be hotkeys.

No `←` / `→` shortcuts in save mode — those keys belong to textinput cursor movement. The `..` entry at the top of every directory listing covers "go to parent."

#### Path resolution

```go
value := picker.filename.Value()
if filepath.IsAbs(value) {
    path = value
} else {
    path = filepath.Join(picker.dir, value)
}
```

No tilde expansion; no environment-variable expansion. A literal `~` becomes a directory named `~` (documented in README).

#### Overwrite confirmation owned by the picker

When `Enter` is pressed on a non-directory and the resolved path exists (`os.Stat` returns no error), the picker enters `confirming` state. The footer line is replaced by an inline prompt:

```
[!] report-old.md exists. Overwrite? [y/n]
```

No nested `Confirm` overlay. The selection isn't complete until overwrite is resolved, and bouncing through a separate component would leave the picker visually stale during the prompt.

#### Result messages

```go
type pickerSaveConfirmedMsg struct {
    Path string // absolute, fully resolved
}

type pickerCanceledMsg struct{} // existing; reused for save cancel
```

Distinct from `pickerConfirmedMsg{Paths []string}` (open mode). Reusing the open-mode message was considered and rejected — the two call shapes are disjoint, and a typed message keeps each call site's intent obvious.

#### View layout

```
┌─ Save report (Markdown) ──────────────────────────┐
│ /home/crapula/code/g3                             │
│                                                   │
│    ..                                             │
│    docs/                                          │
│  ▸ src/                                           │
│    samples/                                       │
│    report-old.md                                  │
│                                                   │
│  Filename: report-7d2a-3f1b.md_                   │
│                                                   │
│  [↑↓] nav  [enter] save / open dir  [esc] cancel  │
└───────────────────────────────────────────────────┘
```

Same outer box style as open-mode. The textinput row sits between the listing and the footer; the `[x]` selection markers from open-mode are absent (no multi-select state to display).

### ReportPane

New file `src/g3tui/internal/ui/report.go`. Full-screen overlay paralleling `LogsViewer` — replaces the right pane while the 44-column scan list stays.

#### State machine

```go
type reportState int

const (
    reportLoading reportState = iota
    reportLoaded
    reportSaving    // brief, sync write
    reportExporting // multi-call data fetch, long-running
    reportError
)

type ReportPane struct {
    scanID     string
    scanStatus string
    width, height int

    state    reportState
    markdown string         // raw markdown from server
    rendered string         // glamour output, cached, refreshed on resize
    errors   string         // server's parse-error blob, optional
    err      error          // network/decode error → state == reportError

    viewport viewport.Model
    picker   *FilePicker    // non-nil while picker is open

    exportCtxCancel context.CancelFunc // for [E] cancellation
    exportProgress  struct{ Done, Total int }
}
```

#### Lifecycle

| Event | Behavior |
|---|---|
| `[R]` from dashboard, scan terminal | Open `ReportPane`, `state = reportLoading`, fire one `getReportCmd(scanID)`. |
| `[R]` on non-terminal scan | No-op. Footer hint stays hidden when scan is non-terminal (gating identical to the logs work). |
| `reportLoadedMsg{Markdown, Errors}` | Glamour-render once into `rendered`, push to viewport, `state = reportLoaded`. |
| `reportErrorMsg{Err}` | `state = reportError`; centered error box with `[r] retry  [esc] back`. |
| Window resize | Re-render through Glamour at the new width; refresh viewport. |
| `[S]` (loaded) | Open save-mode picker; on `pickerSaveConfirmedMsg`, sync `os.WriteFile` with the raw markdown. |
| `[E]` (loaded) | Open save-mode picker; on `pickerSaveConfirmedMsg`, start JSON export goroutine; `state = reportExporting`. |
| `exportProgressMsg{Done, Total}` | Update spinner overlay counters. |
| `exportDoneMsg{Path}` | `state = reportLoaded`; banner `Exported <N> objects to <path>`. |
| `exportErrorMsg{Err}` | `state = reportLoaded`; banner with error; temp file cleaned up. |
| `[Esc]` during exporting | Call `exportCtxCancel()`; goroutine returns at next batch boundary; temp file removed; banner `Export canceled`. |
| `[Esc]` (loaded) | Close pane, restore previous focus. |

`SetScanStatus` is mirrored from `LogsViewer` so the pane's title stays in sync with scan-state transitions visible elsewhere. The status doesn't gate any polling (the report viewer doesn't poll), but the `· <status>` segment in the title should reflect reality if a paranoid double-cancel happens while a stale report is open.

#### Glamour integration

```go
renderer, _ := glamour.NewTermRenderer(
    glamour.WithAutoStyle(),
    glamour.WithWordWrap(p.viewport.Width),
)
rendered, _ := renderer.Render(p.markdown)
```

`auto` style auto-selects light/dark by terminal background, matching the 2026-05-06 spec. Width changes trigger a full re-render because Glamour's word wrap is baked into the rendered output.

#### `[S]` — save Markdown

| Step | Behavior |
|---|---|
| `[S]` (loaded) | Open `NewSaveFilePicker(cwd, "<scanid-short8>-report.md", "Save report (Markdown)")`. |
| `pickerSaveConfirmedMsg{Path}` | `state = reportSaving`; `os.WriteFile(Path, []byte(p.markdown), 0644)`; `state = reportLoaded`; banner `Saved to <path>` (5s auto-clear). |
| Save error | `state = reportLoaded`; banner with the OS error. |

Sync because reports are KB-to-MB sized; microseconds to write.

#### `[E]` — export JSON

| Step | Behavior |
|---|---|
| `[E]` (loaded) | Open `NewSaveFilePicker(cwd, "<scanid-short8>-export.json", "Export scan data (JSON)")`. |
| `pickerSaveConfirmedMsg{Path}` | Create `context.WithCancel` from `App.ctx`; store `cancel` in pane; `state = reportExporting`; spawn export goroutine; spinner overlay visible. |
| Goroutine | POST `/scan/datalist`; loop batches of 20 IDs → POST `/scan/data`; stream beautified JSON array into `<Path>.tmp` adjacent to target; on completion `os.Rename(temp, path)` atomically; emit `exportDoneMsg`. |
| Per-batch tick | Emit `exportProgressMsg{Done, Total}` after each `/scan/data` returns. |
| `[Esc]` during export | `exportCtxCancel()`; goroutine cleans up temp file; `state = reportLoaded`; banner `Export canceled`. |
| Network error mid-export | Goroutine cleans up temp file; emit `exportErrorMsg{Err}`. |

Batch size 20 matches `g3cli` for proven behavior. Beautified by default — interactive operators want readable files, not pipe-friendly minified output.

**Why temp-and-rename:** a slow export over a flaky network could leave the target path as a truncated invalid JSON file. The temp-and-rename pattern guarantees the target path either exists complete or never appeared. Temp lives in `filepath.Dir(path)` to keep the rename on a single filesystem.

`[E]` is gated identically to `[R]` — only on terminal scans, because a running scan's data set is still growing and the export would race with new objects.

#### Spinner overlay during export

```
            ┌─────────────────────────────────┐
            │  ⠋ Exporting scan data…         │
            │     43 / 280 objects            │
            │                                 │
            │  [esc] cancel                   │
            └─────────────────────────────────┘
```

Centered over the viewport content using `lipgloss.Place`. Spinner uses the existing `bubbles/spinner` component.

#### Yellow caveats banner

When `errors != ""` (the server's report-generation produced parse errors but a report was returned), a one-row `BannerWarn`-styled banner renders above the viewport body:

```
Report generated with caveats: <first-line-of-errors>
```

Full error blob is dropped on the floor for v1. The signal is "the report had problems"; the detail isn't shown. (A future `[?]` toggle could expose the full blob.)

#### Loading and error states

- **Loading** — centered text `Loading report…` with a `bubbles/spinner`. Glamour-render of a typical report takes under 100ms, so the spinner often won't visibly tick — but on a slow/large report the operator gets a clear "something is happening" signal.
- **Error** — centered error box with `Failed to load report: <err>` plus `[r] retry  [esc] back`. The server returns 500 with a meaningful message when no finished report exists in Redis ("Could not find a finished report object in Redis…"); that message surfaces to the operator unmodified.

#### Layout

```
┌─ Scans ───────┬─ Report · 7d2a-3f1b-… · FINISHED ───────────────────────────┐
│   <scan-1>    │                                                              │
│   <scan-2>    │   # Golismero3 Scan Report                                   │
│               │                                                              │
│               │   ## Targets                                                 │
│               │   - 192.168.1.1                                              │
│               │                                                              │
│               │   ## Findings                                                │
│               │                                                              │
│               │   ### High — Outdated SSH                                    │
│               │   Host **192.168.1.1** is running OpenSSH 7.4 …              │
│               │   …                                                          │
├───────────────┴──────────────────────────────────────────────────────────────┤
│ s save · e export · esc back                                                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

Footer (`Help()`-driven): `s save · e export · esc back`. `pgup/pgdn`/`g`/`G` scroll keys still work but are not advertised, matching the 2026-05-08 footer-trim convention.

### LogsViewer `[S]` integration

The full-screen `LogsViewer` already exists. This adds:

| Step | Behavior |
|---|---|
| `[S]` | Open `NewSaveFilePicker(cwd, "<scanid-short8>-logs.log", "Save scan logs")`. |
| `pickerSaveConfirmedMsg{Path}` | `os.WriteFile(Path, []byte(strings.Join(viewer.renderedLines, "\n")), 0644)`. |
| Save error | Banner with OS error. |
| Save success | Banner `Saved to <path>` (5s auto-clear). |

The viewer already maintains a `renderedLines []string` buffer that feeds `viewport.SetContent`. The save handler is one line. No re-rendering, no separate formatter — saving captures exactly what the viewer was rendering.

**Save format** matches the on-screen format:

```
14:42:01 [nmap-fast]    Starting nmap scan against 192.168.1.1
14:42:01 [nmap-fast]    [g3:dispatch] task=a1b2... tool=nmap-fast
14:42:03 [nmap-fast]    Host is up (0.00033s latency).
14:42:04 [nikto]        + Server: nginx/1.18.0
14:42:04 [nmap-fast]    PORT    STATE SERVICE
```

ANSI stripped, `[g3:*]` markers preserved, tool column aligned to the viewer's computed `toolWidth`, `[?]` fallback for unmapped tasks. The 8-character UUID prefix in the default filename is a comfortable disambiguator in a downloads folder without making the filename UUID-heavy — same convention used by `git log --oneline`-style abbreviation.

Footer (`Help()`-driven): `s save · esc back`. `pgup/pgdn`/`g`/`G` scroll keys still work but are not advertised, consistent with the 2026-05-08 footer-trim convention.

**No `[E]` on the logs viewer.** Logs are already line-oriented text; a JSON export of `[{timestamp, tool, text}, ...]` has no consumer in mind. YAGNI.

**No `[S]` on the inline `LogsPanel`.** The panel is a preview; saving from it would require a separate per-task filename convention. Operators who want to save panel content press `[L]` to open the full-screen viewer first.

### README

File: `src/g3tui/README.md`. Length target ~180-220 lines.

**Outline:**

```
# g3tui — Interactive Terminal UI for Golismero3

One-sentence tagline.

## What is g3tui?
Positioning vs g3cli; the six workflows; static Go binary.

## Building and installing
make bin → bin/g3tui; make install → /usr/bin/g3tui; Go toolchain note.

## Configuration
Required env vars: G3_API_BASEURL, G3_API_WSURL, G3_API_TOKEN.
Optional: G3_PIPELINES_DIR, G3_CMD_LOG_LEVEL. Shares .env with g3cli.

## Dashboard tour
ASCII three-panel layout, annotated.
Global keys table.

## The six workflows
Create scan (n) · Monitor (default) · Logs (l) · Report (r) with [s]/[e] · Cancel (c) · Delete (d).

## Custom scan types
Embedded (network, web) and user .pipeline files. Format. Skip-on-invalid.

## Coexisting with g3cli
When to reach for which.

## Design docs
Links into docs/plans/2026-05-*-g3tui-*.md.
```

**Deliberately not in the README:**

- Screenshots / animated GIFs (user-owned).
- Per-keybind exhaustive table (the footer is the source of truth via each sub-model's `Help()`; a doc table goes stale).
- Architecture deep-dive (lives in `docs/plans/`).
- Testing instructions (tests are user-owned).
- Contribution / style guide (top-level concern).

Written last in the implementation order so it documents shipped behavior, not behavior that subsequently shifts during code review.

## Color and style additions

`src/g3tui/internal/ui/styles.go` gains:

- **`BannerSuccess`** — green-tinted banner style for the save toast (`Saved to <path>`, `Exported N objects to <path>`).
- **`PickerOverwritePrompt`** — yellow-tinted single-row style for the inline `[!] foo exists. Overwrite? [y/n]` line in the save-mode picker.

Glamour brings its own theming; no project styles cover the report body.

## File touch list

**Create:**

| Path | Purpose |
|---|---|
| `src/g3tui/internal/ui/report.go` | New `ReportPane` component. |
| `src/g3tui/README.md` | Subcomponent documentation. |
| `docs/plans/2026-05-11-g3tui-tier3-completion-implementation.md` | Per-task implementation plan (separate document). |

**Modify:**

| Path | Change |
|---|---|
| `src/g3tui/internal/ui/picker.go` | Add `PickerMode`, `filename textinput.Model`, `title`, `confirming`; `NewSaveFilePicker` constructor; save-mode `Update`/`View` branches; inline overwrite-confirm; `pickerSaveConfirmedMsg`. |
| `src/g3tui/internal/ui/keys.go` | Add `Keys.Save` (`s`), `Keys.Export` (`e`), `Keys.Yes` (`y`), `Keys.No` (`n`). |
| `src/g3tui/internal/ui/styles.go` | Add `BannerSuccess`, `PickerOverwritePrompt`. |
| `src/g3tui/internal/ui/app.go` | Wire `[R]` to instantiate `ReportPane`; route messages/keys through it when non-nil; gate `[R]`/`[E]` on terminal status; compose like the existing `LogsViewer` overlay. |
| `src/g3tui/internal/ui/logsviewer.go` | Add `[S]` handler; compose save-mode picker; expose `Keys.Save` in `Help()`. |
| `src/g3tui/internal/client/client.go` | Add `GetReport(ctx, scanID)`, `GetScanDataList(ctx, scanID)`, `GetScanData(ctx, scanID, dataIDs)`. |
| `src/g3tui/internal/client/messages.go` | Add `reportLoadedMsg`, `reportErrorMsg`, `exportProgressMsg`, `exportDoneMsg`, `exportErrorMsg`. |
| `src/g3tui/go.mod`, `go.sum` | Add `github.com/charmbracelet/glamour` and `github.com/charmbracelet/bubbles/textinput` if not present from earlier tiers. |

**Unchanged:**

`src/g3tui/internal/client/poll.go`, `stream.go`; `src/g3tui/internal/pipelines/`; `src/g3tui/internal/ui/logspanel.go`, `scanlist.go`, `scandetail.go`, `wizard.go`, `confirm.go`. The save-mode picker work is purely additive — open-mode behavior (used by the wizard's imports flow) is unchanged.

## Risks

- **Glamour rendering on minimal terminals.** `auto` style may not detect background correctly on some SSH multiplexers or headless TTYs. Matches existing convention (no per-terminal config); switch to a fixed style via env var if a real complaint arrives later.
- **No tilde / `$VAR` expansion in save paths.** A user typing `~/Downloads/foo.md` gets a literal `~` directory under cwd. Documented in README; consistent with typical TUI text-input behavior.
- **Large-scan export memory and time.** 10k issues at 20 IDs/batch = 500 round-trips. Atomic temp-rename guards partial-write corruption; cancel-via-`Esc` is bounded by batch latency, not instant. Documented near the export goroutine.
- **Concurrent save+export attempts.** `[S]` and `[E]` are no-ops while `state` is `reportSaving` or `reportExporting`. Footer keys hidden during those states.
- **`os.Rename` across filesystems.** Temp file lives in `filepath.Dir(path)`, not in cwd, guaranteeing same-filesystem atomic rename even when the user picks a target on a different mount.
- **Picker save-mode state pollution between invocations.** Each `[S]`/`[E]` press in `ReportPane` and each `[S]` in `LogsViewer` calls `NewSaveFilePicker` fresh and stores it on the component as `picker *FilePicker`; on dismiss the pointer goes back to `nil`. A previous session's filename or `confirming` state cannot leak in. (The wizard uses the open-mode picker differently — composed once and reused — but the two modes never share an instance.)
- **Report viewer status drift.** Without `SetScanStatus`, a viewer left open across a state transition would show a stale title. Mirrored from the logs work; not novel risk surface.

## Verification scope (agent-side)

Per project rule (`feedback_tests_are_user_owned.md`): agent verification is strictly `go build ./...` plus `golangci-lint run ./...`. No behavioral testing, no `bin/g3tui` runs, no `docker compose` interactions, no live-server calls.

Behavioral verification — Glamour rendering on multiple terminal types, JSON export against a real multi-thousand-issue scan, cancel-during-export, overwrite-prompt UX, save-toast clearing, README accuracy against shipped behavior — is user-owned.

## Out of scope (reaffirmed)

- Additional report formats beyond Markdown and JSON.
- Tilde or `$VAR` expansion in save paths.
- Filename collision auto-suffix.
- Save history / "repeat last save."
- Background saves with toast notification.
- Streaming JSON export to a pipe (use `g3cli export -o -`).
- Per-task log save in the inline `LogsPanel`.
- A `?` help overlay.
- Mouse support.