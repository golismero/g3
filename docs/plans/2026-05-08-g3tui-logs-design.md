# g3tui Logs — Inline Panel and Full-Screen Viewer

**Status:** Implemented and tested 2026-05-11. Implementation plan: [`2026-05-08-g3tui-logs-implementation.md`](2026-05-08-g3tui-logs-implementation.md). This document was updated post-implementation to reflect a few details that were settled or refined during code review and testing — call-outs are in the relevant sections, with a consolidated summary in **Resolved during implementation** near the bottom.

**Scope:** Replace the placeholder inline `LogsPanel` with a working live preview that auto-tracks the Tasks-panel cursor, and implement the `l` keybinding's full-screen scan-level logs viewer that today renders only a "coming soon" banner.

**Predecessors:**
- [`2026-05-06-g3tui-design.md`](2026-05-06-g3tui-design.md) — original `g3tui` design; specified a full-screen logs viewer with per-task picker.
- [`2026-05-08-g3tui-layout-redesign-design.md`](2026-05-08-g3tui-layout-redesign-design.md) — three-panel dashboard redesign that introduced the inline `LogsPanel` as a structural placeholder, deferred its implementation to "Tier 3" (this work), and noted "the 250 ms debounce for log fetches is a Tier 3 concern".

This document supersedes the **Logs viewer** section of the 2026-05-06 design (the picker-based per-task viewer is replaced by a unified scan-level viewer) and fills in the deferred Tier 3 details from the 2026-05-08 redesign.

---

## Problem statement

Two pieces of `g3tui` ship today as placeholders:

1. **`LogsPanel`** (`src/g3tui/internal/ui/logspanel.go`) is the bottom-right panel of the dashboard. It is focusable, it sizes correctly inside the layout, and it discards keystrokes. Its `View()` renders only `(log preview — coming in a follow-up release)`. Operators have no way to see live tool output from the dashboard without leaving it.

2. The **`l` keybinding** in `App.Update` (`src/g3tui/internal/ui/app.go:176-192`) shows a 5s banner — `"logs viewer for task X — coming in a follow-up release"` or `"scan logs viewer — coming in a follow-up release"` depending on the focused panel — and does nothing else.

The endpoint plumbing is mostly already there: `Client.GetLogs(scanID, taskID)` (`src/g3tui/internal/client/client.go:81`) calls `/scan/logs` and returns `g3lib.G3TaskLog`. The polling layer (`internal/client/poll.go`) is already used by `ScanList` and `ScanDetail`. What is missing is (a) the UI components, and (b) one small server change so a single endpoint can serve both task-scoped and scan-scoped log fetches.

## Goals and non-goals

**Goals**

- Make the inline `LogsPanel` show live log output for whichever task the Tasks-panel cursor is on, polling at the same 2s cadence the rest of the dashboard uses.
- Make `l` open a full-screen scan-level logs viewer (replacing the right pane like the future Report viewer) that shows all tasks for the selected scan, chronologically interleaved, with per-line tool-name attribution.
- Keep both surfaces self-contained: each owns its own polling lifecycle, its own viewport, its own scroll state.
- Reuse existing infrastructure (`bubbles/viewport`, `internal/client/poll.go`, `g3lib.QueryLog`, `g3lib.StripAnsi`, the existing `[g3:dispatch]` log-marker convention) wherever possible.

**Non-goals**

- **Save-to-file (`[S]`).** Deferred. The original 2026-05-06 design called for a save-as overlay backed by a save-mode `FilePicker`; the existing picker is multi-select-only. Implementing save-mode is its own work that also unblocks the Report viewer's `[S]`.
- **Per-task picker in the full-screen viewer.** Replaced by the scan-level unified stream. The original picker concept is obsolete now that the inline panel covers the per-task drilldown.
- **WebSocket log streaming.** Polling is the contract through the entire 2026-05-06 design. WS streaming becomes a `client/` swap when it lands; no UI change needed.
- **Incremental log cursor (`since=<index>`).** Same reasoning — full re-fetch + dedupe is the documented v1 trade-off, and WS streaming will obviate it.
- **Per-task log filtering inside the full-screen viewer.** Operators who want one task's logs use the inline panel.
- **ANSI color preservation in log lines.** Strip on receipt for predictable layout (matches `g3cli logs` convention via `g3lib.StripAnsi`).

## Architecture

The work has three layers, each minimal:

1. **Server change** — relax `/scan/logs` to accept an empty `TaskID`; branch the handler to a scan-level mode. Existing types only.
2. **Inline `LogsPanel`** — replace the placeholder body with a viewport-backed live preview bound to the Tasks-panel cursor.
3. **`LogsViewer` overlay** — new component, parallel to the existing `Confirm` and `Wizard` overlays, opened by `l` and dismissed by `Esc`.

```
┌─ g3tui ─────────────────────────────────  ● connected · srv=… ─┐
│ Scans         │ Tasks                                          │
│   <scan-1>    │   ID  STATE  TOOL  TIME  LAST SEEN  WORKER     │
│   <scan-2>    │   …                                            │
│               ├────────────────────────────────────────────────│
│               │ Logs · <task-id> · <line-count>                │
│               │   14:42:03  Host is up (0.00033s latency).     │
│               │   14:42:04  PORT    STATE SERVICE              │
│               │   …                                            │
├───────────────┴────────────────────────────────────────────────┤
│ tab cycle · n new · ↑↓ select · l logs · r report · ...        │
└────────────────────────────────────────────────────────────────┘
```

Pressing `l` replaces the right pane:

```
┌─ Scans ───────┬─ Logs · <scan-id> · <status> ─────  ● polling 2s · ↓ tail ─┐
│   <scan-1>    │ 14:42:01 [nmap-fast]    Starting nmap against 192.168.1.1  │
│   <scan-2>    │ 14:42:01 [nmap-fast]    [g3:dispatch] task=a1b2... tool=…  │
│               │ 14:42:03 [nmap-fast]    Host is up (0.00033s latency).    │
│               │ 14:42:04 [nikto]        + Server: nginx/1.18.0             │
│               │ 14:42:04 [nmap-fast]    PORT    STATE SERVICE             │
│               │ …                                                          │
├───────────────┴────────────────────────────────────────────────────────────┤
│ [PgUp/PgDn] scroll · [g/G] top/bot · [esc] back                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## Server change (g3lib + g3api)

### `src/g3lib/api.go`

Relax the `TaskID` validator on `ReqQueryLog`:

```go
type ReqQueryLog struct {
    ScanID string `json:"scanid"  validate:"uuid"`
    TaskID string `json:"taskid"  validate:"omitempty,uuid"`
}
```

Empty `TaskID` now validates; non-empty values must still be a UUID.

### `src/g3api/g3api.go`

Branch the existing `/scan/logs` handler on emptiness:

```
if request.TaskID == "" {
    // scan-level: stream rows via QueryLog(db, cb, scanID), return []LogEntry
} else {
    // unchanged: QueryLogForTask(db, scanID, taskID), return G3TaskLog
}
```

The endpoint becomes polymorphic by mode: `G3TaskLog` for the existing single-task call, `[]LogEntry` for the new scan-level call. `LogEntry` is the existing row shape in `g3lib` (`{Timestamp, ScanID, TaskID, Text}`) — no new types.

The underlying SQL is `g3lib.QueryLog(db, callback, scanid)` (already in `sql.go:140`), which orders by `(timestamp, id)` ASC. The wire output is naturally chronological.

### TUI client (`src/g3tui/internal/client/client.go`)

Split the existing `GetLogs` into two methods so call sites don't switch on response shape:

```go
func (c *Client) GetTaskLogs(ctx context.Context, scanID, taskID string) (g3lib.G3TaskLog, error)
func (c *Client) GetScanLogs(ctx context.Context, scanID string) ([]g3lib.LogEntry, error)
```

Both hit `/scan/logs`. The first sends `{ScanID, TaskID}` and decodes the existing `G3TaskLog`. The second sends `{ScanID, TaskID:""}` and decodes `[]LogEntry`.

A new `ScanLogChunk` message type joins `LogChunk` in `internal/client/messages.go`:

```go
type ScanLogChunk struct {
    ScanID  string
    Entries []g3lib.LogEntry
}
```

## Inline `LogsPanel`

### Binding

The panel binds to `(scanID, taskID)` derived from `(ScanList.SelectedID(), ScanDetail.SelectedTaskID())`. The `App` is the source of truth for both. Whenever either changes, `App` emits a `logsBindingChangedMsg{scanID, taskID}` and forwards it to the `LogsPanel`.

The empty-binding cases (`scanID == ""`, or `taskID == ""` because the focused scan has no tasks yet) render a dimmed message and skip polling.

### Polling lifecycle

A new helper `LogsPoller` wraps the existing `Poller` from `internal/client/poll.go` and adds a 250ms debounce on binding changes:

- `bindingChanged(scanID, taskID)` — cancel any pending fetch, start a 250ms timer.
- 250ms expires → fetch once → schedule a 2s tick.
- 2s tick → fetch (same binding) → schedule next tick.
- Scan reaches a terminal state (status visible from the cached `ScanList` row) → stop ticking, no further fetches.
- Binding changes again before the debounce elapses → reset the 250ms timer (cursor thrash mitigation).

The 250ms debounce is the value the layout-redesign design already flagged for this work. 2s matches the cadence of `ScanList` and `ScanDetail`.

### Rendering

Lines are formatted as `HH:MM:SS  <text>` — no per-line tool prefix because the panel is single-task and its title already carries the task ID. ANSI escape sequences in `text` are stripped on receipt via `g3lib.StripAnsi` (matches `g3cli logs` convention).

Panel header: `Logs · <truncated-taskid> · <line-count>`. Title progressive-collapse uses the same helper as the existing `renderDetailTitle` in `scandetail.go` so a long UUID never wraps to a second visual row.

### Scrolling and follow-tail

The body uses `bubbles/viewport`. When the panel is focused, `↑`/`↓`/`k`/`j` move one line, `pgup`/`pgdn` page, `g`/`G` jump to top/bottom.

Follow-tail is **implicit, not a toggle**: before applying new content from a poll, the panel checks `viewport.AtBottom()`. If true, it re-applies the new content and then scrolls to the new bottom. If false, it preserves the user's scroll offset. This matches a standard `tail -f` UX without an extra keybind, and is consistent with the user's intent that the panel act as a focusable scrolling viewport.

### Empty and error states

- **No binding** (no scan selected, or scan has no tasks): `(no task selected)` dimmed.
- **Empty result** (the bound task has no log lines yet): `(no log lines yet)` dimmed.
- **Fetch error**: keep the last successful render visible. Surface the error via the existing app-level `ErrorMsg` banner (5s auto-clear). Do not blank the panel — partial visibility beats no visibility while the next poll is in flight.

### Reset on binding change

When the binding changes, clear the panel's line buffer and scroll to top so the operator does not see stale content from the previous task during the 250ms debounce + fetch round-trip.

## Full-screen `LogsViewer`

A new component, parallel in role to the planned `ReportPane` and structurally similar to the existing `Confirm` and `Wizard` overlays in how it composes onto `App`.

### Lifecycle

- `l` from any focused panel (Scans, Tasks, or Logs) opens the viewer for the **currently selected scan**. Focus-independent — the inline panel already covers the per-task case.
- If no scan is selected, `l` is a no-op.
- `Esc` closes the viewer. Focus restores to the panel that was focused when the viewer opened.
- While the viewer is open, the dashboard's polling continues unchanged in the background; the viewer overlays the right pane only.

### Layout

Replaces the right pane (the 44-col left scan list stays). Same horizontal split as today.

```
┌─ Scans ───────┬─ Logs · <scan-id> · <status> ─────  ● polling 2s · ↓ tail ─┐
│   <scan-1>    │ HH:MM:SS [tool]      log line text                          │
│   <scan-2>    │ …                                                           │
└───────────────┴─────────────────────────────────────────────────────────────┘
```

### Per-line attribution

The TUI walks the `[]LogEntry` stream and parses `[g3:dispatch] task=<id> tool=<name>` markers as they pass through, building an in-memory `taskID → tool` map. The map persists for the lifetime of the viewer instance and is rebuilt from scratch on each full re-fetch (the API has no incremental cursor; we re-parse the whole stream).

A line whose `taskid` is not yet in the map renders with `[?]` as the tool prefix. This is rare and self-correcting — usually a same-timestamp ordering edge case where the dispatch marker appears immediately after on the next row; the next poll catches up.

`[g3:dispatch]`, `[g3:start]`, `[g3:done]`, and `[g3:cancel]` marker lines remain visible in the stream as ordinary log lines (matches `g3cli logs` and the 2026-05-06 design). The viewer parses them in passing for the tool map; it does not filter them out.

### Polling

2s cadence while open and the scan is non-terminal. One-shot fetch on entry for terminal scans, then no further polls. Implementation reuses `Poller` directly — no debounce wrapper, since there are no in-viewer binding changes.

### Scrolling and follow-tail

Identical to the inline panel: `bubbles/viewport`, `↑`/`↓`/`pgup`/`pgdn`/`g`/`G`, implicit follow-tail via `viewport.AtBottom()` check before applying new content.

### Width adaptation

The `[tool]` column width is `min(12, max(visualWidth(toolName)) over the current map)`. Below 12, end-ellipsis. The title shrinks via the same `renderDetailTitle`-style helper used elsewhere — UUID always fits one row.

### Empty and error states

- **No log lines yet** (the scan is brand new and no worker has emitted anything): `(no log lines yet)` dimmed in the body.
- **Fetch error**: same treatment as the inline panel — keep the last successful render visible, surface the error via the existing app-level `ErrorMsg` banner (5s auto-clear). Do not blank the viewer.

## Keybinding table revisions

Replaces the relevant rows of the 2026-05-08 layout-redesign keybind table:

| Key | Behavior |
|---|---|
| `l` | Open scan-level logs viewer for the **selected scan**. Focus-independent. |
| `↑` `↓` `pgup` `pgdn` `g` `G` (Logs panel focused) | Scroll log lines. |
| `↑` `↓` `pgup` `pgdn` `g` `G` (Logs viewer open) | Scroll log lines. |
| `esc` (Logs viewer open) | Close, restore previous focus. |

`l` is no longer focus-aware. The previous table's three-case behavior (per-task viewer / scan viewer / selected-task viewer) collapses into one — the inline panel covers the per-task case, the viewer covers the scan case, and there is no third interpretation.

## Color and style additions

`src/g3tui/internal/ui/styles.go` gains:

- **`LogTimestamp`** — dim foreground for the `HH:MM:SS` prefix in both surfaces.
- **`LogTool`** — accented foreground (likely the `AppTitle` purple) for the `[tool]` prefix in the full-screen viewer.

No new border styles — the inline panel reuses `PaneBorder` / `PaneBorderFocused` from the layout redesign.

## File touch list

- `src/g3lib/api.go` — `ReqQueryLog.TaskID` validator → `omitempty,uuid`.
- `src/g3api/g3api.go` — branch `/scan/logs` handler on `TaskID` emptiness; scan-level returns `[]LogEntry`.
- `src/g3tui/internal/client/client.go` — replace `GetLogs` with `GetTaskLogs` + `GetScanLogs`.
- `src/g3tui/internal/client/messages.go` — add `ScanLogChunk` message type.
- `src/g3tui/internal/ui/logspanel.go` — fill in the placeholder: bind tracking, debounced poll, viewport-backed scroll, ANSI strip, follow-tail.
- `src/g3tui/internal/ui/logsviewer.go` — **new file**. Full-screen overlay paralleling `Confirm`/`Wizard` composition.
- `src/g3tui/internal/ui/app.go` — `l` handler simplifies to opening `LogsViewer`; add `logsViewer *LogsViewer` overlay field; route messages/keys through it when non-nil.
- `src/g3tui/internal/ui/styles.go` — `LogTimestamp`, `LogTool`.

`src/g3tui/internal/client/poll.go` is unchanged; the existing `Poller` is reused. `src/g3tui/internal/ui/keys.go` is unchanged; `Keys.Logs` already exists.

## Risks

- **Polymorphic `/scan/logs` response shape.** The endpoint now returns one of two top-level shapes depending on whether `TaskID` was empty. Mitigated client-side by `GetTaskLogs` / `GetScanLogs` being separate methods so callers never have to switch on shape. External consumers (currently only `g3cli logs`) keep working unchanged because they always supply a `TaskID`.
- **Late dispatch markers in the unified stream.** A line that arrives before its `[g3:dispatch]` marker (same-timestamp ordering edge case) renders as `[?]`. Self-correcting on the next poll. Documented in code at the parser site.
- **Cursor-thrash log fetches.** Mitigated by the 250ms debounce on binding changes. The poll cadence is unchanged across the rest of the dashboard, so server load is bounded by `1 fetch per active LogsPanel` plus `1 fetch per open LogsViewer`, both at 2s.
- **Empty per-task panel for terminated scans.** The `/scan/logs` task-mode call already works against the SQL `logs` table directly (not Redis), so terminated scans show their preserved log lines as long as the SQL data is retained. No new fallback logic needed for this surface.

## Resolved during implementation

- **Empty-array JSON shape on scan-level fetch.** Server initializes `entries := make([]g3lib.LogEntry, 0)` rather than `var entries []g3lib.LogEntry`. A nil slice marshals as JSON `null`; the rest of `g3api`'s slice responses use the same `make` pattern to guarantee `[]` on empty. Consistency fix from code review.
- **Generation-stamped chunk envelopes.** `client.LogChunk` and `client.ScanLogChunk` carry `ScanID` and `Err` but not a generation counter; that's a transport concern not a binding-state concern. The TUI wraps them in private message types `logsChunkMsg{Generation, Chunk}` (inline panel) and `logsViewerChunkMsg{Generation, Chunk}` (viewer) so a slow in-flight fetch that returns after a binding rebind cycled `(scanID, taskID)` back to the same value is correctly rejected. Without this, two parallel poll chains could form silently.
- **Viewer scan-status updates.** `LogsViewer.scanStatus` is captured at open time but kept in sync afterwards via a new `SetScanStatus` mutator that `App.dispatchToScanList` calls whenever a `ScanListSnapshot` or `ScanProgressUpdate` reports a new status for the viewer's scan. When the scan transitions to terminal while the viewer is open, the next 2s tick observes `isTerminal()` and the polling loop winds down without waiting for the user to close the viewer.
- **Focus-independent action keys in the footer.** `Keys.Logs`, `Keys.Report`, `Keys.Cancel`, `Keys.Delete` now appear in the footer in any focus state (not only when `focusScans` is active), reflecting that they act on the selected scan regardless of which panel has focus. `Keys.Report` is additionally gated on `isTerminal(SelectedStatus())` so the hint only appears when the report can be generated.
- **PgUp/PgDn dropped from advertised keys.** The keys still work in `ScanDetail.Update`, `LogsPanel.Update`, and `LogsViewer.Update`; they're just not shown in the footer line, which was getting crowded.
- **Duplicate `l logs` hint removed.** `ScanDetail.Help()` no longer appends `Keys.Logs` — the focus-independent global append covers it.
- **In-viewer footer string removed.** `LogsViewer.View` previously rendered its own hint strip (`[PgUp/PgDn] scroll · [g/G] top/bot · [esc] back`) in addition to the global dashboard footer. Removed; `LogsViewer.Help()` feeds the global footer with the same keys, recovering one row of body height.
- **`toolWidth: 1` initialization.** `NewLogsViewer` initializes `toolWidth: 1` rather than leaving the zero value, so the `?`-prefix path renders cleanly even on the first frame before any `[g3:dispatch]` markers are parsed.
- **Non-deprecated viewport methods.** Both `LogsPanel` and `LogsViewer` use `ScrollUp(1)`, `ScrollDown(1)`, `HalfPageUp()`, `HalfPageDown()` rather than the deprecated `LineUp`/`LineDown`/`HalfViewUp`/`HalfViewDown`. Behavior identical; staticcheck-clean.

## Verification scope (agent-side)

Per project rule (`feedback_tests_are_user_owned.md`): agent verification is strictly `go build ./...` plus `golangci-lint run ./...`. No behavioral testing, no `bin/g3tui` runs, no `docker compose` interactions, no live-server `/scan/logs` calls.

Behavioral verification — multiple terminal widths, real scans accumulating log lines, debounce under fast cursor movement, the dispatch-marker parser against real `[g3:` content, and viewer/panel transitions during a scan's lifecycle — is user-owned.
