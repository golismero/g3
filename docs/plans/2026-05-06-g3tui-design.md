# g3tui — Interactive Terminal UI Design

**Status:** Design approved 2026-05-06 (brainstorming complete). Implementation plan to follow as a separate document.

**Scope:** New binary `g3tui` that coexists with `g3cli`. `g3cli` is not modified. `g3tui` consumes only the existing `g3api` HTTP/WebSocket surface — no new server endpoints required for v1, no direct access to MongoDB/MariaDB/Redis/Mosquitto.

---

## Background

`g3cli` is the current operator interface for `g3api`. It exposes ten subcommands (`scan`, `progress`, `logs`, `ls`, `ps`, `cancel`, `report`, `export`, `tools`, `rm`) in a Unix-style command-per-action shape. It is good enough for scripting and one-off use, but mid-flight monitoring, multi-step scan setup, and report consumption all require leaving and re-entering the tool repeatedly. The four core operator workflows — *create scan*, *monitor*, *cancel*, *consume report* — share state but require separate command invocations.

`g3tui` is an interactive companion that keeps an operator inside one persistent session for those four workflows plus two adjacent ones (*delete scan*, *view per-task logs*). `g3cli` remains the right tool for scripting, automation, and the long tail of operations (raw JSON export, plugin listing) that don't justify dedicated TUI screens.

## Goals and non-goals

**Goals**

- Cover six workflows interactively: create scan, monitor (scan list + per-task drill-in), cancel, view per-task logs, view formatted Markdown report, delete scan.
- Live updates without explicit refresh: the dashboard's scan list reflects server state via the `scanprogress` WebSocket; per-task and log panes poll on a 2-second cadence while focused.
- Single static binary, same build/install conventions as the other six binaries.
- Reuse `g3lib`'s request/response types and helpers where they exist; don't reimplement the wire format.
- Hide low-level script syntax from the operator. Targets, imports, and mode are entered through dedicated UI; the term "script" never appears in the UI.

**Non-goals**

- Replacing `g3cli`. `g3cli` continues to exist unchanged; both speak to the same API with the same env vars.
- Raw scan-data export (`g3cli export`), plugin listing as a top-level workflow, or any operation already well-served by a one-line `g3cli` invocation.
- Per-task cancellation. The current API only exposes whole-scan cancellation (`/scan/stop`); a per-task primitive is on the future API roadmap (Tier 3 of the existing API extensions plan) but not in v1.
- Direct backend access. Even where a screen could be cheaper to render by hitting Mongo/Redis directly, `g3tui` goes through the API.
- New server endpoints. Server changes belong in a separate plan; `g3tui` v1 lives within the current API.

## Vocabulary

The TUI uses operator-facing language, not script-internal language:

- **Scan type** — the pipeline content (the `tool | tool | tool` lines). Maps to `.pipeline` files in `resources/pipelines/` (which contain only pipeline lines, no `target`/`mode`/`import`). The two shipped scan types are `network` and `web`. Operators may add their own.
- **Targets, imports, mode** — always entered by the operator through the wizard. They are not part of any scan type. The TUI assembles the final script by prepending these to the chosen scan type's content.
- **Script** — never used in the UI. Only appears in implementation context (the string sent to `/scan/start`).

## Tech stack

Go (version per the existing `src/*/go.mod` files — currently `1.26.2`; the binary tracks the rest of the repo) with:

- **Bubble Tea** (`github.com/charmbracelet/bubbletea`) — the Elm-style event loop.
- **Bubbles** (`github.com/charmbracelet/bubbles`) — components: `list`, `viewport`, `textarea`, `textinput`, `filepicker`, `spinner`, `key`.
- **Lip Gloss** (`github.com/charmbracelet/lipgloss`) — styles and layout (`JoinHorizontal`, `JoinVertical`).
- **Glamour** (`github.com/charmbracelet/glamour`) — Markdown renderer for the report viewer (`auto` style).

Why Go: lives next to `g3cli`/`g3api` under `src/g3tui/` with the existing `Makefile` pattern; reuses `g3lib` request/response structs verbatim via local `replace` directives; static-binary distribution matches the rest of the project.

## Architecture

Three layers, kept separate.

### 1. API client layer — `internal/client/`

A thin package wrapping every endpoint `g3tui` touches, plus the WebSocket subscription. Pure I/O; no Bubble Tea types.

Endpoints used:

- `GET-style` (POST with body) JSON: `/scan/start`, `/scan/list`, `/scan/progress`, `/scan/tasks/status`, `/scan/logs`, `/scan/stop`, `/scan/delete`, `/scan/report`, `/plugin/list`.
- Multipart upload: `/file/upload`.
- WebSocket: `/ws` with `{"msgtype":"scanprogress"}` subscription.

Reuses `g3lib.MakeApiRequest` and the `g3lib.Req*`/`g3lib.ScanStatusEntry`/`g3lib.ScanTaskStatusResponse`/`g3lib.G3TaskLog` types verbatim — no parallel type definitions. WebSocket uses `gorilla/websocket` directly (same pattern as `g3cli`'s `ProgressCmd`); `g3lib.WrapWebSocket` is a server-side helper and not reused on the client.

Both polling and WS streaming emit the same domain `tea.Msg` types (`ScanProgressUpdate`, `TaskStatusUpdate`, `LogChunk`, `ScanStarted`, etc.). The UI does not know which transport delivered them. When per-scan / per-log WS streaming lands later (Tier 1-2 of the existing API extensions plan), only this package changes; the UI is untouched.

### 2. TUI layer — `internal/ui/`

One Bubble Tea model per concern. The top-level `App` model owns the layout (`lipgloss.JoinHorizontal` for left panel + main pane) and routes messages to sub-models. Sub-models own their own state and keybinds; each exports a `Help() []key.Binding` so the footer is built from a single source of truth.

Sub-models:

- `ScanList` — left panel, persistent.
- `ScanDetail` — right pane: per-task table for the selected scan.
- `LogsPane` — right pane: scrollable log viewer for one (scan, task).
- `ReportPane` — right pane: Glamour-rendered Markdown report.
- `WizardOverlay` — modal overlay for new-scan creation (form + sub-overlays for imports and custom scan type).

### 3. Pipeline registry — `internal/pipelines/`

Loads the embedded default scan types and any user-supplied ones, merges them, returns `[]Pipeline{Name, Source, Content}` for the wizard. Detail in §"Pipeline registry" below.

### Process model

Single goroutine for the Bubble Tea event loop. A separate goroutine per active subscription/poll, each writing into Bubble Tea's `tea.Program.Send` channel as `tea.Msg`s. Cancellation via a single `context.Context` from `App.Init()`; `Ctrl-C` cancels it and `App.Run` returns cleanly.

### State

No persistent local state. No SQLite, no config writes. Env vars supply credentials, the pipelines directory supplies scan-type overrides, the API supplies everything else. The TUI is a stateless shell over the server's state.

## Layout — main dashboard

The screen the operator lands on after launch. Persistent throughout the session.

```
┌─ g3tui ──────────────────────────────────────────  ● connected · srv=https://g3.lab/api ─┐
│ Scans                                │ Detail · 7d2a-… (RUNNING · 42%)                   │
│                                      │                                                   │
│ ▸ 7d2a-3f1b-…  RUNNING   42%         │  Tasks (live, 2s poll)                            │
│   c011-8aa2-…  WAITING    0%         │  ┌──────────────────────────────────────────────┐ │
│   91ee-4400-…  FINISHED 100%         │  │ TASK ID    STATE        TOOL       AGE  LINES│ │
│   1f5d-bbb1-…  CANCELED   —          │  │ a1-…      RUNNING       nmap-fast  17s   213 │ │
│   88a0-7e44-…  FAILED    71%         │  │ b3-…      RUNNING        testssl    4s    88 │ │
│                                      │  │ d2-…       DONE           dig        —    12 │ │
│                                      │  │ e7-…     DISPATCHED      vulners     —     0 │ │
│                                      │  └──────────────────────────────────────────────┘ │
│                                      │                                                   │
│                                      │  [L] Logs   [R] Report   [C] Cancel   [Esc] Back  │
│                                      │                                                   │
│ [N] New scan  [↑↓] Select  [/] Filter│                                                   │
├──────────────────────────────────────┴───────────────────────────────────────────────────┤
│ N new · ↑↓ select · L logs · R report · C cancel · D delete · Q quit                     │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

**Behaviors:**

- **Left panel (`ScanList`)** — always visible. Driven by the `scanprogress` WS; falls back to `/scan/list` + `/scan/progress` polling at 3s when WS is disconnected. Sorted: RUNNING first, then WAITING, then terminal states (most-recent first within terminal). `↑↓` selects, `/` filters by ID prefix or status, `n` opens the wizard overlay.
- **Right pane (`ScanDetail`)** — per-task table for the selected scan, polled from `/scan/tasks/status` every 2s while focused; off when scan is terminal. Column shape mirrors `g3cli ps <scanid>` (TASK ID, STATE, TOOL, WORKER, LAST SEEN, AGE, LINES). `L`/`R`/`C`/`D` open the logs viewer, report viewer, or trigger confirm-and-cancel/delete flows.
- **Header bar** — connection status, server URL (host portion only; token never displayed). Dot color: green = WS connected, yellow = reconnecting (poll fallback active), red = both broken.
- **Footer bar** — global keybinds; sub-models override with their own.
- **Empty states** — "No scans yet — press [N] to start one" if `/scan/list` is empty; "Scan has no tasks yet" if a selected scan's task list is empty (matches the existing `g3cli ps` empty-state message).

Layout dimensions: left panel fixed-width ≈38 chars, right pane gets the rest. Minimum supported terminal: 100×24 (smaller is allowed but degrades gracefully — left panel narrows, no responsive breakpoints for v1).

## New-scan wizard

Triggered by `[N]` from the dashboard. Modal overlay (~80×24) centered over the dashboard; the dashboard stays visible behind dimmed content so the live scan list is not lost during setup.

```
┌─ New scan ─────────────────────────────────────────────────────────────────┐
│                                                                            │
│  Targets ─ one per line, blank lines ignored                               │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ 192.168.1.1                                                          │  │
│  │ example.com                                                          │  │
│  │ _                                                                    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│  Imports                                                            [+ Add]│
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ testssl   samples/testssl-www.csv                              [×]   │  │
│  │ nmap      /tmp/scan-1.xml                                      [×]   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│  Mode      ( ) sequential   (●) parallel                                   │
│                                                                            │
│  Scan type                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  ▸ network            (embedded)                                     │  │
│  │    web                (embedded)                                     │  │
│  │    quick-recon        (user)                                         │  │
│  │    Custom…                                                           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│  [Enter] Submit       [Esc] Cancel                                         │
└────────────────────────────────────────────────────────────────────────────┘
```

**Targets.** Multi-line textarea, one target per line, blank lines ignored. Soft warning (not blocking) on lines that don't look like an IP, hostname, or URL — the server's `BuildTargets` is the validation authority.

**Imports — tool-first batch picker.** `[+ Add]` opens a two-step overlay:

1. Tool dropdown sourced from `/plugin/list` (cached at app start). Listed alphabetically. *V1 limitation:* `/plugin/list` does not currently expose whether a plugin has an importer, so all plugins appear; selecting one without an importer surfaces the server's clean rejection at submit. See "Future API improvements" below.
2. Multi-select file picker (`bubbles/filepicker`, Space to toggle, Enter to confirm). All selected files become rows bound to that tool.

The imports list itself shows `<tool>  <file path>  [×]` rows; Enter on a row removes it. Repeat the [+ Add] flow for files of a different tool.

**Mode.** Two-button toggle: `sequential` / `parallel`. Default `parallel` (matches g3cli's convention).

**Scan type.** Selectable list:
- All embedded scan types alphabetically (`network`, `web` for v1).
- All user scan types alphabetically (from `$G3_PIPELINES_DIR` or `~/.config/g3tui/pipelines/`).
- `Custom…` always last.

`Custom…` opens a single-pane textarea where the operator pastes pipeline-only content. Validation: each non-blank, non-comment line must parse as a pipeline. We do this by feeding `"mode parallel\n" + "target placeholder\n" + custom_content` through `g3lib.ParseScript` and surfacing errors. No `target`/`mode`/`import` directives allowed in the custom content — those are added by the wizard.

**No live preview pane.** The wizard is just the form. Operators who want hand-crafted comments and whitespace use `g3cli scan -i my.script` — that is the coexist-with-g3cli story.

**Submit flow** (`[Enter] Submit`):

1. Build the script in-memory via plain string templating: `mode <X>\n` + `target <each>\n` + (per import: `import <tool> <path>\n`) + chosen scan type's content. No `g3lib.ParseScript` round-trip in the wizard's render path.
2. Validate locally: ≥1 target OR ≥1 import (mirrors server check in `g3api.go`); a scan type is selected; custom content (if used) parses cleanly.
3. For each import row, POST the local file to `/file/upload` to get back a file ID. **Bounded parallel, cap 4** — imports typically arrive as same-tool batches (the picker is tool-first), and serial uploads of e.g. 8 large nmap XMLs noticeably block the wizard. Implemented with a buffered channel as a semaphore.
4. Replace each import path in the script with its returned file ID (mirrors `g3cli` `ScanCmd.Run`).
5. POST the assembled script to `/scan/start`.
6. On 200, dismiss the overlay; the new scan appears in the left panel via the WS push.
7. On 4xx/5xx, show the server error in a banner inside the overlay so the operator can correct without losing what they typed.

## Logs viewer

Replaces the right pane (left scan list stays). Reached via `[L]` on a selected scan in the dashboard.

```
┌─ Logs · 7d2a-3f1b-… ───────────────────────────  ● polling 2s (paused on blur) ─┐
│ Task: a1b2-…  nmap-fast                                           [↑↓] tasks    │
│                                                                                 │
│  10:42:01 [INFO]  Starting nmap scan against 192.168.1.1                        │
│  10:42:03 [INFO]  Nmap scan report for 192.168.1.1                              │
│  10:42:03 [INFO]  Host is up (0.00033s latency).                                │
│  10:42:04 [INFO]  Not shown: 998 closed tcp ports (reset)                       │
│  10:42:04 [INFO]  PORT    STATE SERVICE                                         │
│  10:42:04 [INFO]  22/tcp  open  ssh                                             │
│  10:42:04 [INFO]  80/tcp  open  http                                            │
│  ...                                                                            │
│                                                                                 │
│ [PgUp/PgDn] scroll  [G] follow tail  [S] save to file  [Esc] back               │
└─────────────────────────────────────────────────────────────────────────────────┘
```

- Task picker at the top: `↑↓` cycles through this scan's tasks; current task name shown. On entry, picks the most recently active task by default.
- Polls `/scan/logs` for `(scanID, taskID)` every 2s while focused. Stops when the underlying scan reaches a terminal state.
- *V1 limitation:* the `/scan/logs` API has no incremental cursor, so the pane re-fetches the whole log and dedupes client-side. Logs are small enough in practice for this to be fine. When WS log streaming lands later, this becomes a subscription.
- `[G]` toggles "follow tail": when on, the viewport sticks to the bottom on each refresh; auto-disables if the operator scrolls up. Standard `tail -f` behavior.
- `[S]` saves the current task's log to a file via the standard file-picker overlay in save-mode. Format matches `g3cli logs` (timestamped lines, ANSI bold separators between tasks for multi-task saves).
- `[Esc]` returns to the dashboard's right pane (per-task table).

## Report viewer

Replaces the right pane. Reached via `[R]` on a selected scan.

```
┌─ Report · 7d2a-3f1b-… ──────────────────────────────────────────────────────────┐
│                                                                                 │
│  # Golismero3 Scan Report                                                       │
│                                                                                 │
│  ## Targets                                                                     │
│  - 192.168.1.1                                                                  │
│  - example.com                                                                  │
│                                                                                 │
│  ## Findings                                                                    │
│                                                                                 │
│  ### High — Outdated SSH                                                        │
│  Host **192.168.1.1** is running OpenSSH 7.4 …                                  │
│                                                                                 │
│  ...                                                                            │
│                                                                                 │
│ [PgUp/PgDn] scroll  [S] save…  [Esc] back                                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

- One-shot fetch from `/scan/report` on entry. No polling — the server generates reports on demand, not as a stream.
- Rendered through Glamour with `auto` style (light/dark by terminal background) into a `bubbles/viewport`.
- If the server returns a non-empty `errors` field on the report payload (parsing errors during generation), show it in a yellow banner at the top of the pane — the report still rendered, just with caveats.
- `[S]` opens a save-as overlay (file-picker in save-mode). **V1 saves only Markdown** — the raw text from `/scan/report`, no Glamour transformation. The terminal-rendered ANSI form is for reading, not for saving.

## Data flow & API touchpoints

| Trigger | Endpoint / WS | Cadence | tea.Msg | Owning model |
|---|---|---|---|---|
| App start | `/scan/list` + `/scan/progress` | once | `ScanListSnapshot` | `App` (seeds dashboard) |
| App start | `/plugin/list` | once, cached for session | `PluginsLoaded` | `App` |
| App start | `/ws` `scanprogress` subscribe | persistent | `ScanProgressUpdate` | `App` (broadcast to `ScanList`) |
| WS drop | `/scan/progress` | 3s polling fallback while reconnecting | `ScanListSnapshot` | `App` |
| Scan selected, detail focused | `/scan/tasks/status` | 2s while focused; off on terminal | `TaskStatusUpdate` | `ScanDetail` |
| Logs pane focused on `(scanID, taskID)` | `/scan/logs` | 2s while focused; off on terminal | `LogChunk` | `LogsPane` |
| Report pane opened | `/scan/report` | once | `ReportLoaded` | `ReportPane` |
| Wizard submit, per import | `/file/upload` | once per file, parallel cap 4 | `FileUploaded` | `WizardOverlay` |
| Wizard submit, after uploads | `/scan/start` | once | `ScanStarted` | `WizardOverlay` |
| Cancel confirm | `/scan/stop` | once | `ScanCancelRequested` | `App` |
| Delete confirm | `/scan/stop` then `/scan/delete` | once each (mirrors `g3cli rm`) | `ScanDeleted` | `App` |

**Three load-bearing rules:**

1. **The polling layer is one component.** `internal/client/poll.go` exposes `Poller(ctx, interval, fetchFn, sendFn)` that a model spins up via `tea.Cmd` when its pane gains focus and tears down on blur or terminal state. Every poll site uses it. When WS streaming for tasks/logs lands later, each polling caller swaps to a WS subscription via the same `client` package — no UI changes.

2. **WS reconnect is a state machine.** `App` owns one `wsConnection` value with states `Connecting → Connected → Disconnected → Reconnecting`. State transitions emit `tea.Msg`s the header consumes for the dot color. Reconnect loop sleeps backoff `1s, 2s, 4s, 8s, 16s, 30s` capped, and the polling fallback runs in parallel during the gap. Any `Connected` transition cancels the polling fallback.

3. **No data caches across panes.** Each pane fetches what it needs when focused. No shared in-memory store of scan data, task lists, or logs. Avoids stale-data bugs; keeps memory footprint small; keeps the code small. The one exception is the `/plugin/list` response (small, used by the wizard, used by future filter work) — cached at `App` level for the session.

## Pipeline registry

```go
type Pipeline struct {
    Name    string  // basename without .pipeline extension
    Source  string  // "embedded" | "user" | "custom"
    Content string  // raw pipeline-only content (tool|tool lines)
}

func Load() ([]Pipeline, error)
```

- **Embedded:** `//go:embed *.pipeline` packs `network.pipeline` and `web.pipeline` into the binary. The `.pipeline` files live alongside `pipelines.go` inside `src/g3tui/internal/pipelines/` — embed patterns can't traverse `..`, so co-locating the files with the embed directive is the simplest valid layout. Nothing else in the codebase references these files.
- **User:** scans `$G3_PIPELINES_DIR` if set, else `~/.config/g3tui/pipelines/`. Any `*.pipeline` file becomes a `Pipeline`.
- **Merge rule:** user files override embedded ones with the same basename. Order returned: alphabetical by name. `Custom…` is appended by the wizard view, not by the registry.
- **Validation at load time:** call `g3lib.ParseScript` on `mode parallel\n` + `target placeholder\n` + content. Drop the file with a `log.Warning("skipping invalid pipeline file: %s", path)` rather than crashing. A bad user pipeline file does not prevent the TUI from launching.

## Configuration

Reuses `g3cli`'s exact pattern:

- `g3lib.LoadDotEnvFile()` on startup (so the same `.env` works for both binaries).
- `G3_API_BASEURL` — required.
- `G3_API_WSURL` — required.
- `G3_API_TOKEN` — required.
- `G3_PIPELINES_DIR` — optional override of `~/.config/g3tui/pipelines/`.
- `G3_CMD_LOG_LEVEL` — optional, mirrors `g3cli`.

Hard-fail at launch with a clear message if any required var is missing.

## Error handling

Five classes:

1. **API errors (4xx/5xx with structured body).** Server returns `g3lib.APIResponse{Status:"error", Data:"<message>"}`. Surface the `Data` string to the operator in a banner inside the pane that triggered the call (wizard banner for submit failures, dashboard banner for cancel/delete failures). No modal alerts — they break flow.

2. **Network errors (server unreachable, DNS, timeout).** Same banner pattern, message `"Server unreachable: <error>"`. The dashboard's connection indicator goes red; the WS reconnect machine takes over for the WS side. HTTP polls fail silently in their pane (no banner spam for transient blips) but bump a failure count; after 3 consecutive failures the affected pane shows a "stale data" indicator.

3. **WS errors mid-session.** Silent reconnect with exponential backoff up to 30s, polling fallback active during the gap, indicator shows `◌ reconnecting…`. No banners.

4. **Initial connection failure.** Distinct from mid-session: if the *first* WS dial fails or returns 401, show a full-screen error with the cause and a `[R]etry / [Q]uit` prompt. Do not proceed to the dashboard with a broken connection.

5. **Local errors (file pickers, malformed input, etc.).** Inline errors in the affected widget — red border on the input field, single-line message under the textarea. No modal blockers.

**Global rule:** the TUI never crashes on a server error. The only `os.Exit` paths are: missing required env var at launch, hard signal (`Ctrl-C` twice), or fatal Bubble Tea runtime error.

## File structure

```
src/g3tui/
├── go.mod                        # replace directives → ../g3lib, ../g3log
├── go.sum
├── g3tui.go                      # main(); env loading; App.Run
├── internal/
│   ├── client/
│   │   ├── client.go             # http wrappers around g3lib.MakeApiRequest
│   │   ├── poll.go               # generic polling helper
│   │   ├── stream.go             # ws scanprogress subscription + reconnect FSM
│   │   ├── messages.go           # tea.Msg types (ScanProgressUpdate, …)
│   │   └── *_test.go
│   ├── pipelines/
│   │   ├── pipelines.go          # Load(), merge embedded + user
│   │   ├── embed.go              # //go:embed *.pipeline
│   │   ├── network.pipeline      # shipped scan type
│   │   ├── web.pipeline          # shipped scan type
│   │   └── pipelines_test.go
│   └── ui/
│       ├── app.go                # top-level tea.Model
│       ├── scanlist.go           # left panel
│       ├── scandetail.go         # right pane: task table
│       ├── logs.go               # right pane: log viewer
│       ├── report.go             # right pane: report viewer (glamour)
│       ├── wizard.go             # new-scan overlay (form, file picker, custom)
│       ├── styles.go             # lipgloss styles, single source of truth
│       ├── keys.go               # key.Binding declarations
│       └── *_test.go
└── README.md                     # short usage doc
```

## Build integration

- `src/Makefile` gains a `../bin/g3tui` target alongside the existing six binaries; same recipe shape (`go build -o ../bin/g3tui ./g3tui`). No pre-build step needed — `//go:embed pipelines/*.pipeline` reads directly from the committed directory.
- Top-level `Makefile` `bin` target gains `g3tui` as a dependency.
- `make install` adds the symlink `/usr/bin/g3tui`.
- `make clean` removes the `g3tui` binary along with the rest.
- `golangci-lint` config: same as the other Go modules (correctness-only, no formatting enforcement, per project convention).
- `src/g3tui` is added to the existing `make lint` and `go test ./...` invocations.

## Verification & testing

**Tests are user-owned.** Implementing agents do not write unit tests, integration tests, or test scaffolding for `g3tui`. The user writes whatever tests they want at their own cadence, separately from the implementation plan.

**Agent-side verification per task** is strictly the toolchain — no runtime behavior checks:

- `go build` (compile success).
- `golangci-lint run ./...` (correctness lints; project's correctness-only config, no formatting enforcement).

Running the binary, sourcing `.env`, hitting the live API, or starting/stopping `docker compose` services is user-owned. Agents do not perform any behavioral verification. The user runs the binary at their own cadence and reports back if behavior diverges from the spec.

If/when the user does write tests later, they would naturally split along the existing package boundaries — `internal/client/` against `httptest.Server`, `internal/pipelines/` for `Load()` cases, `internal/ui/` via `teatest` substring assertions. None of that is in scope for the implementation plan.

## Future API improvements

These are server-side changes, out of scope for `g3tui` v1, but called out so they can be planned together with future API extension tiers:

- **Extend `/plugin/list` response to surface full plugin metadata.** Today it returns `{name, url, description}`. Useful additions for clients: `has_importer` flag (lets the wizard filter the import-tool dropdown to importers only), supported file extensions for each importer (lets the file picker pre-filter), fingerprint metadata, condition/merger metadata. None of this is sensitive; it's already in `g3lib.G3Plugin`.
- **Per-task cancellation primitive.** `/scan/task/stop` or similar; Tier 3 of the existing API extensions plan. Would unblock per-task cancel in `g3tui`.
- **Incremental log cursor on `/scan/logs`.** A `since=<index>` parameter would let the log viewer fetch deltas instead of full re-fetch + dedupe. Becomes redundant once WS log streaming (Tier 1-2) lands, so may not be worth doing standalone.

## Future report formats

V1 saves only Markdown. Anticipated additions, fitting into the existing save-as overlay as additional dropdown choices:

- **JSON** — the underlying scan data objects (potentially via `/scan/data`), useful for downstream tooling.
- **Obsidian-flavored Markdown** — `[[wikilinks]]`, frontmatter, callouts. Same renderer pipeline, different post-processing.

No architectural change required — the save flow already abstracts format selection.

## Out of scope (reaffirmed)

- `g3cli` modifications.
- Raw scan-data export (`g3cli export` stays the way to do this).
- Plugin listing as a top-level workflow (the wizard's tool dropdown is the only consumer).
- Per-task cancellation.
- Multi-user features (auth/ACL/per-user history) — `g3api` is internal-only per the existing architectural direction; user-facing concerns belong in the future BFF.
- Mouse support. Keyboard-only for v1. Bubble Tea supports mouse if we want it later.
- Configurable themes. `auto` Glamour style and a single Lip Gloss palette for v1.
