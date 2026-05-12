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
