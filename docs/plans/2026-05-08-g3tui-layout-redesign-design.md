# g3tui Layout Redesign

**Status:** Implemented and tested 2026-05-08. Implementation plan: [`2026-05-08-g3tui-layout-redesign-implementation.md`](2026-05-08-g3tui-layout-redesign-implementation.md). This document was updated post-implementation to reflect a few details that were settled or refined during testing — call-outs are in the relevant sections.

**Scope:** Restructure the g3tui dashboard from a fixed-width two-pane layout into a responsive three-panel layout, fix scrolling for long lists, redesign the per-task view with explicit columns and lifecycle-aware information, and add a server-side fallback so the per-task view stays meaningful for terminated scans.

**Predecessors:** [`2026-05-06-g3tui-design.md`](2026-05-06-g3tui-design.md), [`2026-05-06-g3tui-implementation.md`](2026-05-06-g3tui-implementation.md). This document supersedes the layout/columns sections of those for the dashboard's right pane.

---

## Problem statement

The current dashboard has three problems exposed during real use:

1. **Layout assumes an implicit minimum terminal width.** Below ~146 cols the task table wraps mid-row; above it the content is left-anchored and the right side is wasted empty space. The minimum was never designed — it's the accidental sum of column widths picked column-by-column.

2. **No scrolling.** Both `ScanList.View()` and `ScanDetail.View()` `JoinVertical` every entry into a single tall string. Long scan lists or long task lists silently clip past the terminal's viewport. There is no cursor-aware viewport in either panel.

3. **The right pane is meaningless for terminated scans.** Per-task data is stored in Redis and expires shortly after a scan completes. The current right-pane view becomes empty for any scan that has been finished long enough for Redis cleanup, even though the SQL `logs` table still has the underlying data. The same view also conflates running-task concerns ("is this stuck") and terminal-task concerns ("how long did it take") into one ambiguous time column.

A separate, related concern: the right pane only shows tasks. Operators need to see logs of running tasks for diagnostics — currently this requires pressing `l` to open a separate full-screen log viewer, which loses the dashboard context.

## Goals and non-goals

**Goals**

- Replace the right pane with a stacked two-panel layout: tasks (top) + logs (bottom). Logs panel is structural-only in this work; implementation deferred to Tier 3.
- Make the layout responsive: column visibility and content shape adapt to terminal width with explicit priority rules, no accidental minima.
- Add cursor-aware scrolling to both the scan list and the tasks table.
- Reshape the tasks columns to fit the actual operator use cases: per-task identity, lifecycle state, tool, runtime, last-seen-activity, optionally worker.
- Restore meaningful tasks data for terminated scans by reconstructing missing fields server-side from existing SQL log markers (no schema change needed).
- Add Tab/Shift-Tab cycling between panels with per-panel keybind scoping and a clear active-panel indicator.

**Non-goals**

- The log panel implementation. Reserved as a Tier 3 task — this work commits to its existence in the layout but does not render live log content.
- Movable panel boundaries and preference persistence. Tracked as a future iteration; defaults are fixed for this work.
- Schema changes to the `logs` table. The reconstruction pathway uses prefix-tagged log lines that already exist (`[g3:dispatch]`, `[g3:start]`, `[g3:done]`, `[g3:cancel]`).
- Splitting the tasks table into separate "running" and "terminated" sub-tables. A single state-aware table avoids spontaneous layout shifts as tasks transition between states.

## Architecture

### Three-panel layout

```
┌─ g3tui ─────────────────────────────────  ● connected · srv=… ─┐
│ Scans         │ Tasks                                          │
│               │                                                │
│ ▸ <scan-1>    │  ID  STATE  TOOL  TIME  LAST SEEN  WORKER      │
│   FINISHED 100│  ...                                           │
│   <scan-2>    │  ...                                           │
│   RUNNING  42 │                                                │
│   ...         │                                                │
│               ├────────────────────────────────────────────────│
│               │ Logs (Tier 3 — empty in this iteration)        │
│               │                                                │
│               │                                                │
├───────────────┴────────────────────────────────────────────────┤
│ tab cycle · n new · ↑↓ select · l logs · r report · ...        │
└────────────────────────────────────────────────────────────────┘
```

Three panels:

- **Scans** (left column, full-height) — the existing scan list.
- **Tasks** (right side, top) — the per-task table for the focused scan.
- **Logs** (right side, bottom) — live log preview for the focused task. **Inert in this work; Tier 3 implements it.**

Vertical split between Tasks and Logs: 50/50 of the right side's available rows. Tasks panel takes the top half, Logs (inert in this work) takes the bottom half.

Horizontal split between Scans column and the right side: scan list at a fixed width sufficient for the full UUID + cursor prefix + chrome (44 cols when terminal width ≥ 100, else `width/2`). Same as today's value; no change.

### Active-panel focus

Exactly one panel is "focused" at any time. Focus determines:

- Which panel's cursor is rendered.
- Which panel receives ↑↓ and other navigation keystrokes.
- Which panel's keybinds appear in the footer.
- Which selection is the implicit target of action keys (`l` logs, `r` report, `c` cancel, `d` delete).

Focus indicator: the focused panel's border uses a brighter/accented color (the unfocused panels keep the existing faint-gray `PaneBorder`). The focused-border style is added to `styles.go`.

Default focus on launch: **Scans**. Tab cycles forward (Scans → Tasks → Logs → Scans), Shift-Tab cycles backward.

While a modal (wizard, confirm overlay) is open, Tab is captured by the modal — panel cycling is suspended until the modal dismisses, at which point focus restores to the panel that was focused when the modal opened.

While the scan list's filter mode is active, the filter textinput owns letter keys but **not Tab** — Tab still cycles panels. When focus leaves the Scans panel, the filter exits typing mode (cursor leaves the textinput) but the filter string itself is preserved and continues to apply to the visible scan list. Tab-back to Scans returns to filter typing mode at the existing cursor position.

### Per-panel keybind scoping

| Key | Behavior |
|---|---|
| `tab` / `shift+tab` | Cycle focus forward / backward. **Global.** |
| `↑` `↓` `k` `j` | Navigate cursor within focused panel. |
| `pgup` / `pgdn` | Page within focused panel (Tasks and Logs). |
| `g` / `G` | Jump to top / bottom of focused panel (Tasks and Logs). |
| `/` | Filter (Scans only). |
| `enter` | Action on focused-panel cursor (e.g., on Scans = no-op since selection is implicit; on Tasks: see below). |
| `l` | Open logs viewer for: focused task if Tasks panel; selected scan if Scans panel; selected task if Logs panel. |
| `r` | Open report viewer for the selected scan. (Always scan-scoped.) |
| `c` / `d` | Cancel / delete the selected scan. (Always scan-scoped — these are scan-level actions, not task-level.) |
| `n` | New scan wizard. **Global.** |
| `q` / `ctrl+c` | Quit. **Global.** |
| `?` | Help overlay. **Global.** |

Scan- vs. task-scoped action keys are deliberate: there is no "cancel task" API today (per the existing API extensions plan, that's a future server change). `l` is the one key whose behavior depends on focused panel — pressing `l` while Tasks is focused opens the logs for *that specific task*, while pressing `l` while Scans is focused opens the multi-task log viewer for the scan.

## Tasks panel — column design

Six columns, fixed left-to-right order, two priority tiers:

| Order | Column | Priority | Width (default) | Floor width | Floor header | Collapse policy |
|---|---|---|---|---|---|---|
| 1 | TASK ID | **0** | 36 (full UUID) | 6 | `ID📎` | Middle-ellipsis: 36 → 15 → 9 → 6 chars (preserves prefix and suffix). |
| 2 | STATE | **0** | 10 | 2 | `▶` | Single emoji glyph (see emoji map below). |
| 3 | TOOL | **0** | 12 | 2 | `⚙` | End-ellipsis; floor as `⚙` glyph in header, `…` in values. |
| 4 | TIME | **0** | 8 | 2 | `⏰` | Same. |
| 5 | LAST SEEN | **0** | 10 | 2 | `👀` | Same. (Default width is 10 — must be ≥ visual width of `LAST SEEN` to avoid premature header-collapse.) |
| 6 | WORKER | **1** | 16 | — | — | Hidden entirely when narrow (no collapse). |

The floor headers replace the full text when the column is at floor width. They were settled during implementation testing — full text wraps to a second visual row at narrow widths, and that overflow propagates upward through the layout.

**TIME** = runtime. For RUNNING tasks: time elapsed since `[g3:start]`. For terminal tasks: total time between `[g3:start]` and `[g3:done]`. Same value during the running window, just stops accumulating at completion. Header label: `TIME`.

**LAST SEEN** = time since the most recent log line was emitted. For RUNNING tasks: a stuck-detection signal — a small value means the task is actively producing output, a large value flags a stall. For terminal tasks: not applicable; rendered as `-`. Header label: `LAST SEEN`.

These two columns are deliberately separate even though both relate to "time": they encode different operator concerns and overlapping them into one state-aware column was rejected during brainstorming as a UX trap.

**WORKER** is the only auto-hidden column. Useful for distinguishing parallel runs of the same tool and inferring source IP, but not essential at-a-glance.

### State emoji map

| State | Glyph | Color | Notes |
|---|---|---|---|
| RUNNING | ▶ | green | Active task |
| DONE | ✓ | blue | Successful completion |
| ERROR | ✗ | red | Task failed |
| CANCELED | ⊘ | dim/faint | User-initiated stop |
| WAITING | ⌛ | yellow | Pre-dispatch (rare in task list, mostly scan-level) |
| DISPATCHED | … | cyan | Sent to worker, not yet started |

Glyphs over letters because:
- More information per character (state is encoded by glyph shape).
- Avoids the DONE / DISPATCHED letter collision.
- Cleanly i18n-stable — translation of state labels (if ever added) doesn't affect the glyph.
- Falls back gracefully even on terminals with limited Unicode support (the glyphs in this set are all in basic Unicode planes).

If a terminal does not render a glyph cleanly, the underlying issue is terminal config, not our problem to solve at the application layer. Color provides redundant signaling.

### Width math

- All six columns visible: `36 + 10 + 12 + 8 + 10 + 16 + 5 spaces = 97 cols of content`. Plus pane chrome (border 2 + padding 2): **101-col detail pane**.
- WORKER hidden: `36 + 10 + 12 + 8 + 10 + 4 spaces = 80 cols`. Plus chrome: **84-col detail pane**.
- Combined with the 44-col scan-list panel: **145 cols** for full layout, **128 cols** for "WORKER hidden" mode.
- Below 128 cols total, P0 columns progressively collapse. Floor: `6 + 2 + 2 + 2 + 2 + 4 spaces = 18 cols of content`, **22-col detail pane**, **66-col total**. At this point the table conveys identity but little else; user can resize for details.
- Below 60 cols total or 14 rows tall, the dashboard short-circuits to a "terminal too small" warning (see "Minimum-size guard" below).

Collapse order when narrowing past WORKER-hidden:

1. TIME → end-ellipsis at floor (2 cols, `⏰` header).
2. LAST SEEN → end-ellipsis at floor (2 cols, `👀` header).
3. TOOL → end-ellipsis at floor (2 cols, `⚙` header).
4. STATE → glyph at floor (2 cols, single-letter color-coded glyph).
5. TASK ID → middle-ellipsis through breakpoints (15 → 9 → 6).

Order chosen so secondary-information columns degrade first; identity (TASK ID) is the last to lose readability.

### Header collapse contract

Each column's header text is rendered through `headerForColumn(width, full, floor)`:

- If the column's allocated width is ≥ the visual width of the full header text → render the full text.
- Otherwise → render the floor header (the emoji-bearing abbreviation from the column table above).

The `full` widths in the table above are the column's default; they must be ≥ `lipgloss.Width(<full header text>)` to avoid the case where a column at "full" width is still narrower than its full header and prematurely collapses. (`LAST SEEN`'s default was bumped from 8 to 10 during testing for exactly this reason.)

All width measurements use `lipgloss.Width` (visual columns), not `len` (bytes), so emoji and other multi-byte content padded correctly.

### Tasks panel cursor and scrolling

The Tasks panel becomes navigable: `↑↓` / `j` / `k` move a row cursor; `pgup` / `pgdn` page; `g` / `G` jump to top / bottom. Selection drives `l` / future task-scoped actions.

The panel uses a `bubbles/viewport`-backed scrollable region. Cursor stays in view: when the cursor approaches the top/bottom edge, the viewport scrolls to keep at least one row visible above/below.

**On focus change** (e.g., user picks a different scan), the cursor resets to the first task row; viewport scrolls to top.

**On task list refresh** (the 2-second poll receiving updated data): cursor preserves the previously-focused task by ID if it still exists. If the previously-focused task is gone (rare — only happens when a scan transitions from live to terminated and Redis purges before the reconstruction fallback fills in), the cursor moves to the row at the same numeric index, or to the last row if the list shrunk below that index.

### Detail-pane title collapse

The Detail pane's title is `Detail · <scan-id> · <status>`. At narrow pane widths the full UUID makes this title wrap to multiple visual rows; that overflow grows the pane past its allocated height (lipgloss `Height` is a minimum, not a maximum), and the overflow propagates upward — eventually pushing the top header bar (`g3tui · srv=…`) off the top of the terminal.

To prevent this, `renderDetailTitle(scanID, status, maxWidth)` progressively collapses the title until it fits within `maxWidth` visual columns. Candidates, in order of preference:

1. `Detail · <full UUID> · STATUS`
2. `Detail · <UUID-mid 15 chars> · STATUS`
3. `Detail · <UUID-min 9 chars> · STATUS`
4. `Detail · <UUID-floor 6 chars> · STATUS`
5. `Detail · STATUS`
6. `Detail`
7. (rune-truncated last-resort)

The first candidate whose `lipgloss.Width` is ≤ `maxWidth` is used. Result: the title is always exactly one row, regardless of pane width.

## Scan list — scrolling and progressive ID collapse

Same scrolling treatment for the scan list (cursor-aware viewport via `bubbles/viewport`). Two-rows-per-entry layout: UUID on row 1, status pill + progress on row 2.

The UUID line uses the same `collapseID(scanID, idWidth)` middle-ellipsis helper as the task table's TASK ID column: 36 → 15 → 9 → 6 char widths. `idWidth` is computed per-frame as `panel.width - 6` (border + padding + cursor prefix), floored at `colTaskIDFloor`. Below the floor the panel is in degenerate-narrow territory — the minimum-size guard catches this case before rendering.

(Implementation note: stuck with `bubbles/viewport` rather than migrating to `bubbles/list`. The custom two-line rendering and inline filter UX would have fought `list`'s defaults; the viewport wrapper was the smaller delta from existing code. The trade-off is documented in the implementation plan's "Open questions" resolution.)

## Minimum-size guard

Below 60 cols wide or 14 rows tall, `App.View` short-circuits to a centered `⚠ terminal too small` warning rendered with `BannerWarn` style. No panels, no chrome, no content rendering at all.

Why these thresholds, not lower:

- **Width 60** = 30-col scan-list panel + 30-col right pane. The right pane needs ≥22 cols to fit the all-floor task layout (18 cols of content + 4 cols chrome); 30 leaves a comfortable margin.
- **Height 14** = header (1) + footer (1) + body (12), where body splits 6/6 between Tasks and Logs panels. Each panel needs at least 6 rows to render its title + spacer + minimal content within its border.

Below either threshold, the per-panel content row counts would exceed allocated heights, the overflow propagates via lipgloss-Height-as-minimum semantics, and the top of the screen gets pushed off. Rather than chase incremental layout-degradation tiers (hide Logs panel? collapse Tasks to a one-line summary?), we draw the line and stop trying — adding more layout-reflow tiers would also violate the "no spontaneous layout shifts in response to non-user actions" rule.

## Server-side: terminated-scan reconstruction

The `/scan/tasks/status` server handler currently returns an empty entries list when Redis has expired the per-scan task state, even though the SQL `logs` table still has structured lifecycle markers. Operator-visible symptom: the right pane is empty for old completed scans.

The `logs` table contains, for every task that ran:

- `[g3:dispatch] task=<id> tool=<name>` (from scanner)
- `[g3:start] task=<id> worker=<name>` (from worker)
- `[g3:done] task=<id> state=<STATE>` (from worker)
- `[g3:cancel] task=<id>` (from scanner, when applicable)

Plus a `timestamp` column on every row.

Adding a server-side helper `ReconstructTaskStatesFromLogs(scanid)` that runs a prefix-LIKE filter over `logs` and parses these markers into `TaskStatusEntry` shapes lets `/scan/tasks/status` return the same structured response for terminated scans as it does for live ones — Tool, Worker, State, and timing are all recoverable.

```sql
SELECT taskid, timestamp, text FROM logs
WHERE scanid = ? AND text LIKE '[g3:%'
ORDER BY taskid, timestamp ASC
```

Per-task: ~3-4 marker rows. For a scan with 100 tasks: ~300-400 rows scanned, no JOIN. Negligible cost.

**Edge cases** the reconstructor handles explicitly:

- Task dispatched but worker never picked up (no `[g3:start]`): synthesized state = `DISPATCHED`, completion timestamp = null, runtime = null.
- Task started but never reported done (worker crashed mid-run): state = `UNKNOWN` (a new lifecycle bucket meaning "we don't know"). Display rendering: dim italic, similar to CANCELED.
- Multiple `[g3:done]` rows: take the latest.
- Stray text matching `[g3:` from tool output: defensive — only the **first occurrence** of `[g3:dispatch]` per task is treated as authoritative. Anything later that looks like a marker is ignored.

The handler updates so:

```
if Redis returns non-empty taskStates → use Redis (live path, unchanged).
else → use ReconstructTaskStatesFromLogs (terminated path, new fallback).
```

The TUI receives the same `ScanTaskStatusResponse` shape either way and renders identically.

This is documented as **Path 2-lite** in the brainstorm — no schema change, no client-side parsing duplication, just a server-side fallback that uses what's already there.

## Color and style additions

`styles.go` gains:

- **`PaneBorderFocused`** — accented border color (probably the `AppTitle` purple, `lipgloss.Color("63")`) for the currently-focused panel.
- **State glyphs** are inline strings, not styles. The existing `StatusRunning`, `StatusFinished`, etc. are reused as foreground colors applied to the glyph string.
- **`StatusUnknown`** — added for the worker-crashed-mid-run reconstruction case.

## Out of scope (reaffirmed)

- Log panel rendering (Tier 3).
- Movable boundaries / preference persistence.
- Schema migration for tasks metadata (rejected in favor of Path 2-lite).
- Per-task cancellation (waiting on server-side API extension).
- Mouse support.

## Risks

- **Glyph rendering on minimal terminals** — extreme low-end terminals (e.g., headless systems, certain SSH multiplexers) may render some glyphs as boxes or fallbacks. Color provides redundancy. If this becomes a real complaint, a future config flag could swap glyphs for letters.
- **Reconstruction false positives from tool-stdout containing `[g3:` literals** — defensive parsing (first-occurrence-per-task) bounds the worst-case to "phantom early row" rather than UI corruption. Documented in code near the parser.
- **Logs panel content overflow on narrow heights above the threshold** — the placeholder body text wraps when the right pane is narrow. Hasn't shown up as a visible bug in testing, and the minimum-size guard catches the worst cases. Tier 3 will replace the placeholder with a viewport-backed log preview that handles its own bounding.

## Resolved during implementation

- **Bubbles/list vs. viewport choice for the scan list** — went with viewport. Custom two-line rendering and inline filter UX would have fought `bubbles/list`'s defaults; viewport-wrapping was the smaller delta.
- **Floor headers** — settled on `ID📎` / `▶` / `⚙` / `⏰` / `👀` for the five P0 columns. (Originally `LAST👀` for LAST SEEN; reduced to just `👀` after testing.)
- **`colLastSeenFull`** — bumped from 8 to 10 because `LAST SEEN` is 9 visual cols and 8-cols-at-full would prematurely collapse.
- **`padRight` width measurement** — uses `lipgloss.Width` (visual cols) not `len` (bytes); bytes mis-pad emoji content.
- **Detail-pane title 1-row guarantee** — added `renderDetailTitle` with progressive collapse; full-UUID titles were wrapping to multiple visual rows on narrow panes and overflowing the layout.
- **Scan-list UUID collapse** — same `collapseID` middle-ellipsis treatment as the task table.
- **Minimum-size guard** — 60×14 threshold below which the dashboard renders only `⚠ terminal too small`.

## Out of plan / future iterations

- The 250 ms debounce for log fetches is a Tier 3 concern; flagged here so the relevant skill knows it when log panel is implemented.

---

## Verification scope (agent-side)

Per project rule (`feedback_tests_are_user_owned.md`): agent verification is strictly `go build` plus `golangci-lint run ./...`. No behavioral testing, no `bin/g3tui` runs, no `docker compose` interactions.

Behavioral verification of the responsive layout (multiple terminal widths) and the reconstruction pathway (terminated-scan view) is user-owned.
