# g3tui scan-log readability fix — design

**Date:** 2026-06-20
**Status:** Approved (pending spec review)
**Scope:** `src/g3tui/internal/ui/logsviewer.go` only. No server, client-transport, or protocol changes.

## Problem

The full-screen scan-log viewer in g3tui (opened with `l`, the `LogsViewer`) renders an
unreadable mess for scans with many concurrent same-tool tasks. Exporting it (`S`) produces
a flat chronological dump that does not match the readable, task-grouped format `g3cli`
produces.

Root cause (confirmed by diffing an exported `incorrect.log` against a `g3cli`-exported
`correct.log` for the same scan):

- `LogsViewer` fetches `/scan/logs` in **scan-level mode** (empty `TaskID`,
  [`client.go:92`](../../../src/g3tui/internal/client/client.go#L92)), which the server
  returns as a single stream ordered `timestamp, id ASC`
  ([`g3api.go:762-777`](../../../src/g3api/g3api.go#L762), [`mysql.go:141`](../../../src/g3lib/mysql.go#L141)).
- `applyContent` and `renderForSave` render that stream verbatim with **no per-task grouping**.
- When N tasks of the same tool run concurrently and log within the same one-second tick, the
  ordering falls to the auto-increment `id` (worker insertion order), interleaving every task's
  multi-line output line-by-line. The only on-screen disambiguator is the `[tool]` tag, which is
  identical for all of them (e.g. 46 concurrent `dig` tasks).

This is a **presentation bug, not data loss** — the content is complete; only ordering/grouping
and per-line identity are wrong. (The 46 "missing" lines between the two files were just the
per-task trailing blank separator `g3cli` emits.)

`g3cli` is readable because it enumerates the scan's tasks, fetches `/scan/logs` **per task**,
and prints each task as a contiguous headed block
([`g3cli.go:528-661`](../../../src/g3cli/g3cli.go#L528-L661)).

## Decision

Fix g3tui locally — no architectural change, no extra queries. Two distinct use cases get two
distinct treatments, both fed entirely from the viewer's in-memory `v.entries []g3lib.LogEntry`
(each entry already carries `Timestamp`, `ScanID`, `TaskID`, `Text` —
[`mysql.go:23`](../../../src/g3lib/mysql.go#L23)):

1. **Live on-screen view** keeps the chronological interleave (good for tailing a running scan)
   but gains per-task identity in the line prefix.
2. **Export (`S`)** regroups by task into `g3cli`'s block layout, in memory, with no re-query.

A broader "expand WebSocket support so live data is pushed not polled" effort was explored and
**deferred** — the live view is fed by polling `/scan/logs`, and there is no WS log channel
today. That is out of scope here; see the WebSocket gap analysis captured in project memory.

## Change 1 — Live view: tool + short TaskID prefix

**Files/functions:** `applyContent` ([`:321`](../../../src/g3tui/internal/ui/logsviewer.go#L321)),
`viewerLinePrefix` ([`:389`](../../../src/g3tui/internal/ui/logsviewer.go#L389)).

- The prefix tool cell changes from `[tool]` to `[tool·xxxxxxxx]`, where `xxxxxxxx` is the first
  8 characters of `e.TaskID` (the `[:8]` convention already used for the save filename at
  [`:445`](../../../src/g3tui/internal/ui/logsviewer.go#L445) and by `g3cli`). Middle dot `·`
  (U+00B7) separates tool from task id.
- Ordering is unchanged — the server's `timestamp, id ASC` stream is rendered as received.
- The cell that gets ellipsised/padded becomes the **combined** `tool·xxxxxxxx` string. The
  existing width logic (`toolWidth`, the cap, the ellipsis-and-pad in `viewerLinePrefix`) is
  generalized to operate on this combined cell so the body column still aligns and `wrapLogLine`
  hanging-indent still works. The returned `prefixWidth` accounts for the combined cell width.
- `toolByTask` / `rebuildToolMap` are **untouched** — TaskID is already on every entry; no new
  marker parsing is introduced. `toolFor` still yields `"?"` until a task's `[g3:dispatch]`
  marker has been seen, in which case the prefix is `[?·xxxxxxxx]`.

Result:

```
18:57:35 [dig·b68cdcb1] ;; Got answer:
18:57:35 [dig·47b079cc] ;; Got answer:
18:57:35 [dig·b68cdcb1] ;; flags: qr rd ra; QUERY: 1, ANSWER: 2 ...
18:57:35 [dig·47b079cc] ;; flags: qr rd ra; QUERY: 1, ANSWER: 1 ...
```

The lines are still interleaved, but each one now declares which task it belongs to.

## Change 2 — Export: regroup into g3cli's block layout, in memory

**Files/functions:** `renderForSave` ([`:349`](../../../src/g3tui/internal/ui/logsviewer.go#L349)).
`writeLogs` ([`:455`](../../../src/g3tui/internal/ui/logsviewer.go#L455)) and `openSavePicker`
([`:439`](../../../src/g3tui/internal/ui/logsviewer.go#L439)) are unchanged — still no network
calls.

`renderForSave` is rewritten from a flat dump to a task-grouped renderer:

- Group `v.entries` by `TaskID`. Group order = **first-appearance order** of each TaskID in the
  chronological stream (deterministic). Within each group, lines keep their existing order.
- For each task, emit a block modeled on `g3cli`'s
  ([`g3cli.go:650-661`](../../../src/g3cli/g3cli.go#L650-L661)), in **plain text (no ANSI codes)**:
  - `----------------------------------------------------------------------------------------` (80 dashes)
  - `--- Scan ID: <ScanID>`
  - `--- Task ID: <TaskID>`
  - the 80-dash separator again
  - one line per entry: `<time.Unix(ts,0).String()>: <StripAnsi(text)>`
  - a trailing blank line
- The `--- Started:` / `--- Ended:` header lines that `g3cli` prints are **intentionally
  omitted**. The viewer has no separate task record, and deriving them from line timestamps is
  not worth the extra pass — the per-line timestamps already convey timing. This is the only
  intentional difference from `g3cli`; the result is similar enough.

Styling decision (resolved): **g3cli layout, plain text** — same headers/grouping/full
timestamps as `g3cli`, but without the raw `\033[1m` bold escape codes, so the saved `.log` is
clean in any editor.

## Edge cases

- **No entries:** `applyContent` keeps the existing `(no log lines yet)` dimmed message;
  `renderForSave` returns `""` (empty file). Unchanged behavior.
- **Task with no `[g3:dispatch]` marker yet:** tool resolves to `"?"`; prefix is `[?·xxxxxxxx]`
  (live) and the export header still has the real Scan/Task IDs.
- **Very long tool names:** the combined cell is subject to the same cap/ellipsis as today; the
  8-char task id is fixed width, so only the tool portion is truncated.

## Out of scope / non-goals

- No change to the server, `/scan/logs`, the client transport, or the WS protocol.
- No change to the per-task `LogsPanel` (it already shows a single task).
- No re-query on export; no new MQTT/WS channels.
- WebSocket-push expansion (task-status / log streaming) is explicitly deferred.

## Verification

Per project conventions, verification is **lint + build only** (`make bin`, golangci-lint for
the `g3tui` module); tests and binary runs are user-owned. The author will not run g3tui or hit
a live server.
