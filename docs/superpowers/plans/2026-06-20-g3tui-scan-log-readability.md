# g3tui Scan-Log Readability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the g3tui full-screen scan-log viewer readable for scans with many concurrent same-tool tasks — disambiguate interleaved live lines, and export in g3cli's task-grouped format.

**Architecture:** Two independent changes, both confined to `src/g3tui/internal/ui/logsviewer.go` and both fed entirely from the viewer's in-memory `v.entries []g3lib.LogEntry` (no new queries, no server/protocol changes). (1) The live view keeps the server's chronological order but prefixes each line with `[tool·<short-taskid>]` instead of `[tool]`. (2) Export (`S`) regroups entries by TaskID into g3cli-style per-task blocks.

**Tech Stack:** Go 1.25, Bubble Tea (`viewport`), lipgloss. No new dependencies.

## Global Constraints

- **Single file:** all changes are in `src/g3tui/internal/ui/logsviewer.go`. No other file changes.
- **No new queries / no protocol changes:** everything renders from `v.entries`.
- **Verification is lint + build only.** Per project convention, tests and binary runs are user-owned — this plan does NOT add test files or run g3tui. Each task verifies by compiling the `g3tui` module and running golangci-lint (correctness linters only; no formatting enforcement).
- **Git is user-owned.** This plan does NOT include `git commit` steps; the user stages and commits at the end.
- **Short TaskID = first 8 characters** of the UUID (the `[:8]` convention already used at `logsviewer.go:445` and by g3cli).
- **Separator = exactly 80 dashes** (matches g3cli at `g3cli.go:651`).
- **Export is plain text** — no ANSI escape codes; full timestamps via `time.Unix(ts,0).String()`.

---

### Task 1: Live view — `[tool·<short-taskid>]` line prefix

**Files:**
- Modify: `src/g3tui/internal/ui/logsviewer.go` — add a `shortTaskID` helper, change `viewerLinePrefix` signature/body, update its single caller in `applyContent`.

**Interfaces:**
- Consumes: `g3lib.LogEntry{Timestamp int64, ScanID, TaskID, Text string}`; existing `v.toolFor(taskID) string`; existing `wrapLogLine(prefix string, prefixWidth int, body string, width int, wrap bool) string`; styles `LogTool`, `LogTimestamp`.
- Produces: `shortTaskID(id string) string` (first ≤8 chars); `viewerLinePrefix(ts int64, tool, shortID string, toolWidth int) (string, int)`.

- [ ] **Step 1: Add the `shortTaskID` helper**

Add this function near the other small helpers in `logsviewer.go` (e.g. directly above `viewerLinePrefix`, currently around line 385):

```go
// shortTaskID returns the first 8 characters of a task UUID for use as a
// compact per-line identity tag. Shorter ids (shouldn't happen for valid
// uuid4) are returned whole.
func shortTaskID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
```

- [ ] **Step 2: Replace `viewerLinePrefix`**

Replace the existing `viewerLinePrefix` (currently `logsviewer.go:389-408`, the version taking `(ts int64, tool string, width int)`) in full with:

```go
// viewerLinePrefix builds the styled "HH:MM:SS [tool·xxxxxxxx]  " prefix for
// a log row and returns its visible column width. The tool portion is
// end-ellipsised to toolWidth and right-padded so the body column aligns
// across rows; the 8-char short task id is fixed width and never truncated,
// so concurrent tasks of the same tool stay distinguishable.
func viewerLinePrefix(ts int64, tool, shortID string, toolWidth int) (string, int) {
	when := time.Unix(ts, 0).Format("15:04:05")
	cell := tool
	if lipgloss.Width(cell) > toolWidth {
		runes := []rune(cell)
		if toolWidth <= 1 {
			cell = "…"
		} else {
			cell = string(runes[:toolWidth-1]) + "…"
		}
	}
	pad := toolWidth - lipgloss.Width(cell)
	if pad < 0 {
		pad = 0
	}
	bracketed := "[" + LogTool.Render(cell) + "·" + LogTool.Render(shortID) + "]" + strings.Repeat(" ", pad)
	prefix := LogTimestamp.Render(when) + " " + bracketed + "  "
	// 8 (timestamp) + 1 (space) + 1 ("[") + toolWidth (tool cell) + 1 ("·")
	// + 8 (short id) + 1 ("]") + 2 ("  ") = 22 + toolWidth
	return prefix, 22 + toolWidth
}
```

- [ ] **Step 3: Update the caller in `applyContent`**

In `applyContent` (currently `logsviewer.go:331`), replace the single `viewerLinePrefix` call line:

```go
		prefix, prefixWidth := viewerLinePrefix(e.Timestamp, v.toolFor(e.TaskID), v.toolWidth)
```

with:

```go
		prefix, prefixWidth := viewerLinePrefix(e.Timestamp, v.toolFor(e.TaskID), shortTaskID(e.TaskID), v.toolWidth)
```

- [ ] **Step 4: Build the g3tui module**

Run:
```bash
cd src/g3tui && go build ./...
```
Expected: exits 0, no output. (Confirms the new signature, the single caller, and the `·` literal all compile.)

- [ ] **Step 5: Lint the changed file**

Run:
```bash
cd src/g3tui && golangci-lint run ./internal/ui/...
```
Expected: no findings for `logsviewer.go`. (Correctness linters only; formatting is not enforced in this project.)

---

### Task 2: Export — regroup into g3cli-style per-task blocks

**Files:**
- Modify: `src/g3tui/internal/ui/logsviewer.go` — rewrite `renderForSave`.

**Interfaces:**
- Consumes: `v.entries []g3lib.LogEntry`; `v.scanID string`; `g3lib.StripAnsi(string) string`.
- Produces: `renderForSave() string` returning the full export body (grouped by task, plain text). `writeLogs` and `openSavePicker` are unchanged and still call `renderForSave`.

- [ ] **Step 1: Replace `renderForSave`**

Replace the existing `renderForSave` (currently `logsviewer.go:349-383`, the flat-dump version) in full with:

```go
// renderForSave returns the viewer's entries formatted for [S] save, grouped
// by task into g3cli-style blocks (separator, Scan ID, Task ID, separator,
// then each line as "<full-timestamp>: <text>", then a trailing blank line).
// Tasks appear in first-appearance order; each task's lines keep their
// existing order. Plain text — no ANSI styling. Built entirely from
// v.entries, so there is no re-query.
func (v LogsViewer) renderForSave() string {
	if len(v.entries) == 0 {
		return ""
	}
	const sep = "--------------------------------------------------------------------------------"

	order := make([]string, 0)
	byTask := make(map[string][]g3lib.LogEntry)
	for _, e := range v.entries {
		if _, ok := byTask[e.TaskID]; !ok {
			order = append(order, e.TaskID)
		}
		byTask[e.TaskID] = append(byTask[e.TaskID], e)
	}

	var b strings.Builder
	for _, taskID := range order {
		b.WriteString(sep)
		b.WriteByte('\n')
		b.WriteString("--- Scan ID: " + v.scanID)
		b.WriteByte('\n')
		b.WriteString("--- Task ID: " + taskID)
		b.WriteByte('\n')
		b.WriteString(sep)
		b.WriteByte('\n')
		for _, e := range byTask[taskID] {
			b.WriteString(time.Unix(e.Timestamp, 0).String())
			b.WriteString(": ")
			b.WriteString(g3lib.StripAnsi(e.Text))
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return b.String()
}
```

- [ ] **Step 2: Build the g3tui module**

Run:
```bash
cd src/g3tui && go build ./...
```
Expected: exits 0, no output. (Confirms `lipgloss` is still used elsewhere in the file — it is, by `viewerLinePrefix` and `renderTitle` — so removing the old `renderForSave`'s lipgloss use does not leave an unused import.)

- [ ] **Step 3: Lint the changed file**

Run:
```bash
cd src/g3tui && golangci-lint run ./internal/ui/...
```
Expected: no findings for `logsviewer.go`. In particular `ineffassign`/`unused` should be clean — the rewrite removes the old per-line tool-cell width code that `renderForSave` previously duplicated.

---

### Final verification (whole module)

- [ ] **Step 1: Build all g3tui packages**

Run:
```bash
cd src/g3tui && go build ./...
```
Expected: exits 0.

- [ ] **Step 2: Build the binary via the repo target (optional sanity)**

Run:
```bash
cd src && make ../bin/g3tui
```
Expected: produces `bin/g3tui`, exits 0.

- [ ] **Step 3: Hand off to the user for commit**

The code change is complete and compiles/lints clean. The user stages and commits (git is user-owned). Suggested message:
`fix(g3tui): disambiguate live scan-log lines by task and export in g3cli grouped format`

---

## Notes for the implementer

- **Do not** add `_test.go` files or run g3tui against a live server — verification in this project is lint + build only.
- **Do not** run `git add`/`git commit` — leave the working tree changed for the user to commit.
- The `·` in the prefix is U+00B7 (middle dot); `lipgloss.Width("·")` is 1, so column math is unaffected.
- `toolWidth` and `rebuildToolMap` are deliberately untouched — the tool column width is reused as-is for the tool portion of the combined cell.
- If `go build` reports an unused `lipgloss` import after Task 2, that means another lipgloss user was removed unexpectedly — it should NOT happen (`viewerLinePrefix` and `renderTitle` still use it). Investigate rather than blindly deleting the import.
