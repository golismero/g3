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

	"github.com/golismero/g3/src/g3"
	"github.com/golismero/g3/src/g3tui/internal/client"
)

// focusChangedMsg is dispatched by App whenever the scan list's selection
// changes (or the list arrives empty). ScanDetail consumes it to retarget
// its polling.
type focusChangedMsg struct {
	ScanID string
}

// ScanDetail renders the per-task table for the focused scan and drives
// its own /scan/tasks/status polling via tea.Tick chains. Polling pauses
// when the underlying scan reaches a terminal state.
type ScanDetail struct {
	cli          *client.Client
	pollInterval time.Duration

	scanID     string
	scanStatus g3.G3SCANSTATUS
	tasks      []g3.TaskStatusEntry
	cursor     int
	viewport   viewport.Model

	width   int
	height  int
	focused bool
}

func NewScanDetail(cli *client.Client, pollInterval time.Duration) ScanDetail {
	return ScanDetail{cli: cli, pollInterval: pollInterval, viewport: viewport.New(0, 0)}
}

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
	sd.applyContent()
}

// SelectedTaskID returns the TaskID of the currently-highlighted row,
// or "" when there is no selection. Used by App for task-scoped key
// actions (e.g., `l` opens logs for the selected task).
func (sd ScanDetail) SelectedTaskID() string {
	if sd.cursor < 0 || sd.cursor >= len(sd.tasks) {
		return ""
	}
	return sd.tasks[sd.cursor].TaskID
}

// SetFocused toggles the focused-border style. Called by App.applyFocus.
func (sd *ScanDetail) SetFocused(focused bool) {
	sd.focused = focused
}

func (sd ScanDetail) Update(msg tea.Msg) (ScanDetail, tea.Cmd) {
	switch m := msg.(type) {
	case focusChangedMsg:
		sd.scanID = m.ScanID
		sd.tasks = nil
		sd.scanStatus = ""
		sd.cursor = 0
		sd.applyContent()
		sd.viewport.GotoTop()
		if sd.scanID == "" {
			return sd, nil
		}
		return sd, sd.fetchNowCmd()

	case client.TaskStatusUpdate:
		if m.ScanID != sd.scanID {
			return sd, nil // stale tick from a previous focus
		}
		if m.Err != nil {
			// Transient HTTP failure — re-arm the chain at the regular
			// cadence rather than letting it die. State is preserved
			// (last successful poll's data stays visible). Per design's
			// "HTTP polls fail silently in their pane" rule.
			return sd, sd.fetchLaterCmd(sd.pollInterval)
		}
		// Preserve cursor across refreshes by task ID where possible.
		var prevID string
		if sd.cursor >= 0 && sd.cursor < len(sd.tasks) {
			prevID = sd.tasks[sd.cursor].TaskID
		}
		sd.scanStatus = m.Response.ScanStatus
		sd.tasks = m.Response.Tasks
		if prevID != "" {
			found := -1
			for i, t := range sd.tasks {
				if t.TaskID == prevID {
					found = i
					break
				}
			}
			if found >= 0 {
				sd.cursor = found
			} else if sd.cursor >= len(sd.tasks) {
				sd.cursor = max(0, len(sd.tasks)-1)
			}
		}
		if sd.cursor < 0 {
			sd.cursor = 0
		}
		sd.applyContent()
		sd.ensureCursorVisible()
		if isTerminal(sd.scanStatus) {
			return sd, nil
		}
		return sd, sd.fetchLaterCmd(sd.pollInterval)

	case tea.KeyMsg:
		if len(sd.tasks) == 0 {
			return sd, nil
		}
		switch {
		case key.Matches(m, Keys.Up):
			if sd.cursor > 0 {
				sd.cursor--
			}
			sd.applyContent()
			sd.ensureCursorVisible()
		case key.Matches(m, Keys.Down):
			if sd.cursor < len(sd.tasks)-1 {
				sd.cursor++
			}
			sd.applyContent()
			sd.ensureCursorVisible()
		case key.Matches(m, Keys.PgUp):
			sd.cursor = max(0, sd.cursor-sd.viewport.Height/2)
			sd.applyContent()
			sd.ensureCursorVisible()
		case key.Matches(m, Keys.PgDn):
			sd.cursor = min(len(sd.tasks)-1, sd.cursor+sd.viewport.Height/2)
			sd.applyContent()
			sd.ensureCursorVisible()
		case key.Matches(m, Keys.GotoTop):
			sd.cursor = 0
			sd.applyContent()
			sd.viewport.GotoTop()
		case key.Matches(m, Keys.GotoBottom):
			sd.cursor = len(sd.tasks) - 1
			sd.applyContent()
			sd.viewport.GotoBottom()
		}
		return sd, nil
	}
	return sd, nil
}

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

func (sd ScanDetail) fetchNowCmd() tea.Cmd {
	scanID := sd.scanID
	cli := sd.cli
	return func() tea.Msg {
		resp, err := cli.GetTaskStatus(context.Background(), scanID)
		return client.TaskStatusUpdate{ScanID: scanID, Response: resp, Err: err}
	}
}

func (sd ScanDetail) fetchLaterCmd(after time.Duration) tea.Cmd {
	scanID := sd.scanID
	cli := sd.cli
	return tea.Tick(after, func(time.Time) tea.Msg {
		resp, err := cli.GetTaskStatus(context.Background(), scanID)
		return client.TaskStatusUpdate{ScanID: scanID, Response: resp, Err: err}
	})
}

func isTerminal(s g3.G3SCANSTATUS) bool {
	switch s {
	case g3.G3_STATUS_FINISHED, g3.G3_STATUS_CANCELED, g3.G3_STATUS_ERROR:
		return true
	}
	return false
}

func emptyTaskMessage(s g3.G3SCANSTATUS) string {
	if s == "" {
		return "Loading tasks…"
	}
	// Neutral copy across all populated states. For RUNNING/WAITING
	// scans tasks may still appear; for terminal scans the data may
	// have expired from the backend cache. We can't tell which from
	// here, so we don't claim either way.
	return "No task information available."
}

// renderDetailTitle picks the longest "Detail · <id> · <status>"
// formulation that fits within maxWidth, progressively collapsing the
// scan ID via middle-ellipsis. If even the shortest formulation
// (status only) overflows, the result is rune-truncated. Crucial for
// keeping the Detail pane title to one row — when it wraps, the pane
// grows past its allocated height (lipgloss Height is a minimum), the
// overflow propagates upward, and the top-of-screen title bar gets
// pushed off-screen.
func renderDetailTitle(scanID, status string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	candidates := []string{
		fmt.Sprintf("Detail · %s · %s", scanID, status),
		fmt.Sprintf("Detail · %s · %s", collapseID(scanID, colTaskIDMid), status),
		fmt.Sprintf("Detail · %s · %s", collapseID(scanID, colTaskIDMin), status),
		fmt.Sprintf("Detail · %s · %s", collapseID(scanID, colTaskIDFloor), status),
		fmt.Sprintf("Detail · %s", status),
		"Detail",
	}
	for _, c := range candidates {
		if lipgloss.Width(c) <= maxWidth {
			return c
		}
	}
	// Below "Detail" — pane is degenerate. Rune-truncate the shortest
	// candidate so we still hand back something that fits.
	shortest := candidates[len(candidates)-1]
	runes := []rune(shortest)
	if len(runes) > maxWidth {
		shortest = string(runes[:maxWidth])
	}
	return shortest
}

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
	innerW := sd.width - 4 // border 2 + padding 1+1
	header := AppTitle.Render(renderDetailTitle(sd.scanID, string(sd.scanStatus), innerW))
	if len(sd.tasks) == 0 {
		body := ListItemDimmed.Render(emptyTaskMessage(sd.scanStatus))
		return border.Width(sd.width - 2).Height(sd.height - 2).Render(
			lipgloss.JoinVertical(lipgloss.Left, header, "", body),
		)
	}
	return border.Width(sd.width - 2).Height(sd.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			header,
			"",
			taskTableHeader(pickTaskLayout(innerW)),
			sd.viewport.View(),
		),
	)
}

// applyContent rebuilds viewport content from sd.tasks/cursor/width.
// Lives outside View so the persisted (not value-receiver-copy) viewport
// gets its `lines` slice populated — viewport.SetYOffset() clamps against
// len(lines) via maxYOffset(), so if Update sets the offset before
// content exists, every scroll request clamps to 0 and the cursor moves
// without the viewport following.
func (sd *ScanDetail) applyContent() {
	if len(sd.tasks) == 0 {
		sd.viewport.SetContent("")
		return
	}
	layout := pickTaskLayout(sd.width - 4)
	rows := make([]string, 0, len(sd.tasks))
	for i, t := range sd.tasks {
		rows = append(rows, taskTableRow(t, i == sd.cursor, layout))
	}
	sd.viewport.SetContent(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

// Column geometry. Order is the visual order. Priority 0 columns
// collapse before being hidden (they always render, even at the floor
// width with a header glyph and "…" / "-" values); priority 1 columns
// hide entirely when the panel is too narrow.
//
// Floor sizes are chosen to fit both the floor header text and the
// floor value representation. Emoji glyphs in the header may render at
// 1 or 2 visual columns depending on the terminal — the floor widths
// here accommodate the wider 2-column rendering, so the column stays
// honest across emoji width quirks. Padding uses lipgloss.Width (not
// byte length) to handle multi-byte emoji content correctly.
const (
	colTaskIDFull  = 36
	colTaskIDMid   = 15 // first ~8 + ellipsis + last ~6
	colTaskIDMin   = 9  // first ~4 + ellipsis + last ~4
	colTaskIDFloor = 6  // floor header "ID📎" (4 visual cols, padded); first 2 + ellipsis + last 2 for values

	colStateFull  = 10
	colStateFloor = 2 // floor header "▶" padded to 2 cols (also handles 2-col-wide emojis)

	colToolFull  = 12
	colToolFloor = 2

	colTimeFull  = 8
	colTimeFloor = 2

	colLastSeenFull  = 10 // ≥ visual width of "LAST SEEN" (9 cols)
	colLastSeenFloor = 2  // floor header "👀" (2 visual cols)

	colWorkerFull = 16
	// WORKER has no floor — it hides entirely.
)

// Floor header texts. Per the layout spec:
//
//	TASK ID    "ID📎"     — short word + paperclip
//	STATE      "▶"        — green play (matches RUNNING glyph)
//	TOOL       "⚙"        — gears
//	TIME       "⏰"        — alarm clock
//	LAST SEEN  "LAST👀"   — short word + eyes
//
// The full headers ("TASK ID", "STATE", etc.) are used at full width;
// floor headers replace them when the column is at its floor width.
const (
	hdrTaskIDFull   = "TASK ID"
	hdrTaskIDFloor  = "ID📎"
	hdrStateFull    = "STATE"
	hdrStateFloor   = "▶"
	hdrToolFull     = "TOOL"
	hdrToolFloor    = "⚙"
	hdrTimeFull     = "TIME"
	hdrTimeFloor    = "⏰"
	hdrLastSeenFull  = "LAST SEEN"
	hdrLastSeenFloor = "👀"
	hdrWorkerFull    = "WORKER"
)

// taskLayout is the resolved per-frame column geometry chosen by
// pickTaskLayout based on available content width.
type taskLayout struct {
	idWidth       int
	stateExpanded bool // false = single-glyph
	toolWidth     int
	timeWidth     int
	lastSeenWidth int
	workerVisible bool
}

// pickTaskLayout chooses column widths to fit the available content
// area (excluding pane border + padding). Order of operations:
//  1. Hide WORKER if the full layout doesn't fit.
//  2. Progressively collapse P0 columns: TIME → LAST SEEN → TOOL → STATE → TASK ID.
//  3. If still wider than available, accept clipping (we're below
//     minimum supported terminal width).
func pickTaskLayout(contentWidth int) taskLayout {
	const sepFull = 5     // 6 columns => 5 separator spaces
	const sepNoWorker = 4 // 5 columns => 4 separators

	l := taskLayout{
		idWidth:       colTaskIDFull,
		stateExpanded: true,
		toolWidth:     colToolFull,
		timeWidth:     colTimeFull,
		lastSeenWidth: colLastSeenFull,
		workerVisible: true,
	}
	stateW := func() int {
		if l.stateExpanded {
			return colStateFull
		}
		return colStateFloor
	}
	totalWidth := func() int {
		seps := sepNoWorker
		w := l.idWidth + stateW() + l.toolWidth + l.timeWidth + l.lastSeenWidth
		if l.workerVisible {
			w += colWorkerFull
			seps = sepFull
		}
		return w + seps
	}

	if totalWidth() <= contentWidth {
		return l
	}
	// 1. Hide WORKER.
	l.workerVisible = false
	if totalWidth() <= contentWidth {
		return l
	}
	// 2. Collapse columns in order: TIME → LAST SEEN → TOOL → STATE → TASK ID.
	l.timeWidth = colTimeFloor
	if totalWidth() <= contentWidth {
		return l
	}
	l.lastSeenWidth = colLastSeenFloor
	if totalWidth() <= contentWidth {
		return l
	}
	l.toolWidth = colToolFloor
	if totalWidth() <= contentWidth {
		return l
	}
	l.stateExpanded = false
	if totalWidth() <= contentWidth {
		return l
	}
	// Step the TASK ID through its three intermediate widths.
	l.idWidth = colTaskIDMid
	if totalWidth() <= contentWidth {
		return l
	}
	l.idWidth = colTaskIDMin
	if totalWidth() <= contentWidth {
		return l
	}
	l.idWidth = colTaskIDFloor
	return l // floor reached; may still overflow if contentWidth is below minimum supported
}

func taskTableHeader(layout taskLayout) string {
	parts := []string{
		padRight(headerForColumn(layout.idWidth, hdrTaskIDFull, hdrTaskIDFloor), layout.idWidth),
	}
	if layout.stateExpanded {
		parts = append(parts, padRight(hdrStateFull, colStateFull))
	} else {
		parts = append(parts, padRight(hdrStateFloor, colStateFloor))
	}
	parts = append(parts, padRight(headerForColumn(layout.toolWidth, hdrToolFull, hdrToolFloor), layout.toolWidth))
	parts = append(parts, padRight(headerForColumn(layout.timeWidth, hdrTimeFull, hdrTimeFloor), layout.timeWidth))
	parts = append(parts, padRight(headerForColumn(layout.lastSeenWidth, hdrLastSeenFull, hdrLastSeenFloor), layout.lastSeenWidth))
	if layout.workerVisible {
		parts = append(parts, padRight(hdrWorkerFull, colWorkerFull))
	}
	return TableHeader.Render(strings.Join(parts, " "))
}

func taskTableRow(t g3.TaskStatusEntry, selected bool, layout taskLayout) string {
	timeStr, lastSeenStr := taskTimeFields(t)

	idCell := collapseID(t.TaskID, layout.idWidth)

	var stateCell string
	if layout.stateExpanded {
		stateCell = taskStateStyle(t.State).Render(padRight(strings.ToUpper(t.State), colStateFull))
	} else {
		stateCell = taskStateStyle(t.State).Render(padRight(taskStateGlyph(t.State), colStateFloor))
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

// collapseID applies middle-ellipsis truncation, preserving prefix and
// suffix per the spec. For widths under 5 chars there's no room for a
// meaningful ellipsis — return the leading prefix.
func collapseID(id string, width int) string {
	if len(id) <= width {
		return padRight(id, width)
	}
	if width < 5 {
		return id[:width]
	}
	keep := width - 1 // one char for the middle ellipsis
	prefix := keep / 2
	suffix := keep - prefix
	return id[:prefix] + "…" + id[len(id)-suffix:]
}

// collapseEnd returns s padded or end-truncated to width. At width 1,
// returns "…" with the value entirely hidden — the floor-collapse
// signal that there's information here you can resize the terminal to
// see. The "-" sentinel for "no value" is preserved instead of being
// replaced with "…".
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

// taskTimeFields returns (TIME, LAST SEEN) display strings per the
// spec's state-aware rules:
//
//	RUNNING:    TIME = active since start; LAST SEEN = since last log
//	terminal:   TIME = StartTS → CompleteTS duration; LAST SEEN = "-"
//	DISPATCHED: TIME = "-"; LAST SEEN = "-"
//	UNKNOWN:    TIME = StartTS → now (best-effort); LAST SEEN = since last log
func taskTimeFields(t g3.TaskStatusEntry) (timeStr, lastSeenStr string) {
	state := strings.ToUpper(t.State)
	switch state {
	case "RUNNING":
		if t.StartTS > 0 {
			timeStr = humanDurationFromDur(time.Since(time.Unix(t.StartTS, 0)))
		} else {
			timeStr = "-"
		}
		lastSeenStr = humanAgo(t.LastLogTS)
	case "DONE", "WARNING", "ERROR", "CANCELED", "FINISHED":
		switch {
		case t.StartTS > 0 && t.CompleteTS > 0:
			timeStr = humanDurationFromDur(time.Duration(t.CompleteTS-t.StartTS) * time.Second)
		case t.StartTS > 0 && t.LastLogTS > 0:
			// Reconstructed path: no CompleteTS, approximate from logs.
			timeStr = humanDurationFromDur(time.Duration(t.LastLogTS-t.StartTS) * time.Second)
		default:
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

// taskStateGlyph returns the single-character lifecycle indicator for
// a state. Combined with taskStateStyle's color, it conveys state in
// 1 col when the layout is constrained.
func taskStateGlyph(state string) string {
	switch strings.ToUpper(state) {
	case "RUNNING":
		return "▶"
	case "DONE", "FINISHED":
		return "✓"
	case "WARNING":
		return "⚠"
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

// padRight pads s to width with spaces if visually shorter; returns s
// unchanged if visually wider. Uses lipgloss.Width so multi-byte and
// wide-emoji content padded correctly (byte-length padding under-pads
// emoji and over-pads ASCII). Long values break column alignment for
// that one row, which is the honest trade-off vs. truncating the value
// with a "…".
func padRight(s string, width int) string {
	visualWidth := lipgloss.Width(s)
	if visualWidth >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visualWidth)
}

// headerForColumn returns the full header text when the column is wide
// enough, or the floor (emoji-bearing) abbreviation otherwise.
func headerForColumn(width int, full, floor string) string {
	if width >= lipgloss.Width(full) {
		return full
	}
	return floor
}

func humanAgo(epoch int64) string {
	if epoch <= 0 {
		return "—"
	}
	d := time.Since(time.Unix(epoch, 0))
	return humanDurationFromDur(d)
}

func humanDurationFromDur(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func taskStateStyle(state string) lipgloss.Style {
	switch strings.ToUpper(state) {
	case "RUNNING":
		return StatusRunning
	case "DONE", "FINISHED":
		return StatusFinished
	case "WARNING":
		return StatusWarning
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

func (sd ScanDetail) Help() []key.Binding {
	return []key.Binding{Keys.Up, Keys.Down}
}
