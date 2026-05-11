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
	"golismero.com/g3lib"
	"golismero.com/g3tui/internal/client"
)

// logsViewerGenCounter is a process-wide monotonic counter used to
// stamp each LogsViewer instance and its messages, so a tick from a
// just-closed viewer cannot be mistaken for a tick of a new viewer
// opened for the same scanID.
var logsViewerGenCounter int

// logsViewerTickMsg is the periodic 2 s re-poll for the viewer. The
// Generation and ScanID fields together identify which open instance
// the tick belongs to, so a stale tick from a just-closed viewer is
// not misrouted to a freshly-opened one for the same scanID.
type logsViewerTickMsg struct {
	Generation int
	ScanID     string
}

// logsViewerChunkMsg wraps a client.ScanLogChunk with the generation
// the fetch was issued at, so a chunk returning after the viewer has
// closed and a fresh viewer has been opened for the same scanID
// cannot be misattributed.
type logsViewerChunkMsg struct {
	Generation int
	Chunk      client.ScanLogChunk
}

// logsViewerClosedMsg fires when the user presses Esc. App tears down
// the overlay and restores focus to the previously-focused panel.
type logsViewerClosedMsg struct{}

// LogsViewer is the full-screen scan-level logs overlay opened by `l`.
// It is constructed each time the user opens the viewer and discarded
// when they Esc out — there is no long-lived state to preserve across
// open/close cycles.
type LogsViewer struct {
	cli *client.Client

	scanID     string
	scanStatus g3lib.G3SCANSTATUS
	generation int
	entries    []g3lib.LogEntry
	toolByTask map[string]string
	toolWidth  int // cached visual width of the widest known [tool] prefix, capped at logsViewerToolCap

	viewport viewport.Model

	width  int
	height int
}

const logsViewerToolCap = 12

func NewLogsViewer(cli *client.Client, scanID string, scanStatus g3lib.G3SCANSTATUS) LogsViewer {
	logsViewerGenCounter++
	v := LogsViewer{
		cli:        cli,
		scanID:     scanID,
		scanStatus: scanStatus,
		generation: logsViewerGenCounter,
		toolByTask: map[string]string{},
		toolWidth:  1,
		viewport:   viewport.New(0, 0),
	}
	return v
}

func (v *LogsViewer) SetSize(w, h int) {
	v.width = w
	v.height = h
	inner := w - 4 // border 2 + padding 1+1
	chrome := 2
	titleRow := 1
	spacerRow := 1
	contentHeight := max(1, h-chrome-titleRow-spacerRow)
	v.viewport.Width = inner
	v.viewport.Height = contentHeight
	v.applyContent()
}

// SetScanStatus updates the viewer's cached scan status. Called by App
// when a ScanListSnapshot / ScanProgressUpdate reports a new status
// for the viewer's scan, so the next tick's isTerminal() check sees
// the current state and the polling loop can wind down for finished
// scans without waiting for the user to close the viewer.
func (v *LogsViewer) SetScanStatus(status g3lib.G3SCANSTATUS) {
	v.scanStatus = status
}

// InitCmd kicks off the first fetch and (for non-terminal scans)
// schedules the 2 s tick implicitly via the chunk handler. Called
// once by App immediately after constructing the viewer.
func (v LogsViewer) InitCmd() tea.Cmd {
	return v.fetchNowCmd()
}

func (v LogsViewer) Help() []key.Binding {
	return []key.Binding{Keys.PgUp, Keys.PgDn, Keys.GotoTop, Keys.GotoBottom, Keys.Back}
}

func (v LogsViewer) Update(msg tea.Msg) (LogsViewer, tea.Cmd) {
	switch m := msg.(type) {
	case logsViewerTickMsg:
		if m.Generation != v.generation || m.ScanID != v.scanID {
			return v, nil // stale
		}
		if isTerminal(v.scanStatus) {
			return v, nil
		}
		return v, v.fetchNowCmd()

	case logsViewerChunkMsg:
		if m.Generation != v.generation {
			return v, nil // stale chunk from a previous viewer instance
		}
		if m.Chunk.ScanID != v.scanID {
			return v, nil // defensive — generation guard should already cover this
		}
		if m.Chunk.Err != nil {
			// Keep last successful render; re-arm on the regular cadence.
			return v, v.scheduleNextTickCmd()
		}
		wasAtBottom := v.viewport.AtBottom()
		v.entries = m.Chunk.Entries
		v.rebuildToolMap()
		v.applyContent()
		if wasAtBottom {
			v.viewport.GotoBottom()
		}
		if isTerminal(v.scanStatus) {
			return v, nil
		}
		return v, v.scheduleNextTickCmd()

	case tea.KeyMsg:
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
		}
		return v, nil
	}
	return v, nil
}

func (v LogsViewer) View() string {
	title := AppTitle.Render(v.renderTitle(v.width - 4))
	body := v.viewport.View()
	return PaneBorderFocused.Width(v.width - 2).Height(v.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, title, "", body),
	)
}

func (v LogsViewer) renderTitle(maxWidth int) string {
	status := string(v.scanStatus)
	if status == "" {
		status = "?"
	}
	candidates := []string{
		fmt.Sprintf("Logs · %s · %s", v.scanID, status),
		fmt.Sprintf("Logs · %s · %s", collapseID(v.scanID, colTaskIDMid), status),
		fmt.Sprintf("Logs · %s · %s", collapseID(v.scanID, colTaskIDMin), status),
		fmt.Sprintf("Logs · %s · %s", collapseID(v.scanID, colTaskIDFloor), status),
		fmt.Sprintf("Logs · %s", status),
		"Logs",
	}
	for _, c := range candidates {
		if lipgloss.Width(c) <= maxWidth {
			return c
		}
	}
	runes := []rune("Logs")
	if len(runes) > maxWidth {
		return string(runes[:maxWidth])
	}
	return "Logs"
}

// rebuildToolMap walks the current entries slice and (re)populates the
// taskID → tool map by parsing [g3:dispatch] markers. Defensive: only
// the first dispatch marker per task is treated as authoritative;
// later occurrences are ignored (matches the reconstructor's rule).
// Also updates toolWidth.
func (v *LogsViewer) rebuildToolMap() {
	v.toolByTask = map[string]string{}
	for _, e := range v.entries {
		if !strings.HasPrefix(e.Text, "[g3:dispatch]") {
			continue
		}
		if _, ok := v.toolByTask[e.TaskID]; ok {
			continue
		}
		if tool := parseDispatchTool(e.Text); tool != "" {
			v.toolByTask[e.TaskID] = tool
		}
	}
	v.toolWidth = 1 // at least "?"
	for _, t := range v.toolByTask {
		w := lipgloss.Width(t)
		if w > v.toolWidth {
			v.toolWidth = w
		}
	}
	if v.toolWidth > logsViewerToolCap {
		v.toolWidth = logsViewerToolCap
	}
}

// parseDispatchTool extracts "<name>" from a "[g3:dispatch] task=<id>
// tool=<name>" marker line. Returns "" if the marker is malformed.
// Tool names contain no whitespace, so we read up to the next space.
func parseDispatchTool(text string) string {
	const toolKey = "tool="
	i := strings.Index(text, toolKey)
	if i < 0 {
		return ""
	}
	rest := text[i+len(toolKey):]
	if j := strings.IndexAny(rest, " \t"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// applyContent re-renders the viewport content from the current entries
// slice and tool map. Each line is "HH:MM:SS [tool] <stripped text>"
// where [tool] is end-ellipsised to toolWidth.
func (v *LogsViewer) applyContent() {
	if len(v.entries) == 0 {
		v.viewport.SetContent(ListItemDimmed.Render("(no log lines yet)"))
		return
	}
	var b strings.Builder
	for i, e := range v.entries {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(formatViewerLine(e.Timestamp, v.toolFor(e.TaskID), v.toolWidth, e.Text))
	}
	v.viewport.SetContent(b.String())
}

func (v LogsViewer) toolFor(taskID string) string {
	if t, ok := v.toolByTask[taskID]; ok {
		return t
	}
	return "?"
}

// formatViewerLine renders one stream line. tool is the per-task name
// from the map (or "?" for lines whose dispatch marker hasn't been
// seen yet); width is the column the [tool] cell pads to.
func formatViewerLine(ts int64, tool string, width int, text string) string {
	when := time.Unix(ts, 0).Format("15:04:05")
	cell := tool
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
	bracketed := "[" + LogTool.Render(cell) + "]" + strings.Repeat(" ", pad)
	return LogTimestamp.Render(when) + " " + bracketed + "  " + g3lib.StripAnsi(text)
}

func (v LogsViewer) fetchNowCmd() tea.Cmd {
	cli := v.cli
	sid := v.scanID
	gen := v.generation
	return func() tea.Msg {
		entries, err := cli.GetScanLogs(context.Background(), sid)
		return logsViewerChunkMsg{
			Generation: gen,
			Chunk:      client.ScanLogChunk{ScanID: sid, Entries: entries, Err: err},
		}
	}
}

func (v LogsViewer) scheduleNextTickCmd() tea.Cmd {
	sid := v.scanID
	gen := v.generation
	return tea.Tick(logsPollInterval, func(time.Time) tea.Msg {
		return logsViewerTickMsg{Generation: gen, ScanID: sid}
	})
}
