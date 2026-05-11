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

// logsBindingChangedMsg is dispatched by App when the (scanID, taskID)
// binding for the inline Logs panel changes — either because the focused
// scan changed or because the Tasks-panel cursor moved. ScanID can be
// empty (no scan selected); TaskID can be empty (scan has no tasks yet).
type logsBindingChangedMsg struct {
	ScanID     string
	TaskID     string
	ScanStatus g3lib.G3SCANSTATUS
}

// logsDebounceFiredMsg fires 250 ms after a binding change and triggers
// the actual fetch. The Generation field guards against a stale debounce
// timer firing after the binding has changed again — only the latest
// generation triggers a fetch.
type logsDebounceFiredMsg struct {
	Generation int
	ScanID     string
	TaskID     string
}

// logsTickMsg is the periodic 2 s re-poll for the current binding.
// Generation guards against late ticks after a binding change.
type logsTickMsg struct {
	Generation int
	ScanID     string
	TaskID     string
}

// logsChunkMsg wraps a client.LogChunk with the generation the fetch
// was issued at, so the receiver can reject stale fetches that returned
// after a binding rebind cycled (sid, tid) back to the same value.
type logsChunkMsg struct {
	Generation int
	Chunk      client.LogChunk
}

// debounceDelay is the design-mandated cursor-thrash mitigation
// (docs/plans/2026-05-08-g3tui-layout-redesign-design.md).
const logsDebounceDelay = 250 * time.Millisecond

// pollInterval matches the cadence used by ScanList and ScanDetail.
const logsPollInterval = 2 * time.Second

// LogsPanel is the dashboard's bottom-right panel. It renders a live
// preview of log output for whichever task the Tasks-panel cursor is
// on. Polling is governed by the App-emitted binding messages; the
// panel never reaches into the client layer outside of the fetch
// commands defined here.
type LogsPanel struct {
	cli *client.Client

	scanID     string
	taskID     string
	scanStatus g3lib.G3SCANSTATUS
	generation int // invalidates pending debounce/tick callbacks on rebind

	lines    []g3lib.TaskLogLine
	viewport viewport.Model

	width   int
	height  int
	focused bool
}

func NewLogsPanel(cli *client.Client) LogsPanel {
	return LogsPanel{cli: cli, viewport: viewport.New(0, 0)}
}

func (l *LogsPanel) SetSize(w, h int) {
	l.width = w
	l.height = h
	inner := w - 4 // border 2 + padding 1+1
	chrome := 2
	titleRow := 1
	spacerRow := 1
	contentHeight := max(1, h-chrome-titleRow-spacerRow)
	l.viewport.Width = inner
	l.viewport.Height = contentHeight
	l.applyContent()
}

func (l *LogsPanel) SetFocused(focused bool) {
	l.focused = focused
}

// Help returns the keybinds shown in the footer when the Logs panel
// has focus. ↑↓/PgUp/PgDn/g/G are the documented in-panel navigation.
func (l LogsPanel) Help() []key.Binding {
	if len(l.lines) == 0 {
		return nil
	}
	return []key.Binding{Keys.Up, Keys.Down, Keys.PgUp, Keys.PgDn, Keys.GotoTop, Keys.GotoBottom}
}

func (l LogsPanel) Update(msg tea.Msg) (LogsPanel, tea.Cmd) {
	switch m := msg.(type) {
	case logsBindingChangedMsg:
		l.generation++
		l.scanID = m.ScanID
		l.taskID = m.TaskID
		l.scanStatus = m.ScanStatus
		l.lines = nil
		l.viewport.GotoTop()
		l.applyContent()
		if l.scanID == "" || l.taskID == "" {
			return l, nil
		}
		// Debounce: schedule the first fetch 250 ms out so rapid cursor
		// movement collapses into a single round-trip.
		gen := l.generation
		sid, tid := l.scanID, l.taskID
		return l, tea.Tick(logsDebounceDelay, func(time.Time) tea.Msg {
			return logsDebounceFiredMsg{Generation: gen, ScanID: sid, TaskID: tid}
		})

	case logsDebounceFiredMsg:
		if m.Generation != l.generation || m.ScanID != l.scanID || m.TaskID != l.taskID {
			return l, nil // stale debounce — binding has changed since
		}
		return l, l.fetchNowCmd()

	case logsTickMsg:
		if m.Generation != l.generation || m.ScanID != l.scanID || m.TaskID != l.taskID {
			return l, nil // stale tick
		}
		if isTerminal(l.scanStatus) {
			return l, nil // terminal scan: one-shot done, no further ticks
		}
		return l, l.fetchNowCmd()

	case logsChunkMsg:
		if m.Generation != l.generation {
			return l, nil // stale fetch — binding rebound since this fetch was issued
		}
		if m.Chunk.ScanID != l.scanID || m.Chunk.TaskID != l.taskID {
			return l, nil // defensive — generation guard should already cover this
		}
		if m.Chunk.Err != nil {
			// Transient HTTP failure: keep last successful render, re-arm
			// the chain at the regular cadence. LogsPanel doesn't emit
			// an error banner for poll failures — design rule.
			return l, l.scheduleNextTickCmd()
		}
		wasAtBottom := l.viewport.AtBottom()
		l.lines = m.Chunk.Log.Lines
		l.applyContent()
		if wasAtBottom {
			l.viewport.GotoBottom()
		}
		if isTerminal(l.scanStatus) {
			return l, nil
		}
		return l, l.scheduleNextTickCmd()

	case tea.KeyMsg:
		if !l.focused || len(l.lines) == 0 {
			return l, nil
		}
		switch {
		case key.Matches(m, Keys.Up):
			l.viewport.ScrollUp(1)
		case key.Matches(m, Keys.Down):
			l.viewport.ScrollDown(1)
		case key.Matches(m, Keys.PgUp):
			l.viewport.HalfPageUp()
		case key.Matches(m, Keys.PgDn):
			l.viewport.HalfPageDown()
		case key.Matches(m, Keys.GotoTop):
			l.viewport.GotoTop()
		case key.Matches(m, Keys.GotoBottom):
			l.viewport.GotoBottom()
		}
		return l, nil
	}
	return l, nil
}

func (l LogsPanel) View() string {
	border := PaneBorder
	if l.focused {
		border = PaneBorderFocused
	}
	title := AppTitle.Render(l.renderTitle(l.width - 4))
	body := l.viewport.View()
	return border.Width(l.width - 2).Height(l.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, title, "", body),
	)
}

// renderTitle picks the longest "Logs · <id> · <count>" formulation that
// fits within maxWidth, progressively collapsing the task ID. Same
// pattern as renderDetailTitle in scandetail.go — title must always be
// exactly one row to avoid pushing the panel past its allocated height.
func (l LogsPanel) renderTitle(maxWidth int) string {
	if l.taskID == "" {
		return "Logs"
	}
	count := fmt.Sprintf("%d lines", len(l.lines))
	if len(l.lines) == 1 {
		count = "1 line"
	}
	candidates := []string{
		fmt.Sprintf("Logs · %s · %s", l.taskID, count),
		fmt.Sprintf("Logs · %s · %s", collapseID(l.taskID, colTaskIDMid), count),
		fmt.Sprintf("Logs · %s · %s", collapseID(l.taskID, colTaskIDMin), count),
		fmt.Sprintf("Logs · %s · %s", collapseID(l.taskID, colTaskIDFloor), count),
		fmt.Sprintf("Logs · %s", count),
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

// applyContent rebuilds the viewport's content from the current lines
// slice, applying the per-line formatting and ANSI strip.
func (l *LogsPanel) applyContent() {
	if l.scanID == "" || l.taskID == "" {
		l.viewport.SetContent(ListItemDimmed.Render("(no task selected)"))
		return
	}
	if len(l.lines) == 0 {
		l.viewport.SetContent(ListItemDimmed.Render("(no log lines yet)"))
		return
	}
	var b strings.Builder
	for i, ln := range l.lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(formatLogLine(ln.Timestamp, ln.Text))
	}
	l.viewport.SetContent(b.String())
}

// formatLogLine renders one line as "HH:MM:SS  <stripped text>". Used
// by both the inline panel and the full-screen viewer (the viewer wraps
// the result with a [tool] prefix on top of this).
func formatLogLine(ts int64, text string) string {
	when := time.Unix(ts, 0).Format("15:04:05")
	return LogTimestamp.Render(when) + "  " + g3lib.StripAnsi(text)
}

func (l LogsPanel) fetchNowCmd() tea.Cmd {
	cli := l.cli
	sid, tid := l.scanID, l.taskID
	gen := l.generation
	return func() tea.Msg {
		log, err := cli.GetTaskLogs(context.Background(), sid, tid)
		return logsChunkMsg{
			Generation: gen,
			Chunk:      client.LogChunk{ScanID: sid, TaskID: tid, Log: log, Err: err},
		}
	}
}

func (l LogsPanel) scheduleNextTickCmd() tea.Cmd {
	gen := l.generation
	sid, tid := l.scanID, l.taskID
	return tea.Tick(logsPollInterval, func(time.Time) tea.Msg {
		return logsTickMsg{Generation: gen, ScanID: sid, TaskID: tid}
	})
}
