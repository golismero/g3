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
	"github.com/charmbracelet/x/ansi"
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

// logsTickMsg is the periodic re-poll for the current binding (interval per Config.PollInterval).
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

// LogsPanel is the dashboard's bottom-right panel. It renders a live
// preview of log output for whichever task the Tasks-panel cursor is
// on. Polling is governed by the App-emitted binding messages; the
// panel never reaches into the client layer outside of the fetch
// commands defined here.
type LogsPanel struct {
	cli          *client.Client
	pollInterval time.Duration

	scanID     string
	taskID     string
	scanStatus g3lib.G3SCANSTATUS
	generation int // invalidates pending debounce/tick callbacks on rebind

	lines    []g3lib.TaskLogLine
	viewport viewport.Model
	wrap     bool // off by default: preview pane prioritizes density

	width   int
	height  int
	focused bool
}

func NewLogsPanel(cli *client.Client, pollInterval time.Duration) LogsPanel {
	return LogsPanel{cli: cli, pollInterval: pollInterval, viewport: viewport.New(0, 0)}
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
// has focus. PgUp/PgDn still work (handled in Update) but aren't
// advertised — the footer line is tight.
func (l LogsPanel) Help() []key.Binding {
	if len(l.lines) == 0 {
		return nil
	}
	return []key.Binding{Keys.Up, Keys.Down, Keys.GotoTop, Keys.GotoBottom, Keys.WrapToggle}
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
		case key.Matches(m, Keys.WrapToggle):
			wasAtBottom := l.viewport.AtBottom()
			l.wrap = !l.wrap
			l.applyContent()
			if wasAtBottom {
				l.viewport.GotoBottom()
			}
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
// slice, applying the per-line formatting and ANSI strip. When wrap is
// on, long bodies hard-wrap to the viewport width with a hanging indent
// under the timestamp column.
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
		when := time.Unix(ln.Timestamp, 0).Format("15:04:05")
		prefix := LogTimestamp.Render(when) + "  "
		const prefixWidth = 10 // "HH:MM:SS" (8) + "  " (2)
		body := g3lib.StripAnsi(ln.Text)
		b.WriteString(wrapLogLine(prefix, prefixWidth, body, l.viewport.Width, l.wrap))
	}
	l.viewport.SetContent(b.String())
}

// wrapLogLine emits one log row. When wrap is false the prefix and body
// are concatenated as-is (the viewport clips overflow). When wrap is
// true the body is hard-wrapped to the remaining column budget and
// continuation rows are hanging-indented by prefixWidth blanks so the
// body column stays aligned. Shared between LogsPanel and LogsViewer.
func wrapLogLine(prefix string, prefixWidth int, body string, width int, wrap bool) string {
	if !wrap {
		return prefix + body
	}
	bodyWidth := width - prefixWidth
	if bodyWidth < 1 {
		bodyWidth = 1
	}
	wrapped := ansi.Hardwrap(body, bodyWidth, true)
	rows := strings.Split(wrapped, "\n")
	if len(rows) == 1 {
		return prefix + rows[0]
	}
	pad := strings.Repeat(" ", prefixWidth)
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString(rows[0])
	for _, r := range rows[1:] {
		b.WriteByte('\n')
		b.WriteString(pad)
		b.WriteString(r)
	}
	return b.String()
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
	return tea.Tick(l.pollInterval, func(time.Time) tea.Msg {
		return logsTickMsg{Generation: gen, ScanID: sid, TaskID: tid}
	})
}
