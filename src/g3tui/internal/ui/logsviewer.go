package ui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/golismero/g3/src/g3lib"
	"github.com/golismero/g3/src/g3tui/internal/client"
)

// logsViewerGenCounter is a process-wide monotonic counter used to
// stamp each LogsViewer instance and its messages, so a tick from a
// just-closed viewer cannot be mistaken for a tick of a new viewer
// opened for the same scanID.
var logsViewerGenCounter int

// logsViewerTickMsg is the periodic re-poll for the viewer (interval per Config.PollInterval). The
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

	scanID       string
	scanStatus   g3lib.G3SCANSTATUS
	generation   int
	entries      []g3lib.LogEntry
	toolByTask   map[string]string
	toolWidth    int          // cached visual width of the widest known [tool] prefix, capped at logsViewerToolCap
	pollInterval time.Duration

	viewport viewport.Model
	wrap     bool // on by default: full-screen viewer prioritizes readability

	picker        *FilePicker
	banner        string
	bannerStyle   lipgloss.Style
	bannerExpires time.Time

	width  int
	height int
}

const logsViewerToolCap = 12

func NewLogsViewer(cli *client.Client, scanID string, scanStatus g3lib.G3SCANSTATUS, pollInterval time.Duration) LogsViewer {
	logsViewerGenCounter++
	v := LogsViewer{
		cli:          cli,
		scanID:       scanID,
		scanStatus:   scanStatus,
		generation:   logsViewerGenCounter,
		toolByTask:   map[string]string{},
		toolWidth:    1,
		viewport:     viewport.New(0, 0),
		wrap:         true,
		pollInterval: pollInterval,
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
// schedules the next tick implicitly via the chunk handler. Called
// once by App immediately after constructing the viewer.
func (v LogsViewer) InitCmd() tea.Cmd {
	return v.fetchNowCmd()
}

func (v LogsViewer) Help() []key.Binding {
	return []key.Binding{Keys.Save, Keys.GotoTop, Keys.GotoBottom, Keys.WrapToggle, Keys.Back}
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
		if v.picker != nil {
			np, cmd := v.picker.Update(m)
			v.picker = &np
			return v, cmd
		}
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
		case key.Matches(m, Keys.WrapToggle):
			wasAtBottom := v.viewport.AtBottom()
			v.wrap = !v.wrap
			v.applyContent()
			if wasAtBottom {
				v.viewport.GotoBottom()
			}
		case key.Matches(m, Keys.Save):
			return v.openSavePicker()
		}
		return v, nil

	case pickerSaveConfirmedMsg:
		if v.picker == nil {
			return v, nil
		}
		path := m.Path
		v.picker = nil
		return v.writeLogs(path)

	case pickerCanceledMsg:
		v.picker = nil
		return v, nil

	case logsViewerSavedMsg:
		v.setBanner(BannerSuccess, fmt.Sprintf("Saved to %s", m.Path))
		return v, v.expireBannerCmd()

	case logsViewerSaveErrorMsg:
		v.setBanner(BannerError, fmt.Sprintf("Save failed: %v", m.Err))
		return v, v.expireBannerCmd()

	case logsViewerBannerExpireMsg:
		if !v.bannerExpires.IsZero() && time.Now().After(v.bannerExpires) {
			v.banner = ""
			v.bannerExpires = time.Time{}
		}
		return v, nil
	}
	return v, nil
}

func (v LogsViewer) View() string {
	title := AppTitle.Render(v.renderTitle(v.width - 4))
	body := v.viewport.View()

	parts := []string{title, ""}
	if v.banner != "" {
		parts = append(parts, v.bannerStyle.Width(v.width-4).Render(v.banner))
	}
	parts = append(parts, body)

	rendered := PaneBorderFocused.Width(v.width - 2).Height(v.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, parts...),
	)

	if v.picker != nil {
		return lipgloss.Place(
			v.width, v.height,
			lipgloss.Center, lipgloss.Center,
			v.picker.View(),
		)
	}
	return rendered
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
// where [tool] is end-ellipsised to toolWidth. When wrap is on, long
// bodies hard-wrap to the viewport width with a hanging indent under
// the body column.
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
		prefix, prefixWidth := viewerLinePrefix(e.Timestamp, v.toolFor(e.TaskID), shortTaskID(e.TaskID), v.toolWidth)
		body := g3lib.StripAnsi(e.Text)
		b.WriteString(wrapLogLine(prefix, prefixWidth, body, v.viewport.Width, v.wrap))
	}
	v.viewport.SetContent(b.String())
}

func (v LogsViewer) toolFor(taskID string) string {
	if t, ok := v.toolByTask[taskID]; ok {
		return t
	}
	return "?"
}

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

// shortTaskID returns the first 8 characters of a task UUID for use as a
// compact per-line identity tag. Shorter ids (shouldn't happen for valid
// uuid4) are returned whole.
func shortTaskID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

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
	return tea.Tick(v.pollInterval, func(time.Time) tea.Msg {
		return logsViewerTickMsg{Generation: gen, ScanID: sid}
	})
}

// logsViewerSavedMsg / logsViewerSaveErrorMsg / logsViewerBannerExpireMsg
// are local to this file because they are not part of the client
// transport — they are internal UI events emitted by the save handler
// running as a tea.Cmd.
type logsViewerSavedMsg struct{ Path string }
type logsViewerSaveErrorMsg struct{ Err error }
type logsViewerBannerExpireMsg struct{}

func (v LogsViewer) openSavePicker() (LogsViewer, tea.Cmd) {
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	short := v.scanID
	if len(short) > 8 {
		short = short[:8]
	}
	pk := NewSaveFilePicker(cwd, fmt.Sprintf("%s-logs.log", short), "Save scan logs")
	pk.SetSize(v.width, v.height)
	cmd := pk.InitCmd()
	v.picker = &pk
	return v, cmd
}

func (v LogsViewer) writeLogs(path string) (LogsViewer, tea.Cmd) {
	body := []byte(v.renderForSave())
	return v, func() tea.Msg {
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return logsViewerSaveErrorMsg{Err: err}
		}
		return logsViewerSavedMsg{Path: path}
	}
}

func (v *LogsViewer) setBanner(style lipgloss.Style, text string) {
	v.banner = text
	v.bannerStyle = style
	v.bannerExpires = time.Now().Add(5 * time.Second)
}

func (v LogsViewer) expireBannerCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return logsViewerBannerExpireMsg{} })
}
