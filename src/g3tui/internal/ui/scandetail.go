package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golismero.com/g3lib"
	"golismero.com/g3tui/internal/client"
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
	cli *client.Client

	scanID     string
	scanStatus g3lib.G3SCANSTATUS
	tasks      []g3lib.TaskStatusEntry

	width  int
	height int
}

func NewScanDetail(cli *client.Client) ScanDetail {
	return ScanDetail{cli: cli}
}

func (sd *ScanDetail) SetSize(w, h int) {
	sd.width = w
	sd.height = h
}

func (sd ScanDetail) Update(msg tea.Msg) (ScanDetail, tea.Cmd) {
	switch m := msg.(type) {
	case focusChangedMsg:
		sd.scanID = m.ScanID
		sd.tasks = nil
		sd.scanStatus = ""
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
			return sd, sd.fetchLaterCmd(2 * time.Second)
		}
		sd.scanStatus = m.Response.ScanStatus
		sd.tasks = m.Response.Tasks
		if isTerminal(sd.scanStatus) {
			return sd, nil
		}
		return sd, sd.fetchLaterCmd(2 * time.Second)
	}
	return sd, nil
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

func isTerminal(s g3lib.G3SCANSTATUS) bool {
	switch s {
	case g3lib.STATUS_FINISHED, g3lib.STATUS_CANCELED, g3lib.STATUS_ERROR:
		return true
	}
	return false
}

func emptyTaskMessage(s g3lib.G3SCANSTATUS) string {
	if s == "" {
		return "Loading tasks…"
	}
	// Neutral copy across all populated states. For RUNNING/WAITING
	// scans tasks may still appear; for terminal scans the data may
	// have expired from the backend cache. We can't tell which from
	// here, so we don't claim either way.
	return "No task information available."
}

func (sd ScanDetail) View() string {
	if sd.scanID == "" {
		return PaneBorder.Width(sd.width - 2).Height(sd.height - 2).Render(
			ListItemDimmed.Render("Select a scan to see its tasks"),
		)
	}
	header := AppTitle.Render(fmt.Sprintf("Detail · %s · %s", short12(sd.scanID), string(sd.scanStatus)))
	if len(sd.tasks) == 0 {
		body := ListItemDimmed.Render(emptyTaskMessage(sd.scanStatus))
		return PaneBorder.Width(sd.width - 2).Height(sd.height - 2).Render(
			lipgloss.JoinVertical(lipgloss.Left, header, "", body),
		)
	}
	rows := []string{header, "", taskTableHeader()}
	for _, t := range sd.tasks {
		rows = append(rows, taskTableRow(t))
	}
	return PaneBorder.Width(sd.width - 2).Height(sd.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, rows...),
	)
}

func taskTableHeader() string {
	return TableHeader.Render(fmt.Sprintf(
		"%-13s %-10s %-12s %-12s %8s %8s %6s",
		"TASK ID", "STATE", "TOOL", "WORKER", "LAST SEEN", "AGE", "LINES",
	))
}

func taskTableRow(t g3lib.TaskStatusEntry) string {
	state := taskStateStyle(t.State).Render(fitLeft(t.State, 10))
	return fmt.Sprintf(
		"%-13s %s %-12s %-12s %8s %8s %6d",
		short12(t.TaskID),
		state,
		fitLeft(t.Tool, 12),
		fitLeft(t.Worker, 12),
		humanAgo(t.LastLogTS),
		humanDuration(t.AgeSeconds),
		t.LineCount,
	)
}

func short12(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

func fitLeft(s string, width int) string {
	if len(s) <= width {
		return s + strings.Repeat(" ", width-len(s))
	}
	if width <= 1 {
		return s[:width]
	}
	return s[:width-1] + "…"
}

func humanAgo(epoch int64) string {
	if epoch <= 0 {
		return "—"
	}
	d := time.Since(time.Unix(epoch, 0))
	return humanDurationFromDur(d)
}

func humanDuration(seconds int64) string {
	if seconds <= 0 {
		return "—"
	}
	return humanDurationFromDur(time.Duration(seconds) * time.Second)
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
	case "DONE":
		return StatusFinished
	case "ERROR":
		return StatusError
	case "CANCELED":
		return StatusCanceled
	case "DISPATCHED":
		return StatusDispatched
	}
	return TableRow
}

func (sd ScanDetail) Help() []key.Binding {
	return []key.Binding{Keys.Logs, Keys.Report, Keys.Cancel, Keys.Delete}
}
