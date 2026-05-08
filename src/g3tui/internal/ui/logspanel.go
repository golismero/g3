package ui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// LogsPanel is the bottom-right panel reserved for live log preview of
// the focused task. In this iteration it is structural-only — the
// panel renders a placeholder, accepts focus, and discards keystrokes.
// A follow-up release fills in: live log fetching with debounce,
// scrollable viewport, follow-tail toggle, save-to-file.
type LogsPanel struct {
	width   int
	height  int
	focused bool
}

func NewLogsPanel() LogsPanel {
	return LogsPanel{}
}

func (l *LogsPanel) SetSize(w, h int) {
	l.width = w
	l.height = h
}

func (l *LogsPanel) SetFocused(focused bool) {
	l.focused = focused
}

func (l LogsPanel) Update(msg tea.Msg) (LogsPanel, tea.Cmd) {
	// Inert in this iteration — discards all keystrokes.
	return l, nil
}

func (l LogsPanel) View() string {
	border := PaneBorder
	if l.focused {
		border = PaneBorderFocused
	}
	title := AppTitle.Render("Logs")
	body := ListItemDimmed.Render("(log preview — coming in a follow-up release)")
	return border.Width(l.width - 2).Height(l.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, title, "", body),
	)
}

func (l LogsPanel) Help() []key.Binding {
	return nil
}
