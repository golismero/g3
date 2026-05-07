package ui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// confirmDoneMsg is dispatched when the user accepts or rejects a Confirm
// overlay. App consumes it to dismiss the overlay; the action's own
// success/failure flows through a separate tea.Cmd attached at construction.
type confirmDoneMsg struct {
	Confirmed bool
}

// Confirm is a generic two-button modal: title + body + Y/N. The OnYes
// command is dispatched verbatim alongside the close signal — App owns
// the mapping from confirmation to the actual API call (cancel/delete).
type Confirm struct {
	title string
	body  string
	onYes tea.Cmd
}

func NewConfirm(title, body string, onYes tea.Cmd) Confirm {
	return Confirm{title: title, body: body, onYes: onYes}
}

func (c Confirm) Update(msg tea.Msg) (Confirm, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return c, nil
	}
	switch {
	case key.Matches(km, Keys.Yes):
		cmds := []tea.Cmd{func() tea.Msg { return confirmDoneMsg{Confirmed: true} }}
		if c.onYes != nil {
			cmds = append(cmds, c.onYes)
		}
		return c, tea.Batch(cmds...)
	case key.Matches(km, Keys.No):
		return c, func() tea.Msg { return confirmDoneMsg{Confirmed: false} }
	}
	return c, nil
}

func (c Confirm) View() string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("214")).
		Padding(1, 2)
	title := AppTitle.Render(c.title)
	body := c.body
	hint := FooterBar.Render("[y] yes   [n] no")
	return box.Render(lipgloss.JoinVertical(lipgloss.Left, title, "", body, "", hint))
}

func (c Confirm) Help() []key.Binding {
	return []key.Binding{Keys.Yes, Keys.No}
}
