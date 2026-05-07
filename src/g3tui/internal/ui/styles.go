// Package ui implements the Bubble Tea models that compose the g3tui
// dashboard. styles.go is the single Lip Gloss palette — every other UI
// file pulls from these vars rather than defining inline styles.
package ui

import "github.com/charmbracelet/lipgloss"

var (
	AppTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))

	PaneBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)

	HeaderBar = lipgloss.NewStyle().Bold(true)
	FooterBar = lipgloss.NewStyle().Faint(true)

	DotConnected    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	DotConnecting   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	DotDisconnected = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	ListItem         = lipgloss.NewStyle()
	ListItemSelected = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("237"))
	ListItemDimmed   = lipgloss.NewStyle().Faint(true)

	StatusRunning    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	StatusWaiting    = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	StatusFinished   = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))
	StatusError      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	StatusCanceled   = lipgloss.NewStyle().Faint(true)
	StatusDispatched = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))

	TableHeader = lipgloss.NewStyle().Bold(true).Underline(true)
	TableRow    = lipgloss.NewStyle()

	BannerError = lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("196")).
			Bold(true).
			Padding(0, 1)
	BannerWarn = lipgloss.NewStyle().
			Foreground(lipgloss.Color("232")).
			Background(lipgloss.Color("214")).
			Padding(0, 1)
)
