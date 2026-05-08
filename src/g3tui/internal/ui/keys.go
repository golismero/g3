package ui

import "github.com/charmbracelet/bubbles/key"

type KeyMap struct {
	Up         key.Binding
	Down       key.Binding
	Left       key.Binding
	Right      key.Binding
	PgUp       key.Binding
	PgDn       key.Binding
	GotoTop    key.Binding
	GotoBottom key.Binding
	Enter      key.Binding
	Space      key.Binding
	Tab        key.Binding
	ShiftTab   key.Binding
	Filter     key.Binding
	Quit       key.Binding
	Help       key.Binding
	Back       key.Binding
	Cancel     key.Binding
	Delete     key.Binding
	New        key.Binding
	Logs       key.Binding
	Report     key.Binding
	Yes        key.Binding
	No         key.Binding
	Retry      key.Binding
	Submit     key.Binding
}

// Keys is the global key map. Sub-models consult only the bindings they
// own — this keeps the same keystroke (e.g. `n`) free to mean "new scan"
// at the dashboard level and "no" inside a confirm overlay.
var Keys = KeyMap{
	Up:         key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:       key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Left:       key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "left")),
	Right:      key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("→/l", "right")),
	PgUp:       key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "page up")),
	PgDn:       key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "page down")),
	GotoTop:    key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
	GotoBottom: key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
	Enter:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("⏎", "select")),
	Space:      key.NewBinding(key.WithKeys(" "), key.WithHelp("space", "toggle")),
	Tab:        key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next")),
	ShiftTab:   key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "prev")),
	Filter:     key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Quit:       key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Help:       key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	Back:       key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
	Cancel:     key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "cancel")),
	Delete:     key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "delete")),
	New:        key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "new")),
	Logs:       key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "logs")),
	Report:     key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "report")),
	Yes:        key.NewBinding(key.WithKeys("y", "Y"), key.WithHelp("y", "yes")),
	No:         key.NewBinding(key.WithKeys("n", "N", "esc"), key.WithHelp("n", "no")),
	Retry:      key.NewBinding(key.WithKeys("r", "R"), key.WithHelp("r", "retry")),
	Submit:     key.NewBinding(key.WithKeys("ctrl+s"), key.WithHelp("ctrl+s", "submit")),
}
