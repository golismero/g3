package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// pickerConfirmedMsg fires when the user presses Enter in the file
// browser. Paths are absolute. The Wizard consumes it to append imports
// rows bound to its pendingTool.
type pickerConfirmedMsg struct {
	Paths []string
}

// pickerCanceledMsg fires on Esc. The Wizard tears down the overlay
// without modifying its imports list.
type pickerCanceledMsg struct{}

type pickerEntry struct {
	Name  string
	IsDir bool
	Path  string // absolute
}

// FilePicker is a small multi-select file browser. Renders entries in
// the current directory; ↑↓ navigate, → descends into a directory under
// the cursor, ← goes up, Space toggles file selection (directories
// cannot be selected), Enter confirms, Esc cancels.
type FilePicker struct {
	dir      string
	entries  []pickerEntry
	cursor   int
	selected map[string]bool
	err      string

	width  int
	height int
}

func NewFilePicker(initialDir string) FilePicker {
	p := FilePicker{
		dir:      initialDir,
		selected: map[string]bool{},
	}
	p.refresh()
	return p
}

func (p *FilePicker) refresh() {
	abs, err := filepath.Abs(p.dir)
	if err == nil {
		p.dir = abs
	}
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		p.err = err.Error()
		p.entries = nil
		return
	}
	p.err = ""
	out := make([]pickerEntry, 0, len(entries)+1)
	if parent := filepath.Dir(p.dir); parent != p.dir {
		out = append(out, pickerEntry{Name: "..", IsDir: true, Path: parent})
	}
	for _, e := range entries {
		out = append(out, pickerEntry{
			Name:  e.Name(),
			IsDir: e.IsDir(),
			Path:  filepath.Join(p.dir, e.Name()),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return out[i].Name < out[j].Name
	})
	p.entries = out
	if p.cursor >= len(p.entries) {
		p.cursor = max(0, len(p.entries)-1)
	}
}

func (p *FilePicker) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p FilePicker) Update(msg tea.Msg) (FilePicker, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch {
	case key.Matches(km, Keys.Back):
		return p, func() tea.Msg { return pickerCanceledMsg{} }
	case key.Matches(km, Keys.Enter):
		// Enter on a directory descends into it (so the user isn't
		// stuck if they're currently highlighting one); elsewhere it
		// confirms the multi-selection.
		if p.cursor < len(p.entries) && p.entries[p.cursor].IsDir {
			p.dir = p.entries[p.cursor].Path
			p.cursor = 0
			p.refresh()
			return p, nil
		}
		return p, p.confirmCmd()
	case key.Matches(km, Keys.Up):
		if p.cursor > 0 {
			p.cursor--
		}
	case key.Matches(km, Keys.Down):
		if p.cursor < len(p.entries)-1 {
			p.cursor++
		}
	case key.Matches(km, Keys.Right):
		if p.cursor < len(p.entries) && p.entries[p.cursor].IsDir {
			p.dir = p.entries[p.cursor].Path
			p.cursor = 0
			p.refresh()
		}
	case key.Matches(km, Keys.Left):
		if parent := filepath.Dir(p.dir); parent != p.dir {
			p.dir = parent
			p.cursor = 0
			p.refresh()
		}
	case key.Matches(km, Keys.Space):
		if p.cursor < len(p.entries) {
			e := p.entries[p.cursor]
			if !e.IsDir {
				if p.selected[e.Path] {
					delete(p.selected, e.Path)
				} else {
					p.selected[e.Path] = true
				}
			}
		}
	}
	return p, nil
}

func (p FilePicker) confirmCmd() tea.Cmd {
	paths := make([]string, 0, len(p.selected))
	for k := range p.selected {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	return func() tea.Msg { return pickerConfirmedMsg{Paths: paths} }
}

func (p FilePicker) View() string {
	inner := max(50, min(p.width-4, 80))
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("214")).
		Padding(1, 2).
		Width(inner)

	title := AppTitle.Render("Select files (multi)")
	pathLine := ListItemDimmed.Render(p.dir)
	rows := []string{title, pathLine, ""}
	if p.err != "" {
		rows = append(rows, BannerError.Width(inner-4).Render(p.err), "")
	}

	const visible = 12
	start := 0
	if p.cursor >= visible {
		start = p.cursor - visible + 1
	}
	end := min(start+visible, len(p.entries))
	for i := start; i < end; i++ {
		e := p.entries[i]
		cursor := "  "
		if i == p.cursor {
			cursor = "▸ "
		}
		check := "[ ]"
		switch {
		case e.IsDir:
			check = "   "
		case p.selected[e.Path]:
			check = "[x]"
		}
		name := e.Name
		if e.IsDir {
			name += "/"
		}
		row := fmt.Sprintf("%s%s %s", cursor, check, name)
		if i == p.cursor {
			row = ListItemSelected.Render(row)
		}
		rows = append(rows, row)
	}

	footer := fmt.Sprintf(
		"[↑↓] move  [→/enter] open dir  [←] up  [space] toggle file  [enter] confirm  [esc] cancel  ·  %d selected",
		len(p.selected),
	)
	rows = append(rows, "", FooterBar.Render(footer))
	return box.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (p FilePicker) Help() []key.Binding {
	return []key.Binding{Keys.Up, Keys.Down, Keys.Left, Keys.Right, Keys.Space, Keys.Enter, Keys.Back}
}
