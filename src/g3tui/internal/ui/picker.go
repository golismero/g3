package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
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

// PickerMode selects between the multi-select open-mode used by the
// wizard's imports flow and the single-target save-mode used by
// ReportPane and LogsViewer to pick a save destination.
type PickerMode int

const (
	PickerOpen PickerMode = iota // existing behavior: space-toggle multi-select
	PickerSave                   // new: filename textinput + inline overwrite confirm
)

// pickerSaveConfirmedMsg fires when the user confirms a save destination
// in save-mode (including after an overwrite-confirm prompt if the path
// already existed). Path is absolute and fully resolved.
type pickerSaveConfirmedMsg struct {
	Path string
}

type saveFocus int

const (
	saveFocusInput saveFocus = iota // typing a filename — primary action; default
	saveFocusList                   // browsing/filtering existing files
)

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

	mode       PickerMode
	title      string
	filename   textinput.Model
	confirming bool

	focus           saveFocus
	filter          string
	pendingSavePath string // path being confirmed for overwrite

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

// NewSaveFilePicker builds a save-mode picker. The textinput is
// pre-populated with defaultFilename; the picker still permits
// directory navigation, but Space-toggle multi-select is replaced by
// two focus surfaces (input and file list). On confirm, if the resolved
// path exists, an inline overwrite-confirm prompt is shown; on accept
// the picker emits pickerSaveConfirmedMsg{Path}. On cancel,
// pickerCanceledMsg.
func NewSaveFilePicker(initialDir, defaultFilename, title string) FilePicker {
	ti := textinput.New()
	ti.Prompt = ""
	ti.SetValue(defaultFilename)
	ti.CharLimit = 256

	p := FilePicker{
		dir:      initialDir,
		selected: map[string]bool{},
		mode:     PickerSave,
		title:    title,
		filename: ti,
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
	// In save mode, filter entries by the current filter string. The ".."
	// entry is always preserved so the user can navigate up while filtered.
	if p.mode == PickerSave && p.filter != "" {
		needle := strings.ToLower(p.filter)
		filtered := out[:0]
		for _, e := range out {
			if e.Name == ".." {
				filtered = append(filtered, e)
				continue
			}
			if strings.Contains(strings.ToLower(e.Name), needle) {
				filtered = append(filtered, e)
			}
		}
		out = filtered
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

// InitCmd returns the tea.Cmd that must be dispatched immediately after
// the picker is constructed. For save-mode it is the textinput's cursor
// blink command; for open-mode it is nil. Callers should pass the
// returned Cmd to the Bubble Tea runtime alongside the picker value.
func (p *FilePicker) InitCmd() tea.Cmd {
	if p.mode == PickerSave {
		return p.filename.Focus()
	}
	return nil
}

func (p FilePicker) Update(msg tea.Msg) (FilePicker, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}

	if p.mode == PickerSave {
		// Overwrite-confirm sub-state takes precedence over focus.
		if p.confirming {
			switch {
			case key.Matches(km, Keys.Yes):
				return p, p.saveConfirmCmd()
			case key.Matches(km, Keys.No):
				p.confirming = false
				return p, nil
			}
			return p, nil
		}

		// Tab cycles focus between input and list, regardless of which is active.
		if key.Matches(km, Keys.Tab) || key.Matches(km, Keys.ShiftTab) {
			if p.focus == saveFocusInput {
				p.focus = saveFocusList
			} else {
				p.focus = saveFocusInput
			}
			return p, nil
		}

		// Esc behavior depends on focus + filter state.
		if key.Matches(km, Keys.Back) {
			if p.focus == saveFocusList && p.filter != "" {
				p.filter = ""
				p.cursor = 0
				p.refresh()
				return p, nil
			}
			return p, func() tea.Msg { return pickerCanceledMsg{} }
		}

		// Enter behavior depends on focus.
		if key.Matches(km, Keys.Enter) {
			if p.focus == saveFocusList {
				if p.cursor < len(p.entries) {
					e := p.entries[p.cursor]
					if e.IsDir {
						p.dir = e.Path
						p.cursor = 0
						p.filter = ""
						p.refresh()
						return p, nil
					}
					return p.attemptSavePath(e.Path)
				}
				return p, nil
			}
			// Input focus: save using textinput value.
			return p.attemptSavePath(p.resolvePath())
		}

		if p.focus == saveFocusList {
			// List-mode keys: arrow nav, filter via printable chars, backspace shrinks filter.
			switch km.String() {
			case "up":
				if p.cursor > 0 {
					p.cursor--
				}
				return p, nil
			case "down":
				if p.cursor < len(p.entries)-1 {
					p.cursor++
				}
				return p, nil
			case "backspace":
				if p.filter != "" {
					runes := []rune(p.filter)
					p.filter = string(runes[:len(runes)-1])
					p.cursor = 0
					p.refresh()
				}
				return p, nil
			}
			// Treat other printable single characters as filter input.
			s := km.String()
			if isPrintableFilterRune(s) {
				p.filter += s
				p.cursor = 0
				p.refresh()
			}
			return p, nil
		}

		// Input focus: route everything else to the textinput.
		var cmd tea.Cmd
		p.filename, cmd = p.filename.Update(msg)
		return p, cmd
	}

	// Open-mode behavior (unchanged).
	switch {
	case key.Matches(km, Keys.Back):
		return p, func() tea.Msg { return pickerCanceledMsg{} }
	case key.Matches(km, Keys.Enter):
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

// resolvePath resolves the textinput value to an absolute path. An
// absolute value is used verbatim; a relative one is joined to the
// current directory. No tilde or environment-variable expansion.
func (p FilePicker) resolvePath() string {
	value := strings.TrimSpace(p.filename.Value())
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(p.dir, value)
}

// attemptSavePath checks whether the resolved path already exists. If
// so, the picker enters the overwrite-confirming sub-state and stores
// the path for the y/n handler. Otherwise emits the confirmed message
// immediately. The path argument allows callers to pass either the
// textinput-derived path (input focus) or a list entry's path (list
// focus on a file).
func (p FilePicker) attemptSavePath(path string) (FilePicker, tea.Cmd) {
	if path == "" {
		return p, nil
	}
	_, err := os.Stat(path)
	if err == nil {
		p.confirming = true
		p.pendingSavePath = path
		return p, nil
	}
	if !os.IsNotExist(err) {
		p.err = err.Error()
		return p, nil
	}
	return p, func() tea.Msg { return pickerSaveConfirmedMsg{Path: path} }
}

// saveConfirmCmd emits the confirmed message after the user accepts the
// overwrite prompt, using the path captured when confirming began.
func (p FilePicker) saveConfirmCmd() tea.Cmd {
	path := p.pendingSavePath
	return func() tea.Msg { return pickerSaveConfirmedMsg{Path: path} }
}

func (p FilePicker) View() string {
	inner := max(50, min(p.width-4, 80))
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("214")).
		Padding(1, 2).
		Width(inner)

	if p.mode == PickerSave {
		return box.Render(p.renderSave(inner - 4))
	}

	// Open-mode rendering (unchanged below).
	titleText := "Select files (multi)"
	title := AppTitle.Render(titleText)
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
	rows = append(rows, "")
	footer := fmt.Sprintf(
		"[↑↓] move  [→/enter] open dir  [←] up  [space] toggle file  [enter] confirm  [esc] cancel  ·  %d selected",
		len(p.selected),
	)
	rows = append(rows, FooterBar.Render(footer))
	return box.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

// renderSave builds the save-mode body (everything inside the outer
// orange box). innerWidth is the available width INSIDE the outer
// padding; sub-boxes must size themselves to fit within it.
func (p FilePicker) renderSave(innerWidth int) string {
	titleText := p.title
	if titleText == "" {
		titleText = "Save file"
	}
	title := AppTitle.Render(titleText)
	pathLine := ListItemDimmed.Render(p.dir)

	listBorder := PaneBorder
	inputBorder := PaneBorder
	if p.focus == saveFocusList {
		listBorder = PaneBorderFocused
	} else {
		inputBorder = PaneBorderFocused
	}

	// Files sub-box.
	filesTitleText := "Files"
	if p.filter != "" {
		filesTitleText = fmt.Sprintf("Files / %q", p.filter)
	}
	filesTitle := AppTitle.Render(filesTitleText)

	const visible = 10
	start := 0
	if p.cursor >= visible {
		start = p.cursor - visible + 1
	}
	end := min(start+visible, len(p.entries))
	var listRows []string
	listRows = append(listRows, filesTitle)
	if len(p.entries) == 0 {
		listRows = append(listRows, ListItemDimmed.Render("(no matches)"))
	}
	for i := start; i < end; i++ {
		e := p.entries[i]
		cursor := "  "
		if i == p.cursor {
			cursor = "▸ "
		}
		name := e.Name
		if e.IsDir {
			name += "/"
		}
		row := cursor + name
		if i == p.cursor && p.focus == saveFocusList {
			row = ListItemSelected.Render(row)
		}
		listRows = append(listRows, row)
	}
	listBox := listBorder.Width(innerWidth).Render(
		lipgloss.JoinVertical(lipgloss.Left, listRows...),
	)

	// Filename sub-box.
	inputTitle := AppTitle.Render("Filename")
	inputContent := p.filename.View()
	inputBox := inputBorder.Width(innerWidth).Render(
		lipgloss.JoinVertical(lipgloss.Left, inputTitle, inputContent),
	)

	// Footer adapts to focus and confirming state.
	var footerText string
	switch {
	case p.confirming:
		// Render the warn banner separately below.
	case p.focus == saveFocusList:
		footerText = "[tab] switch  [↑↓] nav  [enter] save / open dir  [a-z] filter  [esc] back"
	default:
		footerText = "[tab] switch  [enter] save  [esc] cancel"
	}

	rows := []string{title, pathLine, ""}
	if p.err != "" {
		rows = append(rows, BannerError.Width(innerWidth).Render(p.err), "")
	}
	rows = append(rows, listBox, "", inputBox, "")
	if p.confirming {
		warn := fmt.Sprintf("[!] %s exists. Overwrite? [y/n]", filepath.Base(p.pendingSavePath))
		rows = append(rows, BannerWarn.Render(warn))
	} else {
		rows = append(rows, FooterBar.Render(footerText))
	}
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (p FilePicker) Help() []key.Binding {
	if p.mode != PickerSave {
		return []key.Binding{Keys.Up, Keys.Down, Keys.Left, Keys.Right, Keys.Space, Keys.Enter, Keys.Back}
	}
	if p.focus == saveFocusList {
		return []key.Binding{Keys.Tab, Keys.Up, Keys.Down, Keys.Enter, Keys.Back}
	}
	return []key.Binding{Keys.Tab, Keys.Enter, Keys.Back}
}

// isPrintableFilterRune returns true when a tea.KeyMsg's String() value
// represents a single printable character suitable for incremental
// filtering. Multi-character names like "shift+up" or "f1" are excluded.
// Space is included; control characters and named keys are not.
func isPrintableFilterRune(s string) bool {
	if len(s) == 0 {
		return false
	}
	runes := []rune(s)
	if len(runes) != 1 {
		return false
	}
	r := runes[0]
	// Exclude control characters (including DEL); allow space and printable.
	if r < 0x20 || r == 0x7f {
		return false
	}
	return true
}
