package ui

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golismero.com/g3lib"
	"golismero.com/g3tui/internal/client"
	"golismero.com/g3tui/internal/pipelines"
	"golismero.com/g3tui/internal/script"
)

// wizardSubmittedMsg fires after a successful /scan/start. Wizard
// translates this into a wizardClosedMsg.
type wizardSubmittedMsg struct {
	ScanID string
}

// wizardSubmitErrorMsg fires on any local-validation, upload, or
// /scan/start error. Wizard sets a banner and stays open.
type wizardSubmitErrorMsg struct {
	Err error
}

// wizardBannerExpiredMsg clears the wizard's banner ~5s after it appeared.
type wizardBannerExpiredMsg struct{}

// ImportEntry is one row in the wizard's imports list. Tool comes from
// the plugin dropdown; Path is an absolute local path until submit time,
// when /file/upload replaces it with a server-side file id.
type ImportEntry struct {
	Tool string
	Path string
}

type importsOverlayState int

const (
	importsOverlayNone importsOverlayState = iota
	importsOverlayTool
	importsOverlayPicker
)

// wizardClosedMsg dismisses the wizard overlay.
type wizardClosedMsg struct{}

type wizardSection int

const (
	sectionTargets wizardSection = iota
	sectionImports
	sectionMode
	sectionScanType

	wizardSectionCount = 4
)

func (s wizardSection) String() string {
	switch s {
	case sectionTargets:
		return "Targets"
	case sectionImports:
		return "Imports"
	case sectionMode:
		return "Mode"
	case sectionScanType:
		return "Scan type"
	}
	return "?"
}

const (
	modeParallel   = "parallel"
	modeSequential = "sequential"

	customScanTypeLabel = "Custom…"
)

// Wizard is the new-scan modal overlay. Tier 2.2 adds the three "static"
// sections (Targets, Mode, Scan type). Imports stack lands in 2.4.
type Wizard struct {
	cfg     Config
	cli     *client.Client
	pipes   []pipelines.Pipeline
	plugins []client.PluginListEntry

	section wizardSection
	banner  string

	targetsArea textarea.Model
	mode        string
	scanTypeIdx int

	// Imports section state.
	imports        []ImportEntry
	importsCursor  int                 // 0..len(imports) → rows; len(imports) → [+ Add] button
	importsOverlay importsOverlayState // none / tool dropdown / file picker
	pickerToolIdx  int                 // selection in tool dropdown
	pendingTool    string              // tool selected, awaiting file picker confirm
	filePicker     FilePicker

	// Custom… sub-overlay state.
	customOpen    bool
	customEditor  textarea.Model
	customContent string // preserved across re-opens
	customError   string // last validation error; "" means valid or unchecked
	lastNonCustom int    // for the "abandon Custom" revert

	submitting bool

	width  int
	height int
}

func NewWizard(cfg Config, cli *client.Client, pipes []pipelines.Pipeline, plugins []client.PluginListEntry) Wizard {
	ta := textarea.New()
	ta.Placeholder = "192.168.1.1, example.com — one per line"
	ta.SetHeight(3)
	ta.Focus()
	// The dropdown drives the `import <tool> <file>` line, so it must only
	// offer plugins that actually implement an importer — otherwise the user
	// could pick a tool that has no way to consume the file.
	sortedPlugins := make([]client.PluginListEntry, 0, len(plugins))
	for _, p := range plugins {
		if p.Importer {
			sortedPlugins = append(sortedPlugins, p)
		}
	}
	sort.Slice(sortedPlugins, func(i, j int) bool { return sortedPlugins[i].Name < sortedPlugins[j].Name })
	return Wizard{
		cfg:         cfg,
		cli:         cli,
		pipes:       pipes,
		plugins:     sortedPlugins,
		targetsArea: ta,
		mode:        modeParallel,
	}
}

func (w *Wizard) SetSize(width, height int) {
	w.width = width
	w.height = height
	w.targetsArea.SetWidth(max(20, min(width-8, 72)))
	if w.customOpen {
		w.customEditor.SetWidth(max(20, min(width-8, 72)))
	}
	if w.importsOverlay == importsOverlayPicker {
		w.filePicker.SetSize(width, height)
	}
}

func (w Wizard) Update(msg tea.Msg) (Wizard, tea.Cmd) {
	switch m := msg.(type) {
	case pickerConfirmedMsg:
		for _, p := range m.Paths {
			w.imports = append(w.imports, ImportEntry{Tool: w.pendingTool, Path: p})
		}
		w.importsOverlay = importsOverlayNone
		w.pendingTool = ""
		w.importsCursor = len(w.imports) // rest on [+ Add]
		return w, nil

	case pickerCanceledMsg:
		w.importsOverlay = importsOverlayNone
		w.pendingTool = ""
		return w, nil

	case wizardSubmittedMsg:
		return w, func() tea.Msg { return wizardClosedMsg{} }

	case wizardSubmitErrorMsg:
		w.banner = m.Err.Error()
		w.submitting = false
		return w, expireWizardBanner()

	case wizardBannerExpiredMsg:
		w.banner = ""
		return w, nil

	case tea.KeyMsg:
		// While submitting, lock the form except for esc-to-dismiss.
		// The goroutine continues; its result lands harmlessly because
		// App will already have nilled out the wizard pointer.
		if w.submitting {
			if key.Matches(m, Keys.Back) {
				return w, func() tea.Msg { return wizardClosedMsg{} }
			}
			return w, nil
		}
		// Submit shortcut wins over per-section input: Ctrl+S.
		if key.Matches(m, Keys.Submit) {
			return w.submit()
		}
		// Sub-overlays own all keystrokes when active.
		switch {
		case w.customOpen:
			return w.updateCustomEditor(m)
		case w.importsOverlay == importsOverlayTool:
			return w.updateToolDropdown(m)
		case w.importsOverlay == importsOverlayPicker:
			var cmd tea.Cmd
			w.filePicker, cmd = w.filePicker.Update(m)
			return w, cmd
		}
		// Section navigation and wizard dismissal always win, even when
		// an inner input (e.g. the targets textarea) would otherwise
		// capture the key.
		switch {
		case key.Matches(m, Keys.Back):
			return w, func() tea.Msg { return wizardClosedMsg{} }
		case key.Matches(m, Keys.Tab):
			w.section = (w.section + 1) % wizardSectionCount
			w.refocus()
			return w, nil
		case key.Matches(m, Keys.ShiftTab):
			w.section = (w.section + wizardSectionCount - 1) % wizardSectionCount
			w.refocus()
			return w, nil
		}
		return w.dispatchSection(m)
	}
	return w, nil
}

func (w *Wizard) refocus() {
	if w.section == sectionTargets {
		w.targetsArea.Focus()
	} else {
		w.targetsArea.Blur()
	}
}

func (w Wizard) dispatchSection(m tea.KeyMsg) (Wizard, tea.Cmd) {
	switch w.section {
	case sectionTargets:
		var cmd tea.Cmd
		w.targetsArea, cmd = w.targetsArea.Update(m)
		return w, cmd
	case sectionMode:
		switch {
		case key.Matches(m, Keys.Up), key.Matches(m, Keys.Down),
			key.Matches(m, Keys.Left), key.Matches(m, Keys.Right), key.Matches(m, Keys.Space):
			if w.mode == modeParallel {
				w.mode = modeSequential
			} else {
				w.mode = modeParallel
			}
		}
		return w, nil
	case sectionScanType:
		types := w.scanTypeNames()
		switch {
		case key.Matches(m, Keys.Up), key.Matches(m, Keys.Left):
			if w.scanTypeIdx > 0 {
				w.scanTypeIdx--
			}
		case key.Matches(m, Keys.Down), key.Matches(m, Keys.Right):
			if w.scanTypeIdx < len(types)-1 {
				w.scanTypeIdx++
			}
		case key.Matches(m, Keys.Enter):
			if w.scanTypeIdx == len(types)-1 {
				w.openCustomEditor()
			}
		}
		if w.scanTypeIdx < len(w.pipes) {
			w.lastNonCustom = w.scanTypeIdx
		}
		return w, nil
	case sectionImports:
		rowCount := len(w.imports) + 1 // imports rows + [+ Add]
		switch {
		case key.Matches(m, Keys.Up):
			if w.importsCursor > 0 {
				w.importsCursor--
			}
		case key.Matches(m, Keys.Down):
			if w.importsCursor < rowCount-1 {
				w.importsCursor++
			}
		case key.Matches(m, Keys.Enter):
			if w.importsCursor == len(w.imports) {
				// [+ Add] — open tool dropdown.
				w.importsOverlay = importsOverlayTool
				w.pickerToolIdx = 0
			} else if w.importsCursor < len(w.imports) {
				// Remove this row.
				w.imports = append(w.imports[:w.importsCursor], w.imports[w.importsCursor+1:]...)
				if w.importsCursor > len(w.imports) {
					w.importsCursor = len(w.imports)
				}
			}
		}
		return w, nil
	}
	return w, nil
}

func (w Wizard) updateToolDropdown(m tea.KeyMsg) (Wizard, tea.Cmd) {
	switch {
	case key.Matches(m, Keys.Back):
		w.importsOverlay = importsOverlayNone
		return w, nil
	case key.Matches(m, Keys.Up):
		if w.pickerToolIdx > 0 {
			w.pickerToolIdx--
		}
	case key.Matches(m, Keys.Down):
		if w.pickerToolIdx < len(w.plugins)-1 {
			w.pickerToolIdx++
		}
	case key.Matches(m, Keys.Enter):
		if w.pickerToolIdx < len(w.plugins) {
			w.pendingTool = w.plugins[w.pickerToolIdx].Name
			initial := initialPickerDir()
			w.filePicker = NewFilePicker(initial)
			w.filePicker.SetSize(w.width, w.height)
			w.importsOverlay = importsOverlayPicker
		}
	}
	return w, nil
}

func expireWizardBanner() tea.Cmd {
	return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return wizardBannerExpiredMsg{} })
}

// submit runs local validation, then (if valid) hands off to the
// upload+start goroutine via a tea.Cmd.
func (w Wizard) submit() (Wizard, tea.Cmd) {
	targets := parseTargets(w.targetsArea.Value())
	if len(targets) == 0 && len(w.imports) == 0 {
		w.banner = "validation: at least one target or import is required"
		return w, expireWizardBanner()
	}
	types := w.scanTypeNames()
	if len(types) == 0 || w.scanTypeIdx >= len(types) {
		w.banner = "validation: select a scan type"
		return w, expireWizardBanner()
	}
	var pipelineContent string
	if types[w.scanTypeIdx] == customScanTypeLabel {
		if strings.TrimSpace(w.customContent) == "" {
			w.banner = "validation: custom scan type is empty — open it and add a pipeline"
			return w, expireWizardBanner()
		}
		if err := validateCustomContent(w.customContent); err != nil {
			w.banner = "validation: custom scan type: " + err.Error()
			return w, expireWizardBanner()
		}
		pipelineContent = w.customContent
	} else {
		pipelineContent = w.pipes[w.scanTypeIdx].Content
	}

	imports := append([]ImportEntry(nil), w.imports...)
	w.submitting = true
	w.banner = ""
	return w, runSubmitCmd(w.cli, targets, imports, w.mode, pipelineContent)
}

func parseTargets(raw string) []string {
	out := make([]string, 0)
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// runSubmitCmd is the upload+start pipeline. Spawned by a single
// tea.Cmd; runs in its own goroutine; returns either wizardSubmittedMsg
// or wizardSubmitErrorMsg. Concurrency cap: 4 parallel uploads via a
// buffered-channel semaphore.
func runSubmitCmd(cli *client.Client, targets []string, imports []ImportEntry, mode, content string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()

		if len(imports) > 0 {
			type upResult struct {
				idx    int
				fileID string
				err    error
			}
			results := make(chan upResult, len(imports))
			sem := make(chan struct{}, 4)
			for i, imp := range imports {
				sem <- struct{}{}
				go func(i int, imp ImportEntry) {
					defer func() { <-sem }()
					id, err := cli.UploadFile(ctx, imp.Path)
					results <- upResult{idx: i, fileID: id, err: err}
				}(i, imp)
			}
			for range imports {
				r := <-results
				if r.err != nil {
					return wizardSubmitErrorMsg{Err: fmt.Errorf("upload %s: %w", imports[r.idx].Path, r.err)}
				}
				imports[r.idx].Path = r.fileID
			}
		}

		scriptImports := make([]script.ImportEntry, len(imports))
		for i, imp := range imports {
			scriptImports[i] = script.ImportEntry{Tool: imp.Tool, Path: imp.Path}
		}
		s, err := script.Build(targets, scriptImports, mode, content)
		if err != nil {
			return wizardSubmitErrorMsg{Err: err}
		}
		scanID, err := cli.StartScan(ctx, s)
		if err != nil {
			return wizardSubmitErrorMsg{Err: fmt.Errorf("/scan/start: %w", err)}
		}
		return wizardSubmittedMsg{ScanID: scanID}
	}
}

func initialPickerDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		return cwd
	}
	return "/"
}

func (w *Wizard) openCustomEditor() {
	ta := textarea.New()
	ta.Placeholder = "tool | tool | tool\n# one pipeline per line"
	ta.SetWidth(max(20, min(w.width-8, 72)))
	ta.SetHeight(8)
	ta.SetValue(w.customContent)
	ta.Focus()
	w.customEditor = ta
	w.customOpen = true
}

func (w Wizard) updateCustomEditor(m tea.KeyMsg) (Wizard, tea.Cmd) {
	if key.Matches(m, Keys.Back) {
		return w.closeCustomEditor(), nil
	}
	var cmd tea.Cmd
	w.customEditor, cmd = w.customEditor.Update(m)
	return w, cmd
}

func (w Wizard) closeCustomEditor() Wizard {
	w.customContent = w.customEditor.Value()
	w.customOpen = false

	if strings.TrimSpace(w.customContent) == "" {
		// Empty content = abandon Custom; revert to last non-Custom pick.
		w.scanTypeIdx = w.lastNonCustom
		w.customError = ""
		return w
	}
	if err := validateCustomContent(w.customContent); err != nil {
		w.customError = err.Error()
	} else {
		w.customError = ""
	}
	return w
}

func validateCustomContent(content string) error {
	wrapped := fmt.Sprintf("mode parallel\ntarget placeholder.local\n%s", content)
	_, err := g3lib.ParseScript(nil, wrapped)
	return err
}

// scanTypeNames returns the merged list of pipeline names plus the
// trailing "Custom…" entry.
func (w Wizard) scanTypeNames() []string {
	out := make([]string, 0, len(w.pipes)+1)
	for _, p := range w.pipes {
		out = append(out, p.Name)
	}
	out = append(out, customScanTypeLabel)
	return out
}

func (w Wizard) View() string {
	if w.customOpen {
		return w.renderCustomEditor()
	}
	if w.importsOverlay == importsOverlayTool {
		return w.renderToolDropdown()
	}
	if w.importsOverlay == importsOverlayPicker {
		return w.filePicker.View()
	}
	innerWidth := max(40, min(w.width-4, 80))
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(0, 2).
		Width(innerWidth)

	title := AppTitle.Render("New scan")
	rows := []string{title}
	if w.banner != "" {
		rows = append(rows, BannerError.Width(innerWidth-4).Render(w.banner))
	}
	bottomHalf := lipgloss.JoinHorizontal(
		lipgloss.Top,
		lipgloss.NewStyle().Width((innerWidth-4)/2).Render(w.renderMode()),
		lipgloss.NewStyle().Width((innerWidth-4)/2).Render(w.renderScanType()),
	)
	rows = append(rows,
		w.renderTargets(),
		w.renderImports(),
		bottomHalf,
		w.renderWizardFooter(),
	)
	return box.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (w Wizard) renderWizardFooter() string {
	if w.submitting {
		return FooterBar.Render("submitting…")
	}
	return FooterBar.Render("[tab] next section · [ctrl+s] submit · [esc] cancel")
}

func (w Wizard) renderSectionHeader(s wizardSection) string {
	style := ListItemDimmed
	prefix := "  "
	if s == w.section {
		style = AppTitle
		prefix = "▸ "
	}
	return style.Render(prefix + s.String())
}

func (w Wizard) renderTargets() string {
	header := w.renderSectionHeader(sectionTargets)
	return lipgloss.JoinVertical(lipgloss.Left, header, w.targetsArea.View())
}

func (w Wizard) renderImports() string {
	header := w.renderSectionHeader(sectionImports)
	rows := []string{header}
	focused := w.section == sectionImports

	// Render up to 5 imports rows, preferring a window around the
	// cursor so removing a row from a long list keeps the cursor in
	// view.
	const visible = 5
	start := 0
	end := len(w.imports)
	if end > visible {
		start = w.importsCursor - visible/2
		if start < 0 {
			start = 0
		}
		end = start + visible
		if end > len(w.imports) {
			end = len(w.imports)
			start = end - visible
		}
	}
	if start > 0 {
		rows = append(rows, ListItemDimmed.Render(fmt.Sprintf("    … %d more above", start)))
	}
	for i := start; i < end; i++ {
		imp := w.imports[i]
		prefix := "    "
		if focused && i == w.importsCursor {
			prefix = "  ▸ "
		}
		row := fmt.Sprintf("%s%-12s %s  [×]", prefix, imp.Tool, truncatePath(imp.Path, 48))
		if focused && i == w.importsCursor {
			row = ListItemSelected.Render(row)
		}
		rows = append(rows, row)
	}
	if end < len(w.imports) {
		rows = append(rows, ListItemDimmed.Render(fmt.Sprintf("    … %d more below", len(w.imports)-end)))
	}

	addPrefix := "    "
	if focused && w.importsCursor == len(w.imports) {
		addPrefix = "  ▸ "
	}
	addRow := addPrefix + "[+ Add]"
	if focused && w.importsCursor == len(w.imports) {
		addRow = ListItemSelected.Render(addRow)
	}
	rows = append(rows, addRow)
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func truncatePath(p string, max int) string {
	if len(p) <= max {
		return p
	}
	if max < 4 {
		return p[:max]
	}
	return "…" + p[len(p)-max+1:]
}

func (w Wizard) renderToolDropdown() string {
	inner := max(40, min(w.width-4, 60))
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("214")).
		Padding(1, 2).
		Width(inner)

	title := AppTitle.Render("Select import tool")
	rows := []string{title, ""}
	const visible = 10
	start := 0
	if w.pickerToolIdx >= visible {
		start = w.pickerToolIdx - visible + 1
	}
	end := min(start+visible, len(w.plugins))
	for i := start; i < end; i++ {
		prefix := "  "
		if i == w.pickerToolIdx {
			prefix = "▸ "
		}
		row := prefix + w.plugins[i].Name
		if i == w.pickerToolIdx {
			row = ListItemSelected.Render(row)
		}
		rows = append(rows, row)
	}
	rows = append(rows, "", FooterBar.Render("[↑↓] move  [enter] confirm  [esc] cancel"))
	return box.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (w Wizard) renderMode() string {
	header := w.renderSectionHeader(sectionMode)
	parallelDot := "( )"
	sequentialDot := "( )"
	if w.mode == modeParallel {
		parallelDot = "(●)"
	} else {
		sequentialDot = "(●)"
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		"  "+sequentialDot+" sequential",
		"  "+parallelDot+" parallel",
	)
}

func (w Wizard) renderScanType() string {
	header := w.renderSectionHeader(sectionScanType)
	rows := []string{header}
	for i, name := range w.scanTypeNames() {
		row := w.renderScanTypeRow(i, name)
		rows = append(rows, row)
	}
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (w Wizard) renderScanTypeRow(idx int, name string) string {
	prefix := "    "
	if idx == w.scanTypeIdx {
		prefix = "  ▸ "
	}
	tag := ""
	switch {
	case name == customScanTypeLabel:
		if c := strings.TrimSpace(w.customContent); c != "" {
			n := strings.Count(w.customContent, "\n") + 1
			tag = fmt.Sprintf(" (%d lines)", n)
			if w.customError != "" {
				tag += " — invalid"
			}
		}
	case idx < len(w.pipes):
		tag = " (" + string(w.pipes[idx].Source) + ")"
	}
	row := prefix + name + tag
	if idx == w.scanTypeIdx && w.section == sectionScanType {
		return ListItemSelected.Render(row)
	}
	return row
}

func (w Wizard) renderCustomEditor() string {
	innerWidth := max(40, min(w.width-4, 80))
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("214")).
		Padding(1, 2).
		Width(innerWidth)
	title := AppTitle.Render("Custom scan type")
	hint := ListItemDimmed.Render(
		"Pipeline-only content; one tool|tool line per pipeline.\n" +
			"Do not include 'mode', 'target', or 'import' directives.",
	)
	parts := []string{title, "", hint, "", w.customEditor.View()}
	if w.customError != "" {
		parts = append(parts, "", BannerError.Width(innerWidth-4).Render("validation: "+w.customError))
	}
	parts = append(parts, "", FooterBar.Render("[esc] save and close"))
	return box.Render(lipgloss.JoinVertical(lipgloss.Left, parts...))
}

func (w Wizard) Help() []key.Binding {
	switch {
	case w.submitting:
		return []key.Binding{Keys.Back}
	case w.customOpen:
		return []key.Binding{Keys.Back}
	case w.importsOverlay == importsOverlayTool:
		return []key.Binding{Keys.Up, Keys.Down, Keys.Enter, Keys.Back}
	case w.importsOverlay == importsOverlayPicker:
		return w.filePicker.Help()
	}
	return []key.Binding{Keys.Tab, Keys.ShiftTab, Keys.Submit, Keys.Back}
}
