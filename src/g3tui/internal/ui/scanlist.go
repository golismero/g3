package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golismero.com/g3lib"
	"golismero.com/g3tui/internal/client"
)

// ScanList is the left-panel sub-model. It owns the raw scan list, the
// sorted+filtered view, the selection cursor, and the filter textinput.
// Selection is exposed via SelectedID so the parent can drive ScanDetail.
type ScanList struct {
	entries  []g3lib.ScanStatusEntry
	filtered []g3lib.ScanStatusEntry
	cursor   int

	filtering bool
	filter    textinput.Model
	viewport  viewport.Model

	width   int
	height  int
	focused bool
}

func NewScanList() ScanList {
	ti := textinput.New()
	ti.Placeholder = "filter (id prefix or status)"
	ti.Prompt = "/ "
	ti.CharLimit = 64
	return ScanList{filter: ti, viewport: viewport.New(0, 0)}
}

// Filtering reports whether the textinput currently owns keystrokes. The
// parent uses this to suppress its own keybinds while filtering.
func (s ScanList) Filtering() bool { return s.filtering }

// SelectedID returns the ScanID of the highlighted row, or "" if empty.
func (s ScanList) SelectedID() string {
	if s.cursor < 0 || s.cursor >= len(s.filtered) {
		return ""
	}
	return s.filtered[s.cursor].ScanID
}

// SetSize is called by the parent on layout resize.
func (s *ScanList) SetSize(w, h int) {
	s.width = w
	s.height = h
	s.filter.Width = max(0, w-3)

	// Viewport content area: total panel height minus chrome (border 2)
	// minus title (1) + spacer (1), minus optional filter input (2 when
	// filtering active).
	chrome := 2
	titleAndSpacer := 2
	filterRows := 0
	if s.filtering {
		filterRows = 2
	}
	inner := w - 4 // border 2 + padding 1+1
	contentHeight := max(1, h-chrome-titleAndSpacer-filterRows)
	s.viewport.Width = inner
	s.viewport.Height = contentHeight
}

// SetFocused toggles the focused-border style. Called by App.applyFocus.
func (s *ScanList) SetFocused(focused bool) {
	s.focused = focused
}

func (s ScanList) Update(msg tea.Msg) (ScanList, tea.Cmd) {
	switch m := msg.(type) {
	case client.ScanListSnapshot:
		s.entries = m.Entries
		s.applyFilter()
		if s.cursor >= len(s.filtered) {
			s.cursor = max(0, len(s.filtered)-1)
		}
		s.ensureCursorVisible()
		return s, nil

	case client.ScanProgressUpdate:
		needBackfill := s.upsert(m)
		s.applyFilter()
		s.ensureCursorVisible()
		if needBackfill {
			scanID := m.ScanID
			return s, func() tea.Msg { return backfillProgressMsg{ScanID: scanID} }
		}
		return s, nil

	case tea.KeyMsg:
		if s.filtering {
			return s.updateFiltering(m)
		}
		switch {
		case key.Matches(m, Keys.Up):
			if s.cursor > 0 {
				s.cursor--
			}
			s.ensureCursorVisible()
		case key.Matches(m, Keys.Down):
			if s.cursor < len(s.filtered)-1 {
				s.cursor++
			}
			s.ensureCursorVisible()
		case key.Matches(m, Keys.PgUp):
			s.viewport.HalfPageUp()
			s.cursor = max(0, s.cursor-s.viewport.Height/2)
			s.ensureCursorVisible()
		case key.Matches(m, Keys.PgDn):
			s.viewport.HalfPageDown()
			if len(s.filtered) > 0 {
				s.cursor = min(len(s.filtered)-1, s.cursor+s.viewport.Height/2)
			}
			s.ensureCursorVisible()
		case key.Matches(m, Keys.GotoTop):
			s.cursor = 0
			s.viewport.GotoTop()
		case key.Matches(m, Keys.GotoBottom):
			if len(s.filtered) > 0 {
				s.cursor = len(s.filtered) - 1
			}
			s.viewport.GotoBottom()
		case key.Matches(m, Keys.Filter):
			s.filtering = true
			s.filter.SetValue("")
			cmd := s.filter.Focus()
			return s, cmd
		}
	}
	return s, nil
}

// ensureCursorVisible scrolls the viewport so the cursor row stays
// within view. Each scan renders as 2 rows (id line + status line), so
// the cursor's pixel-row is cursor*2.
func (s *ScanList) ensureCursorVisible() {
	if len(s.filtered) == 0 {
		return
	}
	rowsPerEntry := 2
	cursorTop := s.cursor * rowsPerEntry
	cursorBottom := cursorTop + rowsPerEntry - 1

	if cursorTop < s.viewport.YOffset {
		s.viewport.SetYOffset(cursorTop)
	} else if cursorBottom >= s.viewport.YOffset+s.viewport.Height {
		s.viewport.SetYOffset(cursorBottom - s.viewport.Height + 1)
	}
}

func (s ScanList) updateFiltering(msg tea.KeyMsg) (ScanList, tea.Cmd) {
	switch msg.String() {
	case "esc":
		s.filtering = false
		s.filter.Blur()
		s.filter.SetValue("")
		s.applyFilter()
		return s, nil
	case "enter":
		s.filtering = false
		s.filter.Blur()
		s.applyFilter()
		return s, nil
	}
	var cmd tea.Cmd
	s.filter, cmd = s.filter.Update(msg)
	s.applyFilter()
	if s.cursor >= len(s.filtered) {
		s.cursor = max(0, len(s.filtered)-1)
	}
	return s, cmd
}

// upsert applies a ScanProgressUpdate. If the update targets a scan
// we've never seen AND the sender did not carry a progress value, no
// row is appended and the function returns true — the caller is
// expected to trigger a backfill from /scan/progress (the
// DB-authoritative source) so the row appears with truthful data
// rather than a fabricated 0%.
func (s *ScanList) upsert(u client.ScanProgressUpdate) (needBackfill bool) {
	for i, e := range s.entries {
		if e.ScanID == u.ScanID {
			s.entries[i].Status = u.Status
			// nil Progress means "sender doesn't know" — preserve
			// whatever value we already have (mirrors the server-side
			// UpdateScanProgress nil-skip semantics).
			if u.Progress != nil {
				s.entries[i].Progress = *u.Progress
			}
			s.entries[i].Message = u.Message
			return false
		}
	}
	if u.Progress == nil {
		return true
	}
	s.entries = append(s.entries, g3lib.ScanStatusEntry{
		ScanID:   u.ScanID,
		Status:   u.Status,
		Progress: *u.Progress,
		Message:  u.Message,
	})
	return false
}

// backfillProgressMsg requests the App to issue a one-shot
// /scan/progress fetch. ScanList emits this when a WS push targets an
// unknown scan without progress data; App handles by firing a tea.Cmd
// that returns ScanListSnapshot, which then populates the row with
// DB-authoritative state via the regular handler.
type backfillProgressMsg struct {
	ScanID string // diagnostic only; the fetch is unconditional
}

func (s *ScanList) applyFilter() {
	sorted := make([]g3lib.ScanStatusEntry, len(s.entries))
	copy(sorted, s.entries)
	sort.SliceStable(sorted, func(i, j int) bool {
		pi, pj := statusPriority(sorted[i].Status), statusPriority(sorted[j].Status)
		if pi != pj {
			return pi < pj
		}
		return sorted[i].ScanID > sorted[j].ScanID
	})
	f := strings.ToLower(strings.TrimSpace(s.filter.Value()))
	if f == "" {
		s.filtered = sorted
		return
	}
	out := make([]g3lib.ScanStatusEntry, 0, len(sorted))
	for _, e := range sorted {
		if strings.HasPrefix(strings.ToLower(e.ScanID), f) ||
			strings.HasPrefix(strings.ToLower(string(e.Status)), f) {
			out = append(out, e)
		}
	}
	s.filtered = out
}

func statusPriority(s g3lib.G3SCANSTATUS) int {
	switch s {
	case g3lib.STATUS_RUNNING:
		return 0
	case g3lib.STATUS_WAITING:
		return 1
	case g3lib.STATUS_FINISHED:
		return 2
	case g3lib.STATUS_CANCELED:
		return 3
	case g3lib.STATUS_ERROR:
		return 4
	}
	return 5
}

func (s ScanList) View() string {
	title := AppTitle.Render("Scans")

	// Available width for the UUID line, after the panel chrome and
	// the 2-char cursor prefix.
	idWidth := max(colTaskIDFloor, s.width-6)

	var content string
	if len(s.filtered) == 0 {
		content = ListItemDimmed.Render("No scans yet — press [N] to start one")
	} else {
		rows := make([]string, 0, len(s.filtered)*2)
		for i, e := range s.filtered {
			idLine, statusLine := formatScanRow(e, i == s.cursor, idWidth)
			rows = append(rows, idLine, statusLine)
		}
		content = lipgloss.JoinVertical(lipgloss.Left, rows...)
	}
	s.viewport.SetContent(content)

	parts := []string{title, "", s.viewport.View()}
	if s.filtering {
		parts = append(parts, "", s.filter.View())
	}
	border := PaneBorder
	if s.focused {
		border = PaneBorderFocused
	}
	// Explicit Height keeps the scan-list panel border closing at the
	// allocated bottom row even when the entry list is shorter than
	// the panel — without it, the border was content-sized and visibly
	// shorter than the right-hand stack on most terminal sizes.
	return border.Width(s.width - 2).Height(s.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, parts...),
	)
}

// formatScanRow returns two lines per scan: the full UUID (or its
// middle-ellipsis collapse if idWidth < 36), then a status pill +
// progress underneath. Each scan therefore takes 2 rows of vertical
// space; UUIDs that don't fit alongside the status on one row get the
// vertical-space treatment instead of horizontal mangling.
func formatScanRow(e g3lib.ScanStatusEntry, selected bool, idWidth int) (idLine, statusLine string) {
	pill := statusStyle(e.Status).Render(string(e.Status))
	id := collapseID(e.ScanID, idWidth)
	if selected {
		idLine = ListItemSelected.Render("▸ " + id)
	} else {
		idLine = "  " + id
	}
	statusLine = fmt.Sprintf("    %s %3d%%", pill, e.Progress)
	return idLine, statusLine
}

func statusStyle(s g3lib.G3SCANSTATUS) lipgloss.Style {
	switch s {
	case g3lib.STATUS_RUNNING:
		return StatusRunning
	case g3lib.STATUS_WAITING:
		return StatusWaiting
	case g3lib.STATUS_FINISHED:
		return StatusFinished
	case g3lib.STATUS_CANCELED:
		return StatusCanceled
	case g3lib.STATUS_ERROR:
		return StatusError
	}
	return ListItem
}

func (s ScanList) Help() []key.Binding {
	if s.filtering {
		return []key.Binding{Keys.Back, Keys.Enter}
	}
	return []key.Binding{Keys.Up, Keys.Down, Keys.Filter}
}
