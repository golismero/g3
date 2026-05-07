package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
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

	width  int
	height int
}

func NewScanList() ScanList {
	ti := textinput.New()
	ti.Placeholder = "filter (id prefix or status)"
	ti.Prompt = "/ "
	ti.CharLimit = 64
	return ScanList{filter: ti}
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
}

func (s ScanList) Update(msg tea.Msg) (ScanList, tea.Cmd) {
	switch m := msg.(type) {
	case client.ScanListSnapshot:
		s.entries = m.Entries
		s.applyFilter()
		if s.cursor >= len(s.filtered) {
			s.cursor = max(0, len(s.filtered)-1)
		}
		return s, nil

	case client.ScanProgressUpdate:
		needBackfill := s.upsert(m)
		s.applyFilter()
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
		case key.Matches(m, Keys.Down):
			if s.cursor < len(s.filtered)-1 {
				s.cursor++
			}
		case key.Matches(m, Keys.Filter):
			s.filtering = true
			s.filter.SetValue("")
			cmd := s.filter.Focus()
			return s, cmd
		}
	}
	return s, nil
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
	parts := []string{title, ""}
	if len(s.filtered) == 0 {
		empty := ListItemDimmed.Render("No scans yet — press [N] to start one")
		parts = append(parts, empty)
	} else {
		for i, e := range s.filtered {
			row := formatScanRow(e, s.width-2)
			if i == s.cursor {
				row = ListItemSelected.Render(row)
			}
			parts = append(parts, row)
		}
	}
	if s.filtering {
		parts = append(parts, "", s.filter.View())
	}
	return PaneBorder.Width(s.width - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, parts...),
	)
}

func formatScanRow(e g3lib.ScanStatusEntry, width int) string {
	const idShown = 12
	short := e.ScanID
	if len(short) > idShown {
		short = short[:idShown] + "…"
	}
	pill := statusStyle(e.Status).Render(string(e.Status))
	row := fmt.Sprintf("%-13s %s %3d%%", short, pill, e.Progress)
	if width > 0 && lipgloss.Width(row) > width {
		row = row[:width]
	}
	return row
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
