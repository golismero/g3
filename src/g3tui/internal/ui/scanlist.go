package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/golismero/g3/src/g3lib"
	"github.com/golismero/g3/src/g3tui/internal/client"
)

// ScanList is the left-panel sub-model. It owns the raw scan list, the
// filtered view, and the selection (tracked by scan id). Selection is
// exposed via SelectedID so the parent can drive ScanDetail.
//
// Ordering is server-defined: /scan/progress returns rows ORDER BY id
// DESC so the newest scan is first. ScanList never sorts client-side.
// Status changes mutate properties in place; previously-unseen scan IDs
// trigger a backfill so the server alone decides where the new row
// lands. Selection is tracked by ScanID, not by index, so reshuffles
// never move the cursor onto a different scan.
type ScanList struct {
	entries    []g3lib.ScanStatusEntry
	filtered   []g3lib.ScanStatusEntry
	selectedID string // "" means no selection — a first-class state

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

// Filtering reports whether the textinput currently owns keystrokes.
// The parent uses this to suppress its own keybinds while filtering.
func (s ScanList) Filtering() bool { return s.filtering }

// SelectedID returns the ScanID of the highlighted row, or "" when no
// scan is selected. "" is a legitimate state (empty list, or the
// selected scan was deleted / filtered out) — consumers must treat it
// as such; other panels render their no-selection state.
func (s ScanList) SelectedID() string { return s.selectedID }

// SelectedStatus returns the status of the currently-highlighted entry,
// or "" when no entry is selected. Used by App to know whether the
// Logs panel should keep polling the binding's task.
func (s ScanList) SelectedStatus() g3lib.G3SCANSTATUS {
	return s.StatusByID(s.selectedID)
}

// StatusByID returns the status of the entry with the given scan ID,
// or "" if no such entry exists. Used by App to refresh the open
// LogsViewer's cached scan status after a snapshot or WS push.
func (s ScanList) StatusByID(id string) g3lib.G3SCANSTATUS {
	if id == "" {
		return ""
	}
	for _, e := range s.entries {
		if e.ScanID == id {
			return e.Status
		}
	}
	return ""
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
	s.applyContent()
}

// SetFocused toggles the focused-border style. Called by App.applyFocus.
func (s *ScanList) SetFocused(focused bool) {
	s.focused = focused
}

func (s ScanList) Update(msg tea.Msg) (ScanList, tea.Cmd) {
	switch m := msg.(type) {
	case client.ScanListSnapshot:
		prevLen := len(s.filtered)
		s.entries = m.Entries
		s.applyFilter()
		s.reconcileSelection(prevLen)
		s.applyContent()
		s.ensureSelectionVisible()
		return s, nil

	case client.ScanProgressUpdate:
		prevLen := len(s.filtered)
		needBackfill := s.applyUpdate(m)
		s.applyFilter()
		s.reconcileSelection(prevLen)
		s.applyContent()
		s.ensureSelectionVisible()
		if needBackfill {
			scanID := m.ScanID
			return s, func() tea.Msg { return backfillProgressMsg{ScanID: scanID} }
		}
		return s, nil

	case client.ScanRemoved:
		prevLen := len(s.filtered)
		s.entries = removeByScanID(s.entries, m.ScanID)
		s.applyFilter()
		s.reconcileSelection(prevLen)
		s.applyContent()
		s.ensureSelectionVisible()
		return s, nil

	case tea.KeyMsg:
		if s.filtering {
			return s.updateFiltering(m)
		}
		switch {
		case key.Matches(m, Keys.Up):
			s.moveSelection(-1)
		case key.Matches(m, Keys.Down):
			s.moveSelection(+1)
		case key.Matches(m, Keys.PgUp):
			s.viewport.HalfPageUp()
			s.moveSelection(-s.viewport.Height / 2)
		case key.Matches(m, Keys.PgDn):
			s.viewport.HalfPageDown()
			s.moveSelection(+s.viewport.Height / 2)
		case key.Matches(m, Keys.GotoTop):
			if len(s.filtered) > 0 {
				s.selectedID = s.filtered[0].ScanID
			}
			s.applyContent()
			s.viewport.GotoTop()
		case key.Matches(m, Keys.GotoBottom):
			if len(s.filtered) > 0 {
				s.selectedID = s.filtered[len(s.filtered)-1].ScanID
			}
			s.applyContent()
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

// indexOfSelected returns the position of s.selectedID in s.filtered,
// or -1 if there is no selection or the selection isn't currently
// visible. Callers use it for nav arithmetic and scroll positioning.
func (s ScanList) indexOfSelected() int {
	if s.selectedID == "" {
		return -1
	}
	for i, e := range s.filtered {
		if e.ScanID == s.selectedID {
			return i
		}
	}
	return -1
}

// moveSelection shifts the selected row by delta, clamping at the
// list's ends. When nothing is selected, Down (delta>0) selects the
// first row and Up (delta<0) selects the last — this gives the user a
// way to re-engage selection after the previous selection was lost
// (deletion, filter, etc.) without dedicated keys.
func (s *ScanList) moveSelection(delta int) {
	if len(s.filtered) == 0 || delta == 0 {
		return
	}
	idx := s.indexOfSelected()
	if idx < 0 {
		if delta > 0 {
			s.selectedID = s.filtered[0].ScanID
		} else {
			s.selectedID = s.filtered[len(s.filtered)-1].ScanID
		}
		s.applyContent()
		s.ensureSelectionVisible()
		return
	}
	newIdx := idx + delta
	if newIdx < 0 {
		newIdx = 0
	}
	if newIdx >= len(s.filtered) {
		newIdx = len(s.filtered) - 1
	}
	s.selectedID = s.filtered[newIdx].ScanID
	s.applyContent()
	s.ensureSelectionVisible()
}

// ensureSelectionVisible scrolls the viewport so the selected row stays
// within view. Each scan renders as 2 rows (id line + status line). No
// scrolling happens when there's no selection or it isn't currently in
// the filtered list.
func (s *ScanList) ensureSelectionVisible() {
	idx := s.indexOfSelected()
	if idx < 0 {
		return
	}
	rowsPerEntry := 2
	top := idx * rowsPerEntry
	bottom := top + rowsPerEntry - 1
	if top < s.viewport.YOffset {
		s.viewport.SetYOffset(top)
	} else if bottom >= s.viewport.YOffset+s.viewport.Height {
		s.viewport.SetYOffset(bottom - s.viewport.Height + 1)
	}
}

func (s ScanList) updateFiltering(msg tea.KeyMsg) (ScanList, tea.Cmd) {
	switch msg.String() {
	case "esc":
		s.filtering = false
		s.filter.Blur()
		s.filter.SetValue("")
		prevLen := len(s.filtered)
		s.applyFilter()
		s.reconcileSelection(prevLen)
		s.applyContent()
		return s, nil
	case "enter":
		s.filtering = false
		s.filter.Blur()
		prevLen := len(s.filtered)
		s.applyFilter()
		s.reconcileSelection(prevLen)
		s.applyContent()
		return s, nil
	}
	var cmd tea.Cmd
	s.filter, cmd = s.filter.Update(msg)
	prevLen := len(s.filtered)
	s.applyFilter()
	s.reconcileSelection(prevLen)
	s.applyContent()
	return s, cmd
}

// applyUpdate applies a ScanProgressUpdate to a known scan in place.
// Returns true when the update targets a scan we've never seen — the
// caller is expected to trigger a backfill from /scan/progress (the
// DB-authoritative source) so the new row lands at the server-defined
// position rather than being placed locally with a guessed offset.
func (s *ScanList) applyUpdate(u client.ScanProgressUpdate) (needBackfill bool) {
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
	return true
}

// reconcileSelection re-derives s.selectedID after any mutation of
// s.filtered. The rules:
//   - empty filtered list → selectedID = ""
//   - selected scan still in filtered list → unchanged
//   - selected scan not found → selectedID = "" (panels go to no-selection state)
//   - no selection and list transitioned from empty → auto-anchor to filtered[0]
//   - no selection and list was already non-empty → stay deselected
//
// The "transition from empty" rule is what gives both startup default
// and sticky-deselect-after-loss behavior with a single condition.
func (s *ScanList) reconcileSelection(prevLen int) {
	if len(s.filtered) == 0 {
		s.selectedID = ""
		return
	}
	if s.selectedID != "" {
		for _, e := range s.filtered {
			if e.ScanID == s.selectedID {
				return
			}
		}
		s.selectedID = ""
		return
	}
	if prevLen == 0 {
		s.selectedID = s.filtered[0].ScanID
	}
}

// removeByScanID returns entries with any element matching id removed.
// Preserves order. Returns the input unchanged if id is not found.
func removeByScanID(entries []g3lib.ScanStatusEntry, id string) []g3lib.ScanStatusEntry {
	for i, e := range entries {
		if e.ScanID == id {
			return append(entries[:i], entries[i+1:]...)
		}
	}
	return entries
}

// backfillProgressMsg requests the App to issue a one-shot
// /scan/progress fetch. ScanList emits this when a WS push targets an
// unknown scan; App handles by firing a tea.Cmd that returns
// ScanListSnapshot, which then populates the row with DB-authoritative
// state via the regular handler.
type backfillProgressMsg struct {
	ScanID string // diagnostic only; the fetch is unconditional
}

// applyFilter rebuilds s.filtered from s.entries, preserving the
// server-defined order. Filtering matches the textinput value against
// scan id prefix or status prefix (case-insensitive).
func (s *ScanList) applyFilter() {
	f := strings.ToLower(strings.TrimSpace(s.filter.Value()))
	if f == "" {
		s.filtered = append(s.filtered[:0], s.entries...)
		return
	}
	out := make([]g3lib.ScanStatusEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if strings.HasPrefix(strings.ToLower(e.ScanID), f) ||
			strings.HasPrefix(strings.ToLower(string(e.Status)), f) {
			out = append(out, e)
		}
	}
	s.filtered = out
}

func (s ScanList) View() string {
	title := AppTitle.Render("Scans")
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

// applyContent rebuilds viewport content from s.filtered/selectedID/width.
// Must run in Update (not View) so the persisted viewport's `lines` slice
// is populated — otherwise viewport.SetYOffset() in ensureSelectionVisible
// clamps against len(lines)=0 and pins YOffset to 0, so the cursor moves
// but the viewport never scrolls.
func (s *ScanList) applyContent() {
	idWidth := max(colTaskIDFloor, s.width-6)
	if len(s.filtered) == 0 {
		s.viewport.SetContent(ListItemDimmed.Render("No scans yet — press [N] to start one"))
		return
	}
	rows := make([]string, 0, len(s.filtered)*2)
	for _, e := range s.filtered {
		idLine, statusLine := formatScanRow(e, e.ScanID == s.selectedID, idWidth)
		rows = append(rows, idLine, statusLine)
	}
	s.viewport.SetContent(lipgloss.JoinVertical(lipgloss.Left, rows...))
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
	// Managed scans are driven externally; g3scanner never emits a
	// progress value for them, so the percentage is meaningless noise.
	if e.Status == g3lib.STATUS_MANAGED {
		statusLine = "    " + pill
	} else {
		statusLine = fmt.Sprintf("    %s %3d%%", pill, e.Progress)
	}
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
