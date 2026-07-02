package ui

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/golismero/g3/src/g3tui/internal/client"
	"github.com/golismero/g3/src/g3tui/internal/pipelines"
)

type Config struct {
	BaseURL      string
	WSURL        string
	Token        string
	GlamourStyle string // "dark" or "light"; detected at startup before bubbletea takes stdin

	// PollInterval applies uniformly to scan-progress (main.go's client.Poll),
	// tasks-status (scandetail.fetchLaterCmd), and inline logs (logspanel
	// tea.Tick). The 250ms cursor-debounce in logspanel is unrelated and not
	// affected. Zero value disables polling-driven refresh; callers always
	// pass a positive duration.
	PollInterval time.Duration

	// NoWS, when true, suppresses the WebSocket subscription goroutine in
	// main.go. Polling fallback then runs continuously and the header
	// connection-dot stays yellow (its existing "polling-only" state).
	NoWS bool

	// ReadOnly hides New/Cancel/Delete bindings from both dispatch and the
	// footer hint string.
	ReadOnly bool
}

// panelFocus identifies which of the three dashboard panels owns
// keyboard focus. Tab cycles forward through these values; Shift-Tab
// cycles backward.
type panelFocus int

const (
	focusScans panelFocus = iota
	focusTasks
	focusLogs

	panelFocusCount = 3
)

// Minimum dashboard footprint. Below either threshold the dashboard
// stops trying to render — the panels' internal min-content rows would
// otherwise overflow, push the title bar off the top, and produce the
// "missing first line" failure mode. Numbers picked from the actual
// per-panel minimums:
//
//   bodyHeight ≥ 12 → tasksPaneHeight ≥ 6 (title 1 + spacer 1 + table
//                     header 1 + viewport 1 + border 2 = 6) and
//                     logsPaneHeight ≥ 6 (border 2 + content 4).
//   width ≥ 60      → scan-list panel 30 + right pane 30, both above
//                     their respective floors.
//
// Plus 2 rows (header bar + footer) → minimum terminal of 60×14.
const (
	minDashboardWidth  = 60
	minDashboardHeight = 14
)

// App is the top-level Bubble Tea model. It owns the API client, the
// pipeline registry, the cached plugin list, the focus state, and the
// WS connection state. Sub-models render specific panes; App routes
// messages to whichever sub-model is interested.
type App struct {
	cfg     Config
	cli     *client.Client
	pipes   []pipelines.Pipeline
	plugins []client.PluginListEntry

	scanList    ScanList
	scanDetail  ScanDetail
	logsPanel   LogsPanel
	logsViewer  *LogsViewer
	reportPane  *ReportPane
	confirm     *Confirm
	wizard      *Wizard
	banner      string
	streamState client.StreamState
	focus       panelFocus
	prevFocus   panelFocus

	width  int
	height int
}

func New(cfg Config, cli *client.Client, pipes []pipelines.Pipeline, plugins []client.PluginListEntry) App {
	a := App{
		cfg:         cfg,
		cli:         cli,
		pipes:       pipes,
		plugins:     plugins,
		scanList:    NewScanList(),
		scanDetail:  NewScanDetail(cli, cfg.PollInterval),
		logsPanel:   NewLogsPanel(cli, cfg.PollInterval),
		streamState: client.StreamConnecting,
		focus:       focusScans,
	}
	a.applyFocus()
	return a
}

func (a App) Init() tea.Cmd {
	// Polling and WS subscription are spawned from main as goroutines
	// that call program.Send — they don't need a tea.Cmd here.
	return nil
}

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = m.Width
		a.height = m.Height
		a.scanList.SetSize(a.leftPaneWidth(), a.bodyHeight())
		a.scanDetail.SetSize(a.rightPaneWidth(), a.tasksPaneHeight())
		a.logsPanel.SetSize(a.rightPaneWidth(), a.logsPaneHeight())
		a.applyFocus()
		if a.wizard != nil {
			a.wizard.SetSize(a.width, a.bodyHeight())
		}
		if a.logsViewer != nil {
			a.logsViewer.SetSize(a.width, a.bodyHeight())
		}
		if a.reportPane != nil {
			a.reportPane.SetSize(a.width, a.bodyHeight())
		}
		return a, nil

	case tea.KeyMsg:
		// Global Quit fires from anywhere except inside a text-accepting
		// overlay. Wizard always absorbs (multiple textareas/inputs); a
		// viewer absorbs only when its filename picker is open.
		if key.Matches(m, Keys.Quit) {
			textActive := a.wizard != nil ||
				(a.reportPane != nil && a.reportPane.picker != nil) ||
				(a.logsViewer != nil && a.logsViewer.picker != nil)
			if !textActive {
				return a, tea.Quit
			}
		}

		// Modals own all keystrokes when active.
		if a.wizard != nil {
			w, cmd := a.wizard.Update(m)
			a.wizard = &w
			return a, cmd
		}
		if a.confirm != nil {
			c, cmd := a.confirm.Update(m)
			a.confirm = &c
			return a, cmd
		}
		if a.reportPane != nil {
			p, cmd := a.reportPane.Update(m)
			a.reportPane = &p
			return a, cmd
		}
		if a.logsViewer != nil {
			v, cmd := a.logsViewer.Update(m)
			a.logsViewer = &v
			return a, cmd
		}
		// A dashboard error banner is user-dismissed: esc clears it and
		// consumes the keystroke so nothing else reacts to that press.
		if a.banner != "" && key.Matches(m, Keys.Back) {
			a.banner = ""
			return a, nil
		}
		// Tab cycling is global to the dashboard. Even when the scan
		// list filter is active, Tab moves focus away (filter buffer
		// preserved per spec).
		switch {
		case key.Matches(m, Keys.Tab):
			a.focus = (a.focus + 1) % panelFocusCount
			a.applyFocus()
			return a, nil
		case key.Matches(m, Keys.ShiftTab):
			a.focus = (a.focus + panelFocusCount - 1) % panelFocusCount
			a.applyFocus()
			return a, nil
		}
		// Scan list filter mode owns letter keys (but not Tab — handled
		// above). Other panels never enter "input mode."
		if a.focus == focusScans && a.scanList.Filtering() {
			var cmd tea.Cmd
			a.scanList, cmd = a.scanList.Update(m)
			return a, cmd
		}
		switch {
		case key.Matches(m, Keys.Quit):
			return a, tea.Quit
		case key.Matches(m, Keys.New):
			if a.cfg.ReadOnly {
				return a, nil
			}
			w := NewWizard(a.cfg, a.cli, a.pipes, a.plugins)
			w.SetSize(a.width, a.bodyHeight())
			a.wizard = &w
			return a, nil
		case key.Matches(m, Keys.Cancel):
			if a.cfg.ReadOnly {
				return a, nil
			}
			if id := a.scanList.SelectedID(); id != "" {
				c := NewConfirm(
					"Cancel scan?",
					"Scan "+id+" will be stopped.",
					cancelScanCmd(a.cli, id),
				)
				a.confirm = &c
			}
			return a, nil
		case key.Matches(m, Keys.Delete):
			if a.cfg.ReadOnly {
				return a, nil
			}
			if id := a.scanList.SelectedID(); id != "" {
				c := NewConfirm(
					"Delete scan?",
					"Scan "+id+" will be stopped and removed. This cannot be undone.",
					deleteScanCmd(a.cli, id),
				)
				a.confirm = &c
			}
			return a, nil
		case key.Matches(m, Keys.Logs):
			sid := a.scanList.SelectedID()
			if sid == "" {
				return a, nil
			}
			v := NewLogsViewer(a.cli, sid, a.scanList.SelectedStatus(), a.cfg.PollInterval)
			v.SetSize(a.width, a.bodyHeight())
			a.logsViewer = &v
			a.prevFocus = a.focus
			return a, v.InitCmd()
		case key.Matches(m, Keys.Report):
			sid := a.scanList.SelectedID()
			if sid == "" || !isTerminal(a.scanList.SelectedStatus()) {
				return a, nil
			}
			p := NewReportPane(a.cli, sid, a.scanList.SelectedStatus(), a.cfg.GlamourStyle)
			p.SetSize(a.width, a.bodyHeight())
			a.reportPane = &p
			a.prevFocus = a.focus
			return a, p.InitCmd()
		}
		// Routing per focused panel.
		switch a.focus {
		case focusScans:
			return a.dispatchToScanList(m)
		case focusTasks:
			prevTaskID := a.scanDetail.SelectedTaskID()
			var cmd tea.Cmd
			a.scanDetail, cmd = a.scanDetail.Update(m)
			if a.scanDetail.SelectedTaskID() != prevTaskID {
				var lpCmd tea.Cmd
				a.logsPanel, lpCmd = a.logsPanel.Update(a.currentLogsBinding())
				return a, tea.Batch(cmd, lpCmd)
			}
			return a, cmd
		case focusLogs:
			var cmd tea.Cmd
			a.logsPanel, cmd = a.logsPanel.Update(m)
			return a, cmd
		}
		return a, nil

	case confirmDoneMsg:
		a.confirm = nil
		return a, nil

	case wizardClosedMsg:
		a.wizard = nil
		return a, nil

	case client.ScanListSnapshot, client.ScanProgressUpdate, client.ScanRemoved:
		return a.dispatchToScanList(m)

	case focusChangedMsg, client.TaskStatusUpdate:
		prevTaskID := a.scanDetail.SelectedTaskID()
		var cmd tea.Cmd
		a.scanDetail, cmd = a.scanDetail.Update(m)
		if a.scanDetail.SelectedTaskID() != prevTaskID {
			var lpCmd tea.Cmd
			a.logsPanel, lpCmd = a.logsPanel.Update(a.currentLogsBinding())
			return a, tea.Batch(cmd, lpCmd)
		}
		return a, cmd

	case logsChunkMsg, logsDebounceFiredMsg, logsTickMsg:
		var cmd tea.Cmd
		a.logsPanel, cmd = a.logsPanel.Update(m)
		return a, cmd

	case logsViewerChunkMsg, logsViewerTickMsg:
		if a.logsViewer == nil {
			return a, nil // stale message after viewer closed
		}
		v, cmd := a.logsViewer.Update(m)
		a.logsViewer = &v
		return a, cmd

	case logsViewerClosedMsg:
		a.logsViewer = nil
		a.focus = a.prevFocus
		a.applyFocus()
		return a, nil

	case reportFetchedMsg, spinner.TickMsg:
		if a.reportPane == nil {
			return a, nil
		}
		p, cmd := a.reportPane.Update(m)
		a.reportPane = &p
		return a, cmd

	case reportPaneClosedMsg:
		a.reportPane = nil
		return a, nil

	case client.StreamStateChanged:
		a.streamState = m.State
		return a, nil

	case client.ScanCancelRequested:
		// No-op: the scanner publishes CANCELED via MQTT once it
		// processes the stop request, which arrives as a WS push and
		// updates the row in place.
		return a, nil

	case client.ScanDeleted:
		// /scan/delete is a synchronous DB cleanup with no MQTT/WS
		// broadcast — without an explicit refresh the deleted row
		// would linger here until restart. Fetch /scan/progress once;
		// the resulting snapshot replaces entries and the row is gone.
		return a, fetchProgressOnceCmd(a.cli)

	case backfillProgressMsg:
		// Triggered when ScanList saw a WS push for an unknown scan
		// without a progress value. Fetch the DB-authoritative state
		// once; the resulting ScanListSnapshot replaces entries via
		// the regular handler.
		return a, fetchProgressOnceCmd(a.cli)

	case client.ErrorMsg:
		// The banner stays until the user dismisses it with esc (handled
		// in the KeyMsg block) — never on a timer.
		a.banner = fmt.Sprintf("%s: %v", m.Op, m.Err)
		return a, nil
	}
	// Anything App didn't claim — forward to the active overlay so
	// its internal messages (picker confirms/cancels, save/export
	// results, banner expiries) flow through without an exhaustive
	// type-switch here. The overlays are mutually exclusive in
	// practice; the priority order mirrors the tea.KeyMsg block.
	if a.wizard != nil {
		w, cmd := a.wizard.Update(msg)
		a.wizard = &w
		return a, cmd
	}
	if a.reportPane != nil {
		p, cmd := a.reportPane.Update(msg)
		a.reportPane = &p
		return a, cmd
	}
	if a.logsViewer != nil {
		v, cmd := a.logsViewer.Update(msg)
		a.logsViewer = &v
		return a, cmd
	}
	return a, nil
}

// applyFocus syncs the focus enum onto each panel's `focused` flag so
// borders reflect the current focus.
func (a *App) applyFocus() {
	a.scanList.SetFocused(a.focus == focusScans)
	a.scanDetail.SetFocused(a.focus == focusTasks)
	a.logsPanel.SetFocused(a.focus == focusLogs)
}

// currentLogsBinding computes the inline Logs panel's binding from the
// scan list's selection, the task panel's cursor, and the selected
// scan's status. Empty strings/empty status are valid: the panel
// renders a "no task selected" state and skips polling.
func (a App) currentLogsBinding() logsBindingChangedMsg {
	return logsBindingChangedMsg{
		ScanID:     a.scanList.SelectedID(),
		TaskID:     a.scanDetail.SelectedTaskID(),
		ScanStatus: a.scanList.SelectedStatus(),
	}
}

// dispatchToScanList forwards a message to the ScanList and, if the
// selection changed as a result, also notifies ScanDetail to refocus.
func (a App) dispatchToScanList(msg tea.Msg) (tea.Model, tea.Cmd) {
	prevID := a.scanList.SelectedID()
	prevStatus := a.scanList.SelectedStatus()
	var slCmd tea.Cmd
	a.scanList, slCmd = a.scanList.Update(msg)
	currentID := a.scanList.SelectedID()
	currentStatus := a.scanList.SelectedStatus()
	cmds := []tea.Cmd{slCmd}
	if currentID != prevID {
		var sdCmd tea.Cmd
		a.scanDetail, sdCmd = a.scanDetail.Update(focusChangedMsg{ScanID: currentID})
		cmds = append(cmds, sdCmd)
	}
	if currentID != prevID || currentStatus != prevStatus {
		var lpCmd tea.Cmd
		a.logsPanel, lpCmd = a.logsPanel.Update(a.currentLogsBinding())
		cmds = append(cmds, lpCmd)
	}
	// Keep the open LogsViewer's cached scan status in sync with the
	// scan list. If the viewer's scan has reached a terminal state, this
	// lets the viewer's next tick observe isTerminal() and wind down its
	// polling without waiting for the user to close it.
	if a.logsViewer != nil {
		if newStatus := a.scanList.StatusByID(a.logsViewer.scanID); newStatus != "" && newStatus != a.logsViewer.scanStatus {
			a.logsViewer.SetScanStatus(newStatus)
		}
	}
	if a.reportPane != nil {
		if newStatus := a.scanList.StatusByID(a.reportPane.scanID); newStatus != "" && newStatus != a.reportPane.scanStatus {
			a.reportPane.SetScanStatus(newStatus)
		}
	}
	return a, tea.Batch(cmds...)
}

func (a App) View() string {
	if a.width == 0 || a.height == 0 {
		return ""
	}
	if a.width < minDashboardWidth || a.height < minDashboardHeight {
		return lipgloss.Place(
			a.width, a.height,
			lipgloss.Center, lipgloss.Center,
			BannerWarn.Render("⚠  terminal too small"),
		)
	}
	header := a.renderHeader()

	var body string
	switch {
	case a.wizard != nil:
		body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Center, lipgloss.Center, a.wizard.View())
	case a.confirm != nil:
		body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Center, lipgloss.Center, a.confirm.View())
	case a.reportPane != nil:
		body = a.reportPane.View()
	case a.logsViewer != nil:
		body = a.logsViewer.View()
	default:
		rightStack := lipgloss.JoinVertical(
			lipgloss.Left,
			a.scanDetail.View(),
			a.logsPanel.View(),
		)
		body = lipgloss.JoinHorizontal(
			lipgloss.Top,
			a.scanList.View(),
			rightStack,
		)
		body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Left, lipgloss.Top, body)
	}

	rows := []string{header}
	if a.banner != "" {
		rows = append(rows, BannerError.Width(a.width).Render(a.banner))
	}
	rows = append(rows, body, a.renderFooter())
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (a App) renderHeader() string {
	dot := "● "
	dotStyle := DotConnecting
	switch a.streamState {
	case client.StreamConnected:
		dotStyle = DotConnected
	case client.StreamDisconnected:
		dotStyle = DotDisconnected
	case client.StreamConnecting, client.StreamReconnecting:
		dotStyle = DotConnecting
	}
	left := AppTitle.Render("g3tui")
	right := HeaderBar.Render(dotStyle.Render(dot) + "srv=" + hostOf(a.cfg.BaseURL))
	gap := a.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

func (a App) renderFooter() string {
	textActive := a.wizard != nil ||
		(a.reportPane != nil && a.reportPane.picker != nil) ||
		(a.logsViewer != nil && a.logsViewer.picker != nil)
	bindings := []key.Binding{Keys.Quit}
	if !a.cfg.ReadOnly {
		bindings = append(bindings, Keys.New)
	}
	bindings = append(bindings, Keys.Help, Keys.Tab)
	switch {
	case a.wizard != nil:
		bindings = []key.Binding{}
		if !textActive {
			bindings = append(bindings, Keys.Quit)
		}
		bindings = append(bindings, a.wizard.Help()...)
	case a.confirm != nil:
		bindings = []key.Binding{Keys.Quit}
		bindings = append(bindings, a.confirm.Help()...)
	case a.reportPane != nil:
		bindings = []key.Binding{}
		if !textActive {
			bindings = append(bindings, Keys.Quit)
		}
		bindings = append(bindings, a.reportPane.Help()...)
	case a.logsViewer != nil:
		bindings = []key.Binding{}
		if !textActive {
			bindings = append(bindings, Keys.Quit)
		}
		bindings = append(bindings, a.logsViewer.Help()...)
	case a.scanList.Filtering():
		bindings = append(bindings, a.scanList.Help()...)
	default:
		switch a.focus {
		case focusScans:
			bindings = append(bindings, a.scanList.Help()...)
		case focusTasks:
			bindings = append(bindings, a.scanDetail.Help()...)
		case focusLogs:
			bindings = append(bindings, a.logsPanel.Help()...)
		}
		// Scan-scoped action hints visible in any focus state when a scan is
		// selected. `l` (open logs viewer) is focus-independent; Cancel and
		// Delete apply to any scan. Report only makes sense once the scan
		// has reached a terminal state.
		if a.scanList.SelectedID() != "" {
			bindings = append(bindings, Keys.Logs)
			if isTerminal(a.scanList.SelectedStatus()) {
				bindings = append(bindings, Keys.Report)
			}
			if !a.cfg.ReadOnly {
				bindings = append(bindings, Keys.Cancel, Keys.Delete)
			}
		}
	}
	parts := make([]string, 0, len(bindings))
	for _, b := range bindings {
		h := b.Help()
		parts = append(parts, h.Key+" "+h.Desc)
	}
	return FooterBar.Render(strings.Join(parts, " · "))
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

// leftPaneWidth sizes the scan-list panel to fit a full UUID (36
// chars) plus the "▸ " cursor prefix, accounting for the panel's
// border (2) and padding (2) chrome — that's 36 + 2 + 4 = 42, with 2
// extra cols of safety margin = 44. On narrow terminals (<100 cols)
// we degrade to half the screen and accept that the UUID may wrap.
func (a App) leftPaneWidth() int {
	if a.width >= 100 {
		return 44
	}
	return a.width / 2
}

func (a App) rightPaneWidth() int {
	return max(0, a.width-a.leftPaneWidth())
}

func (a App) bodyHeight() int {
	// Reserve 2 rows for header + footer (banner consumes one extra row
	// when active, accepted as a transient layout shift for v1).
	return max(0, a.height-2)
}

// tasksPaneHeight is the height of the Tasks panel (top half of the
// right side). The Tasks/Logs split is currently 50/50 of the body
// height; future iterations may make this user-movable.
func (a App) tasksPaneHeight() int {
	return a.bodyHeight() / 2
}

// logsPaneHeight is the height of the Logs panel (bottom half).
func (a App) logsPaneHeight() int {
	return a.bodyHeight() - a.tasksPaneHeight()
}

func fetchProgressOnceCmd(cli *client.Client) tea.Cmd {
	return func() tea.Msg {
		entries, err := cli.GetProgress(context.Background())
		if err != nil {
			return client.ErrorMsg{Op: "/scan/progress backfill", Err: err}
		}
		return client.ScanListSnapshot{Entries: entries}
	}
}

func cancelScanCmd(cli *client.Client, scanID string) tea.Cmd {
	return func() tea.Msg {
		if err := cli.StopScan(context.Background(), scanID); err != nil {
			return client.ErrorMsg{Op: "/scan/stop", Err: err}
		}
		return client.ScanCancelRequested{ScanID: scanID}
	}
}

func deleteScanCmd(cli *client.Client, scanID string) tea.Cmd {
	return func() tea.Msg {
		// Mirrors g3cli rm: stop first, then delete.
		if err := cli.StopScan(context.Background(), scanID); err != nil {
			return client.ErrorMsg{Op: "/scan/stop", Err: err}
		}
		if err := cli.DeleteScan(context.Background(), scanID); err != nil {
			return client.ErrorMsg{Op: "/scan/delete", Err: err}
		}
		return client.ScanDeleted{ScanID: scanID}
	}
}
