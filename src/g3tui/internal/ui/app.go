package ui

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golismero.com/g3tui/internal/client"
	"golismero.com/g3tui/internal/pipelines"
)

type Config struct {
	BaseURL string
	WSURL   string
	Token   string
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

// bannerExpiredMsg clears any active error banner ~5s after it appeared.
type bannerExpiredMsg struct{}

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
	confirm     *Confirm
	wizard      *Wizard
	banner      string
	streamState client.StreamState
	focus       panelFocus

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
		scanDetail:  NewScanDetail(cli),
		logsPanel:   NewLogsPanel(),
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
		return a, nil

	case tea.KeyMsg:
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
			w := NewWizard(a.cfg, a.cli, a.pipes, a.plugins)
			w.SetSize(a.width, a.bodyHeight())
			a.wizard = &w
			return a, nil
		case key.Matches(m, Keys.Cancel):
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
			// `l` is the one focus-aware action. Tasks-focused →
			// per-task logs viewer; Scans-focused → multi-task logs
			// for the scan. Both viewers are deferred to a follow-up.
			switch a.focus {
			case focusTasks:
				if tid := a.scanDetail.SelectedTaskID(); tid != "" {
					a.banner = "logs viewer for task " + tid + " — coming in a follow-up release"
					return a, tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpiredMsg{} })
				}
			case focusScans:
				if sid := a.scanList.SelectedID(); sid != "" {
					a.banner = "scan logs viewer — coming in a follow-up release"
					return a, tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpiredMsg{} })
				}
			}
			return a, nil
		}
		// Routing per focused panel.
		switch a.focus {
		case focusScans:
			return a.dispatchToScanList(m)
		case focusTasks:
			var cmd tea.Cmd
			a.scanDetail, cmd = a.scanDetail.Update(m)
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

	case client.ScanListSnapshot, client.ScanProgressUpdate:
		return a.dispatchToScanList(m)

	case focusChangedMsg, client.TaskStatusUpdate:
		var cmd tea.Cmd
		a.scanDetail, cmd = a.scanDetail.Update(m)
		return a, cmd

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
		a.banner = fmt.Sprintf("%s: %v", m.Op, m.Err)
		return a, tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpiredMsg{} })

	case bannerExpiredMsg:
		a.banner = ""
		return a, nil
	}
	// Anything App didn't claim — forward to the wizard if active.
	// This keeps wizard-internal messages (submit results, banner
	// expiry) flowing through without an exhaustive type-switch here.
	if a.wizard != nil {
		w, cmd := a.wizard.Update(msg)
		a.wizard = &w
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

// dispatchToScanList forwards a message to the ScanList and, if the
// selection changed as a result, also notifies ScanDetail to refocus.
func (a App) dispatchToScanList(msg tea.Msg) (tea.Model, tea.Cmd) {
	prev := a.scanList.SelectedID()
	var slCmd tea.Cmd
	a.scanList, slCmd = a.scanList.Update(msg)
	current := a.scanList.SelectedID()
	if current != prev {
		var sdCmd tea.Cmd
		a.scanDetail, sdCmd = a.scanDetail.Update(focusChangedMsg{ScanID: current})
		return a, tea.Batch(slCmd, sdCmd)
	}
	return a, slCmd
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
	bindings := []key.Binding{Keys.Quit, Keys.New, Keys.Help, Keys.Tab}
	switch {
	case a.wizard != nil:
		bindings = []key.Binding{Keys.Quit}
		bindings = append(bindings, a.wizard.Help()...)
	case a.confirm != nil:
		bindings = []key.Binding{Keys.Quit}
		bindings = append(bindings, a.confirm.Help()...)
	case a.scanList.Filtering():
		bindings = append(bindings, a.scanList.Help()...)
	default:
		switch a.focus {
		case focusScans:
			bindings = append(bindings, a.scanList.Help()...)
			if a.scanList.SelectedID() != "" {
				bindings = append(bindings, Keys.Logs, Keys.Report, Keys.Cancel, Keys.Delete)
			}
		case focusTasks:
			bindings = append(bindings, a.scanDetail.Help()...)
		case focusLogs:
			// LogsPanel.Help() returns nil until Tier 3 implements it.
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
