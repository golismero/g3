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

// bannerExpiredMsg clears any active error banner ~5s after it appeared.
type bannerExpiredMsg struct{}

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
	confirm     *Confirm
	wizard      *Wizard
	banner      string
	streamState client.StreamState

	width  int
	height int
}

func New(cfg Config, cli *client.Client, pipes []pipelines.Pipeline, plugins []client.PluginListEntry) App {
	return App{
		cfg:         cfg,
		cli:         cli,
		pipes:       pipes,
		plugins:     plugins,
		scanList:    NewScanList(),
		scanDetail:  NewScanDetail(cli),
		streamState: client.StreamConnecting,
	}
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
		a.scanDetail.SetSize(a.rightPaneWidth(), a.bodyHeight())
		if a.wizard != nil {
			a.wizard.SetSize(a.width, a.bodyHeight())
		}
		return a, nil

	case tea.KeyMsg:
		// Wizard overlay owns all keystrokes when active.
		if a.wizard != nil {
			w, cmd := a.wizard.Update(m)
			a.wizard = &w
			return a, cmd
		}
		// Confirm overlay owns all keystrokes when active.
		if a.confirm != nil {
			c, cmd := a.confirm.Update(m)
			a.confirm = &c
			return a, cmd
		}
		// While ScanList owns keystrokes (filter mode), suppress global
		// keybinds — `q` should not quit the app while typing a filter.
		if a.scanList.Filtering() {
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
					"Scan "+short12(id)+" will be stopped.",
					cancelScanCmd(a.cli, id),
				)
				a.confirm = &c
			}
			return a, nil
		case key.Matches(m, Keys.Delete):
			if id := a.scanList.SelectedID(); id != "" {
				c := NewConfirm(
					"Delete scan?",
					"Scan "+short12(id)+" will be stopped and removed. This cannot be undone.",
					deleteScanCmd(a.cli, id),
				)
				a.confirm = &c
			}
			return a, nil
		}
		return a.dispatchToScanList(m)

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
	header := a.renderHeader()

	var body string
	switch {
	case a.wizard != nil:
		body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Center, lipgloss.Center, a.wizard.View())
	case a.confirm != nil:
		body = lipgloss.Place(a.width, a.bodyHeight(), lipgloss.Center, lipgloss.Center, a.confirm.View())
	default:
		body = lipgloss.JoinHorizontal(
			lipgloss.Top,
			a.scanList.View(),
			a.scanDetail.View(),
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
	bindings := []key.Binding{Keys.Quit, Keys.New, Keys.Help}
	switch {
	case a.wizard != nil:
		bindings = []key.Binding{Keys.Quit}
		bindings = append(bindings, a.wizard.Help()...)
	case a.confirm != nil:
		bindings = append(bindings, a.confirm.Help()...)
	case a.scanList.Filtering():
		bindings = append(bindings, a.scanList.Help()...)
	default:
		bindings = append(bindings, a.scanList.Help()...)
		if a.scanList.SelectedID() != "" {
			bindings = append(bindings, a.scanDetail.Help()...)
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

// leftPaneWidth fixes the scan-list panel at ~38 cols (per design spec)
// when the terminal is wide enough; degrades to half the width on narrow
// terminals.
func (a App) leftPaneWidth() int {
	if a.width >= 100 {
		return 38
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
