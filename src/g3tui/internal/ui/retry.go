package ui

import (
	"context"
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golismero.com/g3tui/internal/client"
)

// retrySeedResult carries the outcome of one /plugin/list retry attempt.
type retrySeedResult struct {
	plugins []client.PluginListEntry
	err     error
}

// RetryScreen runs as its own tea.Program before the dashboard. If the
// initial seed call to the API succeeds (the constructor's caller did
// it), this screen is skipped entirely. If it failed, the user gets a
// full-screen [R]etry / [Q]uit prompt and the dashboard only launches
// once a retry succeeds.
type RetryScreen struct {
	cfg Config
	cli *client.Client

	err      error
	plugins  []client.PluginListEntry
	retrying bool
	done     bool // a retry succeeded → tea.Quit emitted, plugins populated
	quit     bool // user pressed Q

	width  int
	height int
}

func NewRetryScreen(cfg Config, cli *client.Client, initialErr error) RetryScreen {
	return RetryScreen{cfg: cfg, cli: cli, err: initialErr}
}

func (r RetryScreen) Init() tea.Cmd { return nil }

func (r RetryScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		r.width = m.Width
		r.height = m.Height
		return r, nil

	case tea.KeyMsg:
		if r.retrying {
			return r, nil
		}
		switch {
		case key.Matches(m, Keys.Quit):
			r.quit = true
			return r, tea.Quit
		case key.Matches(m, Keys.Retry):
			r.retrying = true
			r.err = nil
			return r, r.retryCmd()
		}

	case retrySeedResult:
		r.retrying = false
		if m.err != nil {
			r.err = m.err
			return r, nil
		}
		r.plugins = m.plugins
		r.done = true
		return r, tea.Quit
	}
	return r, nil
}

func (r RetryScreen) retryCmd() tea.Cmd {
	cli := r.cli
	return func() tea.Msg {
		plugins, err := cli.ListPlugins(context.Background())
		return retrySeedResult{plugins: plugins, err: err}
	}
}

func (r RetryScreen) View() string {
	if r.width == 0 || r.height == 0 {
		return ""
	}
	title := AppTitle.Render("g3tui — connection failed")
	var body string
	switch {
	case r.retrying:
		body = "Retrying " + hostOf(r.cfg.BaseURL) + "…"
	case r.err != nil:
		body = fmt.Sprintf("Error: %v\n\nHost: %s\n\n[R] retry   [Q] quit", r.err, hostOf(r.cfg.BaseURL))
	}
	stack := lipgloss.JoinVertical(lipgloss.Center, title, "", body)
	return lipgloss.Place(r.width, r.height, lipgloss.Center, lipgloss.Center, stack)
}

// Outcome reports whether a retry succeeded and, if so, the seeded plugin
// list. Returns ([], false) when the user quit.
func (r RetryScreen) Outcome() ([]client.PluginListEntry, bool) {
	if r.quit || !r.done {
		return nil, false
	}
	return r.plugins, true
}
