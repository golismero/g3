package cmd

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kong"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/termenv"

	log "github.com/golismero/g3/src/g3log"
	"github.com/golismero/g3/src/g3tui/internal/client"
	"github.com/golismero/g3/src/g3tui/internal/pipelines"
	"github.com/golismero/g3/src/g3tui/internal/ui"
)

// RunCmd carries the run-only behavior flags. The default Theme value of
// "auto" preserves today's OSC 11 background-probe behavior.
type RunCmd struct {
	NoWS         bool          `help:"Force HTTP polling; never open a WebSocket."`
	PollInterval time.Duration `default:"3s" help:"Polling cadence (applies uniformly to scan-progress, tasks, and logs)."`
	ReadOnly     bool          `help:"Disable destructive keys (n/c/d) in the dashboard."`
	Theme        string        `enum:"dark,light,auto" default:"auto" help:"Force theme; skip OSC 11 probe."`
}

func (r *RunCmd) Run(kctx *kong.Context) error {
	_ = kctx

	cfg, err := loadConfig(true /* requireServer */)
	if err != nil {
		return err
	}

	log.InitLogger()
	if cfg.LogLevel != "" {
		log.SetLogLevel(cfg.LogLevel)
	}

	pipes, err := pipelines.Load(cfg.PipelinesDir)
	if err != nil {
		return fmt.Errorf("failed to load pipelines: %w", err)
	}

	// Resolve the Glamour style. --theme=auto preserves the historical OSC 11
	// probe; explicit dark/light skips the probe entirely (avoids the OSC 11
	// leak that bit the Tier 3 picker).
	glamourStyle := "dark"
	switch r.Theme {
	case "light":
		glamourStyle = "light"
	case "auto", "":
		if !termenv.NewOutput(os.Stdout).HasDarkBackground() {
			glamourStyle = "light"
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli := client.New(cfg.BaseURL, cfg.WSURL, cfg.Token)
	uiCfg := ui.Config{
		BaseURL:      cfg.BaseURL,
		WSURL:        cfg.WSURL,
		Token:        cfg.Token,
		GlamourStyle: glamourStyle,
		PollInterval: r.PollInterval,
		NoWS:         r.NoWS,
		ReadOnly:     r.ReadOnly,
	}

	plugins, err := cli.ListPlugins(ctx)
	if err != nil {
		rs := ui.NewRetryScreen(uiCfg, cli, err)
		final, runErr := tea.NewProgram(rs, tea.WithAltScreen()).Run()
		if runErr != nil {
			return fmt.Errorf("tui error: %w", runErr)
		}
		var ok bool
		plugins, ok = final.(ui.RetryScreen).Outcome()
		if !ok {
			return nil // user quit at the retry screen
		}
	}

	app := ui.New(uiCfg, cli, pipes, plugins)
	program := tea.NewProgram(app, tea.WithAltScreen())

	// WebSocket subscription. Suppressed when --no-ws is set; in that case
	// wsConnected stays false forever and the polling path runs continuously.
	var wsConnected atomic.Bool
	if !r.NoWS {
		go cli.SubscribeScanProgress(ctx, func(m tea.Msg) {
			program.Send(m)
			if ssc, ok := m.(client.StreamStateChanged); ok {
				wsConnected.Store(ssc.State == client.StreamConnected)
			}
		})
	}

	// Polling fallback. Always running; suppresses its fetch while WS is
	// connected (which never happens under --no-ws).
	go client.Poll(ctx, r.PollInterval, "/scan/progress",
		func(c context.Context) (tea.Msg, error) {
			if wsConnected.Load() {
				return nil, nil
			}
			entries, err := cli.GetProgress(c)
			if err != nil {
				return nil, err
			}
			return client.ScanListSnapshot{Entries: entries}, nil
		},
		func(m tea.Msg) { program.Send(m) },
	)

	if _, err := program.Run(); err != nil {
		return fmt.Errorf("tui error: %w", err)
	}
	return nil
}
