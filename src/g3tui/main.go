package main

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/termenv"
	"golismero.com/g3lib"
	log "golismero.com/g3log"
	"golismero.com/g3tui/internal/client"
	"golismero.com/g3tui/internal/pipelines"
	"golismero.com/g3tui/internal/ui"
)

// Version is overwritten at link time by release builds via
// -ldflags "-X main.Version=...". Stays "dev" for local builds.
var Version = "dev"

const (
	G3_API_BASEURL   = "G3_API_BASEURL"
	G3_API_WSURL     = "G3_API_WSURL"
	G3_API_TOKEN     = "G3_API_TOKEN"
	G3_PIPELINES_DIR = "G3_PIPELINES_DIR"
	G3_CMD_LOG_LEVEL = "G3_CMD_LOG_LEVEL"
)

type config struct {
	BaseURL      string
	WSURL        string
	Token        string
	PipelinesDir string
}

func loadConfig() (config, error) {
	g3lib.LoadDotEnvFile() //nolint:errcheck

	cfg := config{
		BaseURL:      os.Getenv(G3_API_BASEURL),
		WSURL:        os.Getenv(G3_API_WSURL),
		Token:        os.Getenv(G3_API_TOKEN),
		PipelinesDir: os.Getenv(G3_PIPELINES_DIR),
	}
	for name, v := range map[string]string{
		G3_API_BASEURL: cfg.BaseURL,
		G3_API_WSURL:   cfg.WSURL,
		G3_API_TOKEN:   cfg.Token,
	} {
		if v == "" {
			return cfg, fmt.Errorf("missing required environment variable: %s", name)
		}
	}
	return cfg, nil
}

func main() {
	log.InitLogger()
	if ll := os.Getenv(G3_CMD_LOG_LEVEL); ll != "" {
		log.SetLogLevel(ll)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Critical(err.Error())
		os.Exit(1)
	}

	pipes, err := pipelines.Load(cfg.PipelinesDir)
	if err != nil {
		log.Critical("failed to load pipelines: " + err.Error())
		os.Exit(1)
	}

	// Probe the terminal background ONCE here, before bubbletea takes over
	// stdin. Glamour's WithAutoStyle does the same OSC 11 probe internally,
	// but if called during the bubbletea event loop the asynchronous
	// response leaks into the input stream as garbage keystrokes (visible
	// in the save-mode FilePicker as `]11;rgb:...\` in the filename field).
	// By detecting at startup and passing the resolved style through, we
	// keep Glamour off the dynamic path entirely.
	glamourStyle := "dark"
	if !termenv.NewOutput(os.Stdout).HasDarkBackground() {
		glamourStyle = "light"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli := client.New(cfg.BaseURL, cfg.WSURL, cfg.Token)
	uiCfg := ui.Config{
		BaseURL:      cfg.BaseURL,
		WSURL:        cfg.WSURL,
		Token:        cfg.Token,
		GlamourStyle: glamourStyle,
	}

	// Seed the plugin list once at startup. On failure, fall through to
	// the RetryScreen — a small tea.Program that lets the user retry or
	// quit, and only returns the seeded data once a retry succeeds.
	plugins, err := cli.ListPlugins(ctx)
	if err != nil {
		rs := ui.NewRetryScreen(uiCfg, cli, err)
		final, runErr := tea.NewProgram(rs, tea.WithAltScreen()).Run()
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "tui error: %v\n", runErr)
			os.Exit(1)
		}
		var ok bool
		plugins, ok = final.(ui.RetryScreen).Outcome()
		if !ok {
			return // user quit at the retry screen
		}
	}

	app := ui.New(uiCfg, cli, pipes, plugins)
	program := tea.NewProgram(app, tea.WithAltScreen())

	// wsConnected tracks whether the scanprogress WS is currently up.
	// The polling fallback below skips fetches while WS is connected
	// (per design's "any Connected transition cancels the polling
	// fallback" rule); when the WS drops, polling resumes immediately.
	var wsConnected atomic.Bool

	// WS scanprogress subscription. Forwards messages to the TUI and
	// flips wsConnected on each state transition.
	go cli.SubscribeScanProgress(ctx, func(m tea.Msg) {
		program.Send(m)
		if ssc, ok := m.(client.StreamStateChanged); ok {
			wsConnected.Store(ssc.State == client.StreamConnected)
		}
	})

	// Polling fallback. Always running; suppresses its fetch while WS
	// is connected. Same context as the WS goroutine — both cancel
	// together when main returns.
	go client.Poll(ctx, 3*time.Second, "/scan/progress",
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
		fmt.Fprintf(os.Stderr, "tui error: %v\n", err)
		os.Exit(1)
	}
}
