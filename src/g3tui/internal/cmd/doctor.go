package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kong"
	"github.com/gorilla/websocket"

	"golismero.com/g3tui/internal/client"
	"golismero.com/g3tui/internal/pipelines"
)

type DoctorCmd struct{}

type checkResult struct {
	ok     bool
	detail string
}

func (d *DoctorCmd) Run(kctx *kong.Context) error {
	_ = kctx

	// Load config but do not fail on missing server config — we want to
	// report which fields are missing rather than aborting.
	cfg, _ := loadConfig(false)

	w := os.Stdout
	fmt.Fprintf(w, "g3tui %s\n\n", Version)

	// Resolved-config table.
	fmt.Fprintln(w, "config:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	printConfigRow(tw, "G3_API_BASEURL", cfg.BaseURL, cfg.BaseURLSource)
	printConfigRow(tw, "G3_API_WSURL", cfg.WSURL, cfg.WSURLSource)
	printConfigRow(tw, "G3_API_TOKEN", redactToken(cfg.Token), cfg.TokenSource)
	printConfigRow(tw, "G3_PIPELINES_DIR", cfg.PipelinesDir, cfg.PipelinesDirSource)
	printConfigRow(tw, "G3_CMD_LOG_LEVEL", cfg.LogLevel, cfg.LogLevelSource)
	_ = tw.Flush()
	fmt.Fprintln(w)

	// Checks.
	var results []checkResult
	results = append(results, checkDotEnv())
	results = append(results, checkHTTP(cfg))
	results = append(results, checkWS(cfg))
	results = append(results, checkPipelines(cfg.PipelinesDir)...)

	fmt.Fprintln(w, "checks:")
	allOK := true
	for _, r := range results {
		mark := "✓"
		if !r.ok {
			mark = "✗"
			allOK = false
		}
		fmt.Fprintf(w, "  %s %s\n", mark, r.detail)
	}

	if !allOK {
		return fmt.Errorf("one or more checks failed")
	}
	return nil
}

func printConfigRow(w io.Writer, name, value, source string) {
	if value == "" {
		fmt.Fprintf(w, "  %s\t= (unset)\n", name)
		return
	}
	fmt.Fprintf(w, "  %s\t= %s\t(from %s)\n", name, value, source)
}

// redactToken returns "********" when a token is set, "(unset)" otherwise.
// Doctor must NEVER print the actual token value.
func redactToken(t string) string {
	if t == "" {
		return "(unset)"
	}
	return "********"
}

func checkDotEnv() checkResult {
	// g3lib.LoadDotEnvFile reads from the working directory by default. We
	// report presence as informational; absence is not a failure.
	if _, err := os.Stat(".env"); err == nil {
		abs, _ := filepath.Abs(".env")
		return checkResult{ok: true, detail: ".env file               found at " + abs}
	}
	return checkResult{ok: true, detail: ".env file               (not present; using env vars only)"}
}

func checkHTTP(cfg Config) checkResult {
	if cfg.BaseURL == "" || cfg.Token == "" {
		return checkResult{
			ok:     false,
			detail: "HTTP reachable          skipped: missing G3_API_BASEURL or G3_API_TOKEN",
		}
	}
	cli := client.New(cfg.BaseURL, cfg.WSURL, cfg.Token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := cli.ListPlugins(ctx); err != nil {
		return checkResult{
			ok:     false,
			detail: fmt.Sprintf("HTTP reachable          POST %s/plugin/list → %v", cfg.BaseURL, err),
		}
	}
	return checkResult{
		ok:     true,
		detail: fmt.Sprintf("HTTP reachable          POST %s/plugin/list → 200 (%dms)", cfg.BaseURL, time.Since(start).Milliseconds()),
	}
}

func checkWS(cfg Config) checkResult {
	if cfg.WSURL == "" {
		return checkResult{
			ok:     false,
			detail: "WebSocket reachable     skipped: missing G3_API_WSURL",
		}
	}
	u, err := url.Parse(cfg.WSURL)
	if err != nil {
		return checkResult{ok: false, detail: fmt.Sprintf("WebSocket reachable     bad URL %q: %v", cfg.WSURL, err)}
	}

	hdr := http.Header{}
	if cfg.Token != "" {
		hdr.Set("Authorization", "Bearer "+cfg.Token)
	}
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 5 * time.Second
	start := time.Now()
	conn, resp, err := dialer.Dial(u.String(), hdr)
	if err != nil {
		status := ""
		if resp != nil {
			status = fmt.Sprintf(" (HTTP %d)", resp.StatusCode)
			_ = resp.Body.Close()
		}
		return checkResult{
			ok:     false,
			detail: fmt.Sprintf("WebSocket reachable     %s → %v%s", cfg.WSURL, err, status),
		}
	}
	_ = conn.Close()
	return checkResult{
		ok:     true,
		detail: fmt.Sprintf("WebSocket reachable     %s → handshake OK (%dms)", cfg.WSURL, time.Since(start).Milliseconds()),
	}
}

func checkPipelines(userDir string) []checkResult {
	pipes, err := pipelines.Load(userDir)
	if err != nil {
		return []checkResult{{ok: false, detail: fmt.Sprintf("Pipelines               load failed: %v", err)}}
	}
	var embedded, user []string
	for _, p := range pipes {
		switch p.Source {
		case pipelines.SourceEmbedded:
			embedded = append(embedded, p.Name)
		case pipelines.SourceUser:
			user = append(user, p.Name)
		}
	}
	summary := fmt.Sprintf("Pipelines               %d embedded (%s), %d user", len(embedded), strings.Join(embedded, ", "), len(user))
	if len(user) > 0 {
		summary += " (" + strings.Join(user, ", ") + ")"
	}
	return []checkResult{{ok: true, detail: summary}}
}
