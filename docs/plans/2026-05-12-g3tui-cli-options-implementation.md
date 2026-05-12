# g3tui CLI options Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Kong-based CLI to `g3tui` covering global config overrides, run-time behavior toggles, and four utility subcommands (`run`, `doctor`, `pipelines`, `completions`), while preserving bare-launch dashboard behavior.

**Architecture:** Subcommands live under `src/g3tui/internal/cmd/` per Go convention for hidden-impl subcommands. `main.go` shrinks to a thin entrypoint that calls `cmd.Execute(Version)`. Behavior flags (`--no-ws`, `--poll-interval`, `--read-only`, `--theme`) thread through `ui.Config` into the existing dashboard model. Config precedence is `flag > env > .env > default`, resolved in one place (`internal/cmd/config.go`). Token is never accepted as a flag value (process-listing leak risk); `--token-file` reads from disk.

**Tech Stack:** Go 1.26.2 · `github.com/alecthomas/kong` v1.15.0 (matches g3cli) · `github.com/willabides/kongplete` (Tab-completion engine, new dep) · Bubble Tea (unchanged) · existing `g3tui/internal/{client,pipelines,ui}` packages.

**Design doc:** [`2026-05-12-g3tui-cli-options-design.md`](2026-05-12-g3tui-cli-options-design.md). Read first.

**User-owned constraints (carried in agent memory; flagged here so the plan is self-contained):**

- **No test code.** Agents do not write `_test.go` files, do not run binaries, do not hit live servers. Verification per task is strictly `go vet` + `go build`.
- **No git commits.** Agents do not run mutating git commands. The user commits at end of tier in one batch.
- **No formatting churn.** Match local style. Do not run `gofmt`/`goimports` reformat passes beyond what the language server does automatically inside an Edit.

---

## File Structure

**New files (all under `src/g3tui/internal/cmd/`):**

| File | Responsibility |
|---|---|
| `cli.go` | The `CLI` struct (root flags + subcommand fields), `Execute(version string) error`, kongplete wiring, run-only-flag-at-root suggestion handler. |
| `config.go` | `Config` struct + `loadConfig(cli *CLI, requireServer bool) (Config, error)` with `flag > env > .env > default` merge. Token-file reading with trim. |
| `run.go` | `RunCmd` struct + `Run(*kong.Context) error`. Ports today's dashboard launch sequence from `main.go`. |
| `doctor.go` | `DoctorCmd` struct + `Run`. Resolves config, redacts token, exercises `/plugin/list`, opens a WS handshake, loads pipelines verbosely. Exits non-zero on any failure. |
| `pipelines.go` | `PipelinesCmd`, `PipelinesListCmd`, `PipelinesValidateCmd` and their `Run` methods. |
| `completions.go` | `CompletionsCmd` struct + `Run`. Emits one of three vendored shell-registration snippets to stdout based on the `<shell>` positional. |

**Modified files:**

| File | Change |
|---|---|
| `src/g3tui/main.go` | Shrinks from ~100 lines to ~15. Calls `cmd.Execute(Version)`. |
| `src/g3tui/go.mod` / `go.sum` | Add `github.com/alecthomas/kong v1.15.0` and `github.com/willabides/kongplete` (latest). |
| `src/g3tui/internal/ui/app.go` | `Config` gains `PollInterval`, `NoWS`, `ReadOnly`. Dispatch and footer gate `n`/`c`/`d` on `ReadOnly`. |
| `src/g3tui/internal/ui/scandetail.go` | `NewScanDetail` takes `pollInterval time.Duration`. The two `2*time.Second` literals at lines 95 and 125 become `sd.pollInterval`. |
| `src/g3tui/internal/ui/logspanel.go` | `NewLogsPanel` takes `pollInterval time.Duration`. The package const `logsPollInterval` is removed; line 321 reads `lp.pollInterval`. |
| `src/g3tui/README.md` | New "Command-line options" section + an update to the "Configuration" section noting flag-level overrides. |

**Layering:** `main.go` → `internal/cmd/*` → `internal/{client,pipelines,ui}`. `internal/ui` MUST NOT import `internal/cmd`.

---

## Task ordering rationale

Tasks 1–2 add the new package and threaded fields **without** changing externally observable behavior — the binary still launches the dashboard exactly as today, with default values where new fields exist. Task 3 is the dependency add. Tasks 4–8 fill in each subcommand. Task 9 is the README. Build stays green at every checkpoint.

---

## Task 1: Extend `ui.Config` and thread `pollInterval`/`readOnly` through sub-models

Add the three new fields to `ui.Config`, thread `pollInterval` into the two sub-models that own hardcoded poll constants, and gate the destructive-key dispatch + footer hints on `readOnly`. `main.go` continues to construct `ui.Config` with defaults equal to today's literal values — behavior is unchanged.

**Files:**
- Modify: `src/g3tui/internal/ui/app.go` (Config struct, dispatch lines 184/189/199, footer lines 485/528, constructor calls 92/93/230)
- Modify: `src/g3tui/internal/ui/scandetail.go` (NewScanDetail signature, lines 95/125)
- Modify: `src/g3tui/internal/ui/logspanel.go` (NewLogsPanel signature, line 321, drop const at line 59)
- Modify: `src/g3tui/internal/ui/logsviewer.go` (NewLogsViewer signature, line 424 uses the dropped const)
- Modify: `src/g3tui/main.go` (ui.Config construction at lines 93–98)

- [ ] **Step 1: Extend `ui.Config` with the three new fields**

In `src/g3tui/internal/ui/app.go`, replace the existing `Config` struct (currently lines 18–23):

```go
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
```

`time` is already imported in this file (used elsewhere), so no import block change is needed.

- [ ] **Step 2: Thread `pollInterval` into `NewScanDetail`**

In `src/g3tui/internal/ui/scandetail.go`, change the `ScanDetail` struct (the `type ScanDetail struct {` block at line 27) to add a `pollInterval` field, and change `NewScanDetail`'s signature.

Locate the struct (it currently does not have a `pollInterval` field) and add the field. Then update the constructor at line 41:

```go
func NewScanDetail(cli *client.Client, pollInterval time.Duration) ScanDetail {
	return ScanDetail{
		cli:          cli,
		pollInterval: pollInterval,
		// ... preserve any existing initializers verbatim ...
	}
}
```

Replace the two `2 * time.Second` literals:

```go
// Line ~95 (was: return sd, sd.fetchLaterCmd(2 * time.Second))
return sd, sd.fetchLaterCmd(sd.pollInterval)

// Line ~125 (was: return sd, sd.fetchLaterCmd(2 * time.Second))
return sd, sd.fetchLaterCmd(sd.pollInterval)
```

If the struct is value-typed throughout (passed by value, as the `sd ScanDetail` receiver suggests), the field assignment in the constructor is sufficient. If the struct receiver functions mutate via pointer elsewhere, the pattern stays the same — read-only access.

- [ ] **Step 3: Thread `pollInterval` into `NewLogsPanel` and drop the package constant**

In `src/g3tui/internal/ui/logspanel.go`:

1. Delete the line `const logsPollInterval = 2 * time.Second` at line 59.
2. Add a `pollInterval time.Duration` field to the `LogsPanel` struct (find the struct definition and add the field).
3. Update the constructor at line 83:

```go
func NewLogsPanel(cli *client.Client, pollInterval time.Duration) LogsPanel {
	return LogsPanel{
		cli:          cli,
		pollInterval: pollInterval,
		// ... preserve any existing initializers verbatim ...
	}
}
```

4. Update the tea.Tick call at line 321:

```go
// Was: return tea.Tick(logsPollInterval, func(time.Time) tea.Msg {
return tea.Tick(lp.pollInterval, func(time.Time) tea.Msg {
```

The receiver name (`lp`, `l`, or whatever the file uses) must match the existing convention in that function — verify before saving.

- [ ] **Step 4: Update `App.New`'s call sites for the two constructors**

In `src/g3tui/internal/ui/app.go`, find the `func New(...)` (around line 80–95) and update the two construction lines (currently lines 92–93):

```go
// Was:
//   scanDetail:  NewScanDetail(cli),
//   logsPanel:   NewLogsPanel(cli),
scanDetail:  NewScanDetail(cli, cfg.PollInterval),
logsPanel:   NewLogsPanel(cli, cfg.PollInterval),
```

`cfg` is the `Config` parameter passed into `App.New`.

- [ ] **Step 5: Gate the New/Cancel/Delete dispatch on `cfg.ReadOnly`**

In `src/g3tui/internal/ui/app.go`, update the three dispatch cases (currently lines 184, 189, 199). Wrap each `case key.Matches(...)` body with a `!a.cfg.ReadOnly` guard. The simplest pattern:

```go
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
```

(The Delete case body must be reproduced in full — read the existing lines 199–210 of `app.go` and preserve them after the guard.)

- [ ] **Step 6: Gate footer hints on `cfg.ReadOnly`**

In `src/g3tui/internal/ui/app.go`, update `renderFooter`:

- Line ~485 currently reads: `bindings := []key.Binding{Keys.Quit, Keys.New, Keys.Help, Keys.Tab}`. Replace with:

```go
bindings := []key.Binding{Keys.Quit, Keys.Help, Keys.Tab}
if !a.cfg.ReadOnly {
	bindings = append([]key.Binding{Keys.Quit, Keys.New, Keys.Help, Keys.Tab}, bindings[1:]...)
}
```

Simpler, equivalent: always build the slice and skip `Keys.New` when read-only:

```go
bindings := []key.Binding{Keys.Quit}
if !a.cfg.ReadOnly {
	bindings = append(bindings, Keys.New)
}
bindings = append(bindings, Keys.Help, Keys.Tab)
```

Use the second form — it is easier to reason about.

- Line ~528 currently reads:

```go
bindings = append(bindings, Keys.Cancel, Keys.Delete)
```

Replace with:

```go
if !a.cfg.ReadOnly {
	bindings = append(bindings, Keys.Cancel, Keys.Delete)
}
```

Leave `Keys.Logs` and `Keys.Report` unchanged — both are read-only operations.

- [ ] **Step 7: Update `main.go` to pass non-zero defaults for the new fields**

In `src/g3tui/main.go`, locate the `uiCfg := ui.Config{...}` construction (around lines 93–98). Update it:

```go
uiCfg := ui.Config{
	BaseURL:      cfg.BaseURL,
	WSURL:        cfg.WSURL,
	Token:        cfg.Token,
	GlamourStyle: glamourStyle,
	PollInterval: 3 * time.Second,
	NoWS:         false,
	ReadOnly:     false,
}
```

This preserves today's behavior — 3s poll, WS enabled, full keymap. Task 5 (RunCmd) will replace these defaults with values from the parsed Kong struct, but at this checkpoint `main.go` is otherwise unchanged.

- [ ] **Step 8: Verify with vet and build**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both commands exit 0 with no output. If `go vet` flags unused `time` imports anywhere, audit the imports in the touched files.

---

## Task 2: Add `kong` and `kongplete` dependencies to g3tui's go.mod

`g3tui/go.mod` currently has no Kong dep. g3cli uses `github.com/alecthomas/kong v1.15.0`; match that version exactly to keep the repo on one Kong major. Kongplete is a new repo-wide dep — pin to its current latest.

**Files:**
- Modify: `src/g3tui/go.mod`
- Modify: `src/g3tui/go.sum`

- [ ] **Step 1: Add kong and kongplete**

```bash
cd src/g3tui
go get github.com/alecthomas/kong@v1.15.0
go get github.com/willabides/kongplete@latest
```

Both commands rewrite `go.mod` and `go.sum`. `kongplete` will pull in `github.com/posener/complete` and `github.com/riywo/loginshell` as transitive deps — that is expected.

- [ ] **Step 2: Tidy**

```bash
cd src/g3tui && go mod tidy
```

- [ ] **Step 3: Verify go.mod direct deps**

Read `src/g3tui/go.mod` and confirm the `require (...)` direct-dependency block now contains both:

```
github.com/alecthomas/kong v1.15.0
github.com/willabides/kongplete v<x.y.z>
```

If `kongplete` lands in the indirect block, it means no file in `internal/cmd/` imports it yet — that is fine for this checkpoint; later tasks will pull it up to direct automatically.

- [ ] **Step 4: Verify with vet and build**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both exit 0. No source files have changed; this only verifies the dep graph resolves.

---

## Task 3: Create `internal/cmd/cli.go` — CLI struct and dispatcher skeleton

Define the full Kong CLI struct with empty (return-nil) `Run` methods on every subcommand. Wire `kongplete.Complete` so Tab-completion is functional from day one even before subcommands have bodies. Implement the run-only-flag-at-root suggestion. Do not yet call this from `main.go`.

**Files:**
- Create: `src/g3tui/internal/cmd/cli.go`

- [ ] **Step 1: Create the file with the CLI struct, empty Run methods, and Execute**

Write `src/g3tui/internal/cmd/cli.go`:

```go
// Package cmd defines g3tui's Kong-based command-line surface. It exposes
// Execute, which main.go calls. Subcommand implementations live in sibling
// files (run.go, doctor.go, pipelines.go, completions.go); shared config
// loading lives in config.go.
package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/willabides/kongplete"
)

// runOnlyFlags lists flags that are valid only on the `run` subcommand. They
// must never be set at root level. The detector below uses this slice to
// produce a friendly suggestion when a user types e.g. `g3tui --no-ws` with
// no subcommand.
var runOnlyFlags = []string{"--no-ws", "--poll-interval", "--read-only", "--theme"}

// CLI is the root of the Kong model. Global flags apply to every subcommand,
// including the default `run`. Run-only flags live on RunCmd.
var CLI struct {
	Server       string           `help:"Override G3_API_BASEURL."`
	WS           string           `help:"Override G3_API_WSURL."`
	TokenFile    string           `type:"existingfile" help:"Read bearer token from file (overrides G3_API_TOKEN)."`
	PipelinesDir string           `type:"existingdir"  help:"Override G3_PIPELINES_DIR."`
	LogLevel     string           `enum:"CRITICAL,ERROR,WARN,INFO,DEBUG,," help:"Override G3_CMD_LOG_LEVEL."`
	Version      kong.VersionFlag `help:"Show version and exit."`

	Run         RunCmd         `cmd:"" aliases:"r" default:"withargs" help:"Launch the interactive dashboard."`
	Doctor      DoctorCmd      `cmd:"" aliases:"d"                    help:"Diagnose environment and server reachability."`
	Pipelines   PipelinesCmd   `cmd:"" aliases:"p"                    help:"List or validate pipelines."`
	Completions CompletionsCmd `cmd:"" aliases:"c"                    help:"Emit shell completion registration snippet."`
}

// Execute parses os.Args[1:] and dispatches to the selected subcommand.
// version is stamped into --version output. Returns the subcommand's error;
// callers (main.go) should exit non-zero on any non-nil return.
func Execute(version string) error {
	// Detect run-only flags at root level BEFORE handing args to Kong. If we
	// find one and no subcommand precedes it, Kong's default error would say
	// "unknown flag: --no-ws" which is unhelpful. We print a targeted
	// suggestion and exit non-zero.
	if hint := runOnlyFlagAtRoot(os.Args[1:]); hint != "" {
		fmt.Fprintln(os.Stderr, hint)
		return fmt.Errorf("run-only flag used at root")
	}

	parser := kong.Must(&CLI,
		kong.Name("g3tui"),
		kong.Description("Golismero3 — Interactive terminal UI."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
		kong.Vars{"version": version},
	)

	// Kongplete short-circuits when the shell has invoked us with COMP_LINE
	// set (the user pressed Tab). When invoked normally, this is a no-op.
	kongplete.Complete(parser)

	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	return ctx.Run()
}

// runOnlyFlagAtRoot returns a non-empty suggestion string if args contains a
// run-only flag with no `run` (or alias) preceding it. Order matters: we walk
// the args left-to-right, tracking whether we have seen a subcommand token.
func runOnlyFlagAtRoot(args []string) string {
	seenSubcommand := false
	subcommands := map[string]bool{
		"run": true, "r": true,
		"doctor": true, "d": true,
		"pipelines": true, "p": true,
		"completions": true, "c": true,
	}
	for _, a := range args {
		if subcommands[a] {
			seenSubcommand = true
			continue
		}
		if seenSubcommand {
			continue
		}
		// Strip "=value" if present (e.g. --poll-interval=5s).
		name := a
		if i := strings.IndexByte(a, '='); i >= 0 {
			name = a[:i]
		}
		for _, f := range runOnlyFlags {
			if name == f {
				return fmt.Sprintf("g3tui: %s is a run-only flag.\ndid you mean: g3tui run %s ?", name, name)
			}
		}
	}
	return ""
}

// Compile-time check that the Kong struct is well-formed. Catches malformed
// struct tags at package-init time rather than first invocation.
var _ = func() bool {
	_ = kong.Must(&CLI, kong.Vars{"version": "dev"})
	return true
}()

// _ = time.Second silences an unused-import warning until run.go references
// time. Once run.go lands, delete this line.
var _ = time.Second
```

The `time` import keeps `cli.go` self-contained for vet purposes until `run.go` lands. Delete the `var _ = time.Second` line in Task 4.

- [ ] **Step 2: Create empty subcommand placeholders**

Empty `Run` methods need somewhere to live. Create four sibling stubs — one file per subcommand from the start. `time.Duration` decodes natively in Kong (no custom decoder needed).

`src/g3tui/internal/cmd/run.go`:

```go
package cmd

import (
	"time"

	"github.com/alecthomas/kong"
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
	return nil
}
```

`src/g3tui/internal/cmd/doctor.go`:

```go
package cmd

import "github.com/alecthomas/kong"

type DoctorCmd struct{}

func (d *DoctorCmd) Run(kctx *kong.Context) error {
	_ = kctx
	return nil
}
```

`src/g3tui/internal/cmd/pipelines.go`:

```go
package cmd

import "github.com/alecthomas/kong"

type PipelinesCmd struct {
	List     PipelinesListCmd     `cmd:"" aliases:"l" default:"withargs" help:"List resolved pipelines."`
	Validate PipelinesValidateCmd `cmd:"" aliases:"v"                    help:"Validate one or more pipeline files."`
}

type PipelinesListCmd struct{}

func (p *PipelinesListCmd) Run(kctx *kong.Context) error {
	_ = kctx
	return nil
}

type PipelinesValidateCmd struct {
	Paths []string `arg:"" optional:"" type:"existingfile" help:"Pipeline files to validate. If omitted, validates everything `run` would load."`
}

func (p *PipelinesValidateCmd) Run(kctx *kong.Context) error {
	_ = kctx
	return nil
}
```

`src/g3tui/internal/cmd/completions.go`:

```go
package cmd

import "github.com/alecthomas/kong"

type CompletionsCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell."`
}

func (c *CompletionsCmd) Run(kctx *kong.Context) error {
	_ = kctx
	return nil
}
```

Once these four files exist, delete `var _ = time.Second` and the `time` import from `cli.go` (the package now uses `time` via `run.go`).

- [ ] **Step 3: Verify with vet and build**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both exit 0. The package compiles in isolation; `main.go` does not yet call it.

---

## Task 4: Create `internal/cmd/config.go` — config loader with precedence

Centralize the `flag > env > .env > default` resolution. The function is consumed by `RunCmd.Run` (which needs all fields) and `DoctorCmd.Run` (which also needs all fields); `PipelinesCmd` and `CompletionsCmd` do not require server config.

**Files:**
- Create: `src/g3tui/internal/cmd/config.go`

- [ ] **Step 1: Write the file**

`Config` carries provenance fields (`*Source`) for `doctor`'s resolved-config table. `loadConfig` reads `CLI` (the package-level Kong-parsed struct from `cli.go`) directly — no accessor interface — because both files live in the same package.

```go
package cmd

import (
	"fmt"
	"os"
	"strings"

	"golismero.com/g3lib"
)

const (
	EnvBaseURL      = "G3_API_BASEURL"
	EnvWSURL        = "G3_API_WSURL"
	EnvToken        = "G3_API_TOKEN"
	EnvPipelinesDir = "G3_PIPELINES_DIR"
	EnvLogLevel     = "G3_CMD_LOG_LEVEL"
)

type Config struct {
	BaseURL      string
	WSURL        string
	Token        string
	PipelinesDir string
	LogLevel     string

	// TokenSource and other *Source fields record provenance for `doctor`'s
	// resolved-config table. Values: "flag", "env", ".env" (we cannot
	// distinguish env from .env after LoadDotEnvFile, so .env is collapsed
	// into env for reporting purposes), or "default".
	BaseURLSource      string
	WSURLSource        string
	TokenSource        string
	PipelinesDirSource string
	LogLevelSource     string
}

// loadConfig merges CLI flags, environment, and built-in defaults. It calls
// g3lib.LoadDotEnvFile so any .env settings populate os.Environ before we
// resolve env-var values.
//
// requireServer == true means BaseURL, WSURL, and Token must all be set (by
// some level of the precedence chain); a missing one is a hard error. This
// is true for run and doctor; false for pipelines and completions.
func loadConfig(requireServer bool) (Config, error) {
	_ = g3lib.LoadDotEnvFile() // best-effort; missing .env is fine

	cfg := Config{}

	cfg.BaseURL, cfg.BaseURLSource = pick(CLI.Server, EnvBaseURL)
	cfg.WSURL, cfg.WSURLSource = pick(CLI.WS, EnvWSURL)
	cfg.PipelinesDir, cfg.PipelinesDirSource = pick(CLI.PipelinesDir, EnvPipelinesDir)
	cfg.LogLevel, cfg.LogLevelSource = pick(CLI.LogLevel, EnvLogLevel)

	// Token: --token-file always wins. If unset, fall back to env. If still
	// empty, that is fine for non-server commands; requireServer will catch.
	if CLI.TokenFile != "" {
		b, err := os.ReadFile(CLI.TokenFile)
		if err != nil {
			return cfg, fmt.Errorf("--token-file: %w", err)
		}
		cfg.Token = strings.TrimSpace(string(b))
		cfg.TokenSource = "flag"
	} else if v := os.Getenv(EnvToken); v != "" {
		cfg.Token = v
		cfg.TokenSource = "env"
	} else {
		cfg.Token = ""
		cfg.TokenSource = "default"
	}

	if requireServer {
		var missing []string
		if cfg.BaseURL == "" {
			missing = append(missing, EnvBaseURL)
		}
		if cfg.WSURL == "" {
			missing = append(missing, EnvWSURL)
		}
		if cfg.Token == "" {
			missing = append(missing, EnvToken)
		}
		if len(missing) > 0 {
			return cfg, fmt.Errorf("missing required configuration: %s (set via flag, env var, or .env)", strings.Join(missing, ", "))
		}
	}

	return cfg, nil
}

// pick returns the flag value when non-empty, else the env-var value, along
// with a source label ("flag", "env", or "default").
func pick(flag, envName string) (string, string) {
	if flag != "" {
		return flag, "flag"
	}
	if v := os.Getenv(envName); v != "" {
		return v, "env"
	}
	return "", "default"
}
```

- [ ] **Step 2: Verify with vet and build**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both exit 0. `loadConfig` is unused at this checkpoint — Go does not flag unused package-level functions, only unused locals.

---

## Task 5: Implement `RunCmd.Run` and rewrite `main.go` as the entrypoint

This is the largest swap: port the current `main.go` body into `RunCmd.Run`, wire the four run-only flags through, and shrink `main.go` to the thin dispatcher.

**Files:**
- Modify: `src/g3tui/internal/cmd/run.go` (replace the stub Run method)
- Modify: `src/g3tui/main.go` (rewrite end-to-end)

- [ ] **Step 1: Replace `internal/cmd/run.go` with the real implementation**

Overwrite the file's contents:

```go
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

	log "golismero.com/g3log"
	"golismero.com/g3tui/internal/client"
	"golismero.com/g3tui/internal/pipelines"
	"golismero.com/g3tui/internal/ui"
)

// Version is set by Execute (which receives it from main.go's ldflags-stamped
// var) so RunCmd does not need to import main. RunCmd.Run reads it for the
// retry-screen header and any future banner needs.
var Version = "dev"

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
```

- [ ] **Step 2: Update `cli.go` to propagate the version into `Version`**

In `src/g3tui/internal/cmd/cli.go`, modify `Execute`:

```go
func Execute(version string) error {
	Version = version // shared with run.go for any version-aware UI

	if hint := runOnlyFlagAtRoot(os.Args[1:]); hint != "" {
		fmt.Fprintln(os.Stderr, hint)
		return fmt.Errorf("run-only flag used at root")
	}

	parser := kong.Must(&CLI,
		kong.Name("g3tui"),
		kong.Description("Golismero3 — Interactive terminal UI."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
		kong.Vars{"version": version},
	)

	kongplete.Complete(parser)

	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	return ctx.Run()
}
```

Also remove the `var _ = time.Second` stub and the `time` import — `run.go` now imports `time`.

- [ ] **Step 3: Rewrite `main.go`**

Overwrite `src/g3tui/main.go`:

```go
package main

import (
	"errors"
	"fmt"
	"os"

	"golismero.com/g3tui/internal/cmd"
)

// Version is overwritten at link time by release builds via
// -ldflags "-X main.Version=...". Stays "dev" for local builds.
var Version = "dev"

func main() {
	err := cmd.Execute(Version)
	if err == nil {
		return
	}
	// cmd.ErrAlreadyReported means Execute already emitted user-facing
	// output (e.g. the run-only-flag-at-root suggestion). Exit non-zero
	// without re-printing the error.
	if !errors.Is(err, cmd.ErrAlreadyReported) {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}
```

That is the entire file. All env-var constants, config loading, logger init, glamour probe, ws/polling goroutines, and Bubble Tea startup move into `cmd.RunCmd.Run`.

- [ ] **Step 4: Verify with vet and build**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both exit 0. After this task the binary is functionally equivalent to today's `g3tui` when invoked as bare `g3tui` (kong dispatches to the default `Run` subcommand), and additionally supports `--server`, `--ws`, `--token-file`, `--pipelines-dir`, `--log-level`, `--no-ws`, `--poll-interval`, `--read-only`, `--theme`, and `--version`. The four utility subcommands still return nil (no-op).

---

## Task 6: Implement `DoctorCmd.Run`

Print resolved config (token redacted), check `.env` presence, exercise `/plugin/list`, open a WS handshake, load pipelines verbosely. Exit non-zero on any failure.

**Files:**
- Modify: `src/g3tui/internal/cmd/doctor.go` (replace stub)

- [ ] **Step 1: Replace doctor.go**

```go
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
	"time"

	"github.com/alecthomas/kong"
	"github.com/gorilla/websocket"

	"golismero.com/g3tui/internal/client"
	"golismero.com/g3tui/internal/pipelines"
)

type DoctorCmd struct{}

type checkResult struct {
	name   string
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
	printConfigRow(w, "G3_API_BASEURL  ", cfg.BaseURL, cfg.BaseURLSource)
	printConfigRow(w, "G3_API_WSURL    ", cfg.WSURL, cfg.WSURLSource)
	printConfigRow(w, "G3_API_TOKEN    ", redactToken(cfg.Token), cfg.TokenSource)
	printConfigRow(w, "G3_PIPELINES_DIR", cfg.PipelinesDir, cfg.PipelinesDirSource)
	printConfigRow(w, "G3_CMD_LOG_LEVEL", cfg.LogLevel, cfg.LogLevelSource)
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
		fmt.Fprintf(w, "  %s = (unset)\n", name)
		return
	}
	fmt.Fprintf(w, "  %s = %-40s (from %s)\n", name, value, source)
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
		return checkResult{name: ".env", ok: true, detail: ".env file               found at " + abs}
	}
	return checkResult{name: ".env", ok: true, detail: ".env file               (not present; using env vars only)"}
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
```

- [ ] **Step 2: Verify with vet and build**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both exit 0.

---

## Task 7: Implement `PipelinesCmd` (list + validate)

`pipelines list` prints a table of resolved scan types. `pipelines validate` runs each file through the same `validate` function `pipelines.Load` uses internally.

**Note:** the package's `validate` function is currently unexported. We need an exported wrapper. Add one in `src/g3tui/internal/pipelines/pipelines.go` rather than reimplement.

**Files:**
- Modify: `src/g3tui/internal/pipelines/pipelines.go` (add exported `Validate(content string) error`)
- Modify: `src/g3tui/internal/cmd/pipelines.go` (replace stubs)

- [ ] **Step 1: Export Validate in the pipelines package**

In `src/g3tui/internal/pipelines/pipelines.go`, immediately after the existing unexported `validate` function (around line 100), add:

```go
// Validate is the exported wrapper around validate. It is used by g3tui's
// `pipelines validate` subcommand to check user files without launching the
// TUI. The accepted content is pipeline-only (no synthetic mode/target
// lines); Validate wraps it internally before parsing.
func Validate(content string) error {
	return validate(content)
}
```

- [ ] **Step 2: Replace `internal/cmd/pipelines.go`**

```go
package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/alecthomas/kong"

	"golismero.com/g3tui/internal/pipelines"
)

type PipelinesCmd struct {
	List     PipelinesListCmd     `cmd:"" aliases:"l" default:"withargs" help:"List resolved pipelines."`
	Validate PipelinesValidateCmd `cmd:"" aliases:"v"                    help:"Validate one or more pipeline files."`
}

type PipelinesListCmd struct{}

func (p *PipelinesListCmd) Run(kctx *kong.Context) error {
	_ = kctx

	// pipelines list does not require server config.
	cfg, err := loadConfig(false)
	if err != nil {
		return err
	}

	pipes, err := pipelines.Load(cfg.PipelinesDir)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSOURCE")
	for _, pl := range pipes {
		source := "<embedded>"
		if pl.Source == pipelines.SourceUser {
			source = "<user>"
		}
		fmt.Fprintf(tw, "%s\t%s\n", pl.Name, source)
	}
	return tw.Flush()
}

type PipelinesValidateCmd struct {
	Paths []string `arg:"" optional:"" type:"existingfile" help:"Pipeline files to validate. Omit to validate all user files in the configured pipelines directory."`
}

func (p *PipelinesValidateCmd) Run(kctx *kong.Context) error {
	_ = kctx

	paths := p.Paths
	if len(paths) == 0 {
		// No paths: enumerate the user dir.
		cfg, err := loadConfig(false)
		if err != nil {
			return err
		}
		userDir := cfg.PipelinesDir
		if userDir == "" {
			home, _ := os.UserHomeDir()
			if home != "" {
				userDir = home + "/.config/g3tui/pipelines"
			}
		}
		if userDir == "" {
			return fmt.Errorf("no pipeline files specified and could not determine default pipelines directory")
		}
		entries, err := os.ReadDir(userDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "pipelines directory does not exist; nothing to validate:", userDir)
				return nil
			}
			return err
		}
		for _, e := range entries {
			if !e.IsDir() && hasSuffix(e.Name(), ".pipeline") {
				paths = append(paths, userDir+"/"+e.Name())
			}
		}
	}

	anyFailed := false
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stdout, "✗ %s    read error: %v\n", path, err)
			anyFailed = true
			continue
		}
		if err := pipelines.Validate(string(raw)); err != nil {
			fmt.Fprintf(os.Stdout, "✗ %s    %v\n", path, err)
			anyFailed = true
			continue
		}
		fmt.Fprintf(os.Stdout, "✓ %s\n", path)
	}

	if anyFailed {
		return fmt.Errorf("one or more files failed validation")
	}
	return nil
}

// hasSuffix is `strings.HasSuffix` inlined to avoid importing "strings" here
// just for one call — pipelines.go's only other strings use was in the
// deleted scaffolding.
func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
```

The `<embedded>` / `<user>` columns are coarser than the design's mockup, which showed full source paths. The current `pipelines.Pipeline` struct does not carry the source path — only name, source-kind, and content. A future enhancement can add a `Path` field; for v1 we report kind only. The `OVERRIDES` column likewise remains blank for v1 (the load-time override is detectable but not currently recorded; leaving the column header for forward compatibility).

- [ ] **Step 3: Verify with vet and build**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both exit 0.

---

## Task 8: Implement `CompletionsCmd`

Emit the kongplete-compatible registration snippet for the requested shell. The snippets are vendored from kongplete's source (MIT-licensed) with a header attribution. They are tiny (≤6 lines each); we do not import kongplete's `InstallCompletions` because it auto-detects shell via `loginshell`, which doesn't match the design's explicit positional.

**Files:**
- Modify: `src/g3tui/internal/cmd/completions.go` (replace stub)

- [ ] **Step 1: Replace completions.go**

```go
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
)

type CompletionsCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

// shellSnippets are the registration lines a user adds to their shell rc to
// enable Tab-completion for g3tui. The actual completion engine is provided
// by kongplete (invoked from cli.go's Execute) — these snippets only tell
// the shell to consult the binary on Tab.
//
// Adapted from github.com/WillAbides/kongplete (MIT) — same templates kongplete
// uses internally, vendored here so we can present them via an explicit
// shell positional rather than its auto-detect login-shell behavior.
var shellSnippets = map[string]string{
	"bash": "complete -C %s %s\n",
	"zsh": `autoload -U +X bashcompinit && bashcompinit
complete -C %s %s
`,
	"fish": `function __complete_%s
    set -lx COMP_LINE (commandline -cp)
    test -z (commandline -ct)
    and set COMP_LINE "$COMP_LINE "
    %s
end
complete -f -c %s -a "(__complete_%s)"
`,
}

func (c *CompletionsCmd) Run(kctx *kong.Context) error {
	_ = kctx

	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate g3tui executable: %w", err)
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return fmt.Errorf("resolve absolute path: %w", err)
	}

	const cmdName = "g3tui"
	tmpl, ok := shellSnippets[c.Shell]
	if !ok {
		return fmt.Errorf("unsupported shell %q (kong enum should have caught this)", c.Shell)
	}

	switch c.Shell {
	case "bash", "zsh":
		fmt.Fprintf(os.Stdout, tmpl, bin, cmdName)
	case "fish":
		// fish template uses cmdName four times and bin once.
		fmt.Fprintf(os.Stdout, tmpl, cmdName, bin, cmdName, cmdName)
	}
	return nil
}
```

- [ ] **Step 2: Verify with vet and build**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both exit 0.

---

## Task 9: Update `src/g3tui/README.md`

Add a "Command-line options" section. Update the "Configuration" section to mention flag-level overrides. Update the "Coexisting with g3cli" table if anything changed.

**Files:**
- Modify: `src/g3tui/README.md`

- [ ] **Step 1: Read the current README**

```bash
cat src/g3tui/README.md
```

(Required by the Edit tool's read-before-edit invariant.)

- [ ] **Step 2: Update the Configuration section**

Find the section starting with `## Configuration` (around line 32). The current text says `g3tui` reads `.env` and lists env vars. Insert, immediately before the "Required" table:

```markdown
Every required env var has a flag-level override; see `g3tui --help` for the full list. Precedence is **flag > env var > .env > built-in default**.
```

- [ ] **Step 3: Append a new "Command-line options" section after "Save paths and file safety"**

Insert before "## Coexisting with g3cli":

```markdown
## Command-line options

`g3tui` is a Kong-based CLI. With no arguments it launches the dashboard (the default `run` subcommand); subcommands provide non-interactive utilities.

```text
g3tui [GLOBAL FLAGS] [<subcommand> [SUBCOMMAND FLAGS]]
```

### Global flags

| Flag | Effect |
|---|---|
| `--server <url>` | Override `G3_API_BASEURL`. |
| `--ws <url>` | Override `G3_API_WSURL`. |
| `--token-file <path>` | Read bearer token from file (overrides `G3_API_TOKEN`). |
| `--pipelines-dir <dir>` | Override `G3_PIPELINES_DIR`. |
| `--log-level <level>` | Override `G3_CMD_LOG_LEVEL` (CRITICAL/ERROR/WARN/INFO/DEBUG). |
| `--version` | Print version and exit. |
| `--help` | Show help. |

There is intentionally no `--token` flag — bearer tokens leak via process listings. Use `--token-file` or the `G3_API_TOKEN` env var.

### Subcommands

| Subcommand | Alias | Purpose |
|---|---|---|
| `run` | `r` | Launch the dashboard (default). |
| `doctor` | `d` | Diagnose environment and server reachability. |
| `pipelines list` | `p l` | List resolved scan-type pipelines. |
| `pipelines validate` | `p v` | Validate one or more pipeline files. |
| `completions <shell>` | `c` | Emit shell completion registration snippet (`bash`, `zsh`, `fish`). |

### `run` flags

| Flag | Effect |
|---|---|
| `--no-ws` | Force HTTP polling; never open a WebSocket. |
| `--poll-interval <dur>` | Poll cadence; default `3s`. Applies to scan-progress, tasks, and inline logs uniformly. |
| `--read-only` | Disable destructive keys (`n`, `c`, `d`). The footer hints update accordingly. |
| `--theme dark\|light\|auto` | Force theme; default `auto` (current OSC 11 probe behavior). |

A `run`-scoped flag at the root level (e.g. `g3tui --no-ws` with no subcommand) produces a `did you mean: g3tui run --no-ws ?` suggestion and exits non-zero.

### Shell completion

Tab-completion is supported in `bash`, `zsh`, and `fish`. Install with:

```bash
# bash
g3tui completions bash >> ~/.bashrc

# zsh
g3tui completions zsh >> ~/.zshrc

# fish
g3tui completions fish >> ~/.config/fish/completions/g3tui.fish
```

The snippet registers `g3tui` for completion by pointing the shell back at the binary itself — the actual completion logic is baked into `g3tui`.
```

- [ ] **Step 4: Verify build (no Go change in this task, but be safe)**

```bash
cd src/g3tui && go vet ./... && go build ./...
```

Expected: both exit 0.

---

## Self-Review Checklist

After implementing all tasks, re-read the plan and the design doc together:

1. **Spec coverage**
   - [ ] Global flags `--server`, `--ws`, `--token-file`, `--pipelines-dir`, `--log-level`, `--version` — Task 3 (CLI struct) + Task 4 (loader). ✓
   - [ ] Run flags `--no-ws`, `--poll-interval`, `--read-only`, `--theme` — Task 1 (Config plumbing) + Task 5 (RunCmd.Run). ✓
   - [ ] `run` default-when-bare — Task 3 (`default:"withargs"`). ✓
   - [ ] `doctor` HTTP probe via existing `cli.ListPlugins` — Task 6. ✓
   - [ ] Doctor token redaction — Task 6 `redactToken`. ✓
   - [ ] `pipelines list` defaulting to `list` — Task 3 + Task 7. ✓
   - [ ] `pipelines validate` standalone — Task 7. ✓
   - [ ] `completions <shell>` with explicit positional — Task 8. ✓
   - [ ] Kongplete engine wired — Task 3 (`kongplete.Complete(parser)`). ✓
   - [ ] Run-only-flag-at-root suggestion — Task 3 `runOnlyFlagAtRoot`. ✓
   - [ ] Precedence flag > env > .env > default — Task 4 `loadConfig`/`pick`. ✓
   - [ ] `internal/cmd/` package layout — Tasks 3, 4, 5, 6, 7, 8. ✓
   - [ ] `ui.Config` extension — Task 1. ✓
   - [ ] README update — Task 9. ✓
   - [ ] Behavior contracts (test invariants in §"Behavior contracts" of design doc) — verifiable by user; agent does not write tests.

2. **Placeholder scan**
   - [ ] No "TBD", "TODO", "implement later" strings.
   - [ ] Every code step shows actual code, not a description.
   - [ ] "Step 1, similar to X" never appears — repeated patterns are written out per task.

3. **Type consistency**
   - [ ] `loadConfig(requireServer bool)` — same signature across run.go, doctor.go, pipelines.go.
   - [ ] `Config` struct fields — same names across config.go and consumers.
   - [ ] `ui.Config.PollInterval`, `NoWS`, `ReadOnly` — same names across app.go, scandetail.go, logspanel.go, run.go.
   - [ ] Constructor signature changes — `NewScanDetail(cli, pollInterval)` and `NewLogsPanel(cli, pollInterval)` consistent across struct, constructor, and call site in App.New.
