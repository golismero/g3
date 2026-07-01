// Package cmd defines g3tui's Kong-based command-line surface. It exposes
// Execute, which main.go calls. Most subcommand implementations live in
// sibling files (run.go, doctor.go, pipelines.go); the smaller completions
// subcommand is at the bottom of this file. Shared config loading lives in
// config.go.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/willabides/kongplete"

	"github.com/golismero/g3/src/g3"
)

// Version is set by Execute (which receives it from main.go's ldflags-stamped
// var) so subcommand implementations do not have to import main.
var Version = "dev"

// runOnlyFlags lists flags that are valid only on the `run` subcommand. The
// detector below uses this slice to produce a friendly suggestion when a user
// types e.g. `g3tui --no-ws` with no subcommand.
var runOnlyFlags = []string{"--no-ws", "--poll-interval", "--read-only", "--theme"}

// valueConsumingGlobals lists global flags that take a value as their next
// arg (e.g. `--server URL`). When the walker in runOnlyFlagAtRoot sees one
// of these without an embedded `=value`, it must skip the following token so
// the value is not mistaken for a subcommand name.
var valueConsumingGlobals = map[string]bool{
	"--server":        true,
	"--ws":            true,
	"--token-file":    true,
	"--pipelines-dir": true,
	"--log-level":     true,
}

// CLI is the root of the Kong model. Global flags apply to every subcommand,
// including the default `run`. Run-only flags live on RunCmd.
var CLI struct {
	Server       string           `help:"Override G3_API_BASEURL."`
	WS           string           `help:"Override G3_API_WSURL."`
	TokenFile    string           `type:"existingfile" help:"Read bearer token from file (overrides G3_API_TOKEN)."`
	PipelinesDir string           `type:"existingdir"  help:"Override G3_PIPELINES_DIR."`
	LogLevel     string           `enum:"CRITICAL,ERROR,WARN,INFO,DEBUG," default:"" help:"Override G3_CMD_LOG_LEVEL."`
	Version      kong.VersionFlag `help:"Show version and exit."`

	Run         RunCmd         `cmd:"" aliases:"r" default:"withargs" help:"Launch the interactive dashboard."`
	Doctor      DoctorCmd      `cmd:"" aliases:"d"                    help:"Diagnose environment and server reachability."`
	Pipelines   PipelinesCmd   `cmd:"" aliases:"p"                    help:"List or validate pipelines."`
	Completions CompletionsCmd `cmd:"" aliases:"c"                    help:"Emit shell completion registration snippet."`
}

// ErrAlreadyReported is a sentinel returned by Execute when it has already
// emitted user-facing output to stderr. main.go should exit non-zero but
// suppress its default error-print to avoid duplicating the message.
var ErrAlreadyReported = errors.New("already reported")

// Execute parses os.Args[1:] and dispatches to the selected subcommand.
// version is stamped into --version output and stored in package var Version
// for subcommands that want to surface it. Returns the subcommand's error;
// callers (main.go) should exit non-zero on any non-nil return.
func Execute(version string) error {
	Version = version

	if hint := runOnlyFlagAtRoot(os.Args[1:]); hint != "" {
		fmt.Fprintln(os.Stderr, hint)
		return ErrAlreadyReported
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
// run-only flag with no `run` (or alias) preceding it. Walks args left-to-
// right, tracking whether a subcommand token has been seen and accounting
// for value-consuming global flags whose argument could otherwise be
// misread as a subcommand.
func runOnlyFlagAtRoot(args []string) string {
	subcommands := map[string]bool{
		"run": true, "r": true,
		"doctor": true, "d": true,
		"pipelines": true, "p": true,
		"completions": true, "c": true,
	}
	seenSubcommand := false
	skipNextAsValue := false
	for _, a := range args {
		if skipNextAsValue {
			skipNextAsValue = false
			continue
		}
		if seenSubcommand {
			continue
		}

		// `--flag=value` carries its value inline; treat as a flag token.
		// `--flag value` (separate tokens) means the next token is the value.
		name := a
		hasEmbeddedValue := false
		if i := strings.IndexByte(a, '='); i >= 0 {
			name = a[:i]
			hasEmbeddedValue = true
		}

		if valueConsumingGlobals[name] && !hasEmbeddedValue {
			skipNextAsValue = true
			continue
		}

		if subcommands[a] {
			seenSubcommand = true
			continue
		}

		for _, f := range runOnlyFlags {
			if name == f {
				return fmt.Sprintf("g3tui: %s is a run-only flag.\ndid you mean: g3tui run %s ?", name, name)
			}
		}
	}
	return ""
}

// CompletionsCmd implements the `completions <shell>` subcommand. The actual
// snippet templates live in g3lib so g3 and g3cli can share them.
type CompletionsCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

func (c *CompletionsCmd) Run(kctx *kong.Context) error {
	_ = kctx
	return g3.EmitShellCompletion(c.Shell, "g3tui", os.Stdout)
}
