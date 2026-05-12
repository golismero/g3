# g3tui CLI options — design

**Date:** 2026-05-12
**Status:** Design
**Scope:** Add command-line options to `g3tui` to bring it on par with `g3cli`'s Kong-based CLI surface, while preserving the bare-launch dashboard behavior.

## Motivation

Today `g3tui` accepts no command-line arguments. All configuration is environment-driven (`G3_API_BASEURL`, `G3_API_WSURL`, `G3_API_TOKEN`, `G3_PIPELINES_DIR`, `G3_CMD_LOG_LEVEL`), and there are no utility subcommands for diagnostics or pipeline inspection. By contrast, `g3cli` exposes a full Kong CLI with ten commands and per-command flags.

`g3tui`'s use case differs from `g3cli` — it is an interactive session, not a one-shot command — so most of `g3cli`'s flags (`-o`, scan IDs, `-b`) do not translate. What does translate falls into three buckets:

1. **Config overrides** — flag-level alternatives to env vars, useful for ad-hoc dev/prod switching without editing `.env`.
2. **Behavior / transport toggles** — TUI-specific knobs (no-ws, poll-interval, read-only, theme) that have no env-var equivalent today.
3. **Utility subcommands** — non-interactive helpers (doctor, pipelines list/validate, completions) that surface information currently locked behind launching the TUI.

Deep-linking flags (e.g. `--scan <id>`, `--view report`) were considered and explicitly excluded from this design — they belong to a future iteration if at all.

## CLI surface

```
g3tui [GLOBAL FLAGS] [<subcommand> [SUBCOMMAND FLAGS]]
```

### Global flags (root-level; apply to every subcommand including the default `run`)

| Flag | Effect |
|---|---|
| `--server <url>` | Override `G3_API_BASEURL`. |
| `--ws <url>` | Override `G3_API_WSURL`. |
| `--token-file <path>` | Read bearer token from file (overrides `G3_API_TOKEN`). |
| `--pipelines-dir <dir>` | Override `G3_PIPELINES_DIR`. |
| `--log-level <level>` | Override `G3_CMD_LOG_LEVEL`. One of `CRITICAL`, `ERROR`, `WARN`, `INFO`, `DEBUG`. |
| `--version` | Print version and exit (Kong `VersionFlag`). |
| `--help` | Show help (Kong built-in). |

A bare `--token` flag is intentionally **not** provided — bearer tokens passed as process arguments leak via `ps`, shell history, and terminal scrollback. `--token-file` reads the token from disk; the value is trimmed of trailing whitespace (the common `echo "$token" > tokenfile` foot-gun) and never logged.

### Subcommands

| Subcommand | Alias | Purpose |
|---|---|---|
| `run` | `r` | Launch the dashboard. **Default** when no subcommand is given. |
| `doctor` | `d` | Diagnose environment and server reachability; exit. |
| `pipelines list` | `p l` | List resolved scan-type pipelines. **Default** when `g3tui pipelines` is given with no further argument. |
| `pipelines validate` | `p v` | Validate one or more pipeline files. |
| `completions` | `c` | Emit shell completions (`bash`, `zsh`, `fish`). |

There is no `version` subcommand — `--version` (Kong's `VersionFlag`) covers it.

The shell names `bash`/`zsh`/`fish` accepted by `completions` are an enum-restricted positional argument, not subcommands; they intentionally receive **no** single-letter aliases. `g3tui c b` would be harder to read than `g3tui c bash` and Kong has no native alias mechanism for an `enum` positional anyway.

### `run` flags (only valid on `run`)

| Flag | Effect |
|---|---|
| `--no-ws` | Skip the WebSocket subscription; rely solely on HTTP polling fallback. |
| `--poll-interval <duration>` | Polling cadence. Default `3s`. Applies uniformly to all three pollers (scan-progress, tasks, logs). The 250ms cursor-debounce in the inline logs view is unchanged — it is a render-coalesce, not a server poll. |
| `--read-only` | Suppress destructive keys (`n`, `c`, `d`) in the dashboard. The footer's hint string updates accordingly. |
| `--theme dark\|light\|auto` | Default `auto`. `auto` performs the current OSC 11 background probe at startup. `dark` and `light` skip the probe and force-set Glamour's style. |

If a `run`-scoped flag (e.g. `--no-ws`) is passed at root without a subcommand, the binary prints a helpful suggestion (`did you mean: g3tui run --no-ws ?`) and exits non-zero. This is implemented by intercepting Kong's parse error.

### Precedence

`flag > env var > .env file > built-in default`

All four levels resolve through a single `loadConfig()` in `internal/cmd/config.go`; no other code path consults env vars directly.

## Per-subcommand behavior

### `run` (default)

Today's dashboard launch sequence, parameterized by the four `run` flags:

- **`--no-ws`** — `main.go` does not spawn the `cli.SubscribeScanProgress` goroutine. The `wsConnected` atomic stays `false`, so the polling fallback runs continuously. The header connection-dot stays yellow (its existing "polling" state); no header-rendering change is required beyond a one-line tooltip noting `--no-ws`.
- **`--poll-interval`** — single knob threaded into all three pollers:
  - scan-progress: `client.Poll(ctx, 3*time.Second, "/scan/progress", …)` at [src/g3tui/main.go:139](../../src/g3tui/main.go#L139).
  - tasks-status: `sd.fetchLaterCmd(2 * time.Second)` at [src/g3tui/internal/ui/scandetail.go:95](../../src/g3tui/internal/ui/scandetail.go#L95) and [:125](../../src/g3tui/internal/ui/scandetail.go#L125) (uses `tea.Tick`, not `client.Poll`).
  - inline logs: `const logsPollInterval = 2 * time.Second` at [src/g3tui/internal/ui/logspanel.go:59](../../src/g3tui/internal/ui/logspanel.go#L59).

  These three live in different files and use different mechanisms (`client.Poll`, `tea.Tick`, and a package constant). The flag replaces each with `cfg.PollInterval`. The 250ms cursor-debounce at [src/g3tui/internal/ui/logspanel.go:56](../../src/g3tui/internal/ui/logspanel.go#L56) is **not** affected — it is a render-coalesce, not a server poll.
- **`--read-only`** — a `bool` carried in `ui.Config`. The dashboard's `Update` ignores `n`/`c`/`d` keypresses when set; the footer's hint computation drops those entries from the displayed string. Full-screen viewers (logs/report) need no change — their destructive operations are already absent.
- **`--theme`** — replaces the unconditional OSC 11 probe at [src/g3tui/main.go:84-87](../../src/g3tui/main.go#L84-L87). `auto` keeps the probe; `dark` / `light` skip it and force-set `glamourStyle`.

### `doctor`

Prints resolved config (token redacted), checks `.env` presence, exercises the same `POST /plugin/list` endpoint that `run` calls at startup (via the existing `cli.ListPlugins`), opens a WebSocket handshake against `G3_API_WSURL`, and loads pipelines with verbose per-file error reporting. Exits `0` if all checks pass, `1` otherwise.

```
$ g3tui doctor
g3tui dev
config:
  G3_API_BASEURL   = https://g3.lab/api          (from .env)
  G3_API_WSURL     = wss://g3.lab/ws             (from .env)
  G3_API_TOKEN     = ********                    (from env)        ✓ present
  G3_PIPELINES_DIR = ~/.config/g3tui/pipelines/  (default)
  G3_CMD_LOG_LEVEL = (unset)

checks:
  ✓ .env file               found at /home/u/.env
  ✓ HTTP reachable          POST https://g3.lab/api/plugin/list → 200 (124ms)
  ✓ WebSocket reachable     wss://g3.lab/ws → handshake OK (89ms)
  ✓ Pipelines               2 embedded (network, web), 1 user (kube)
                            ✗ ~/.config/g3tui/pipelines/broken.pipeline — syntax error at line 4

exit: 1
```

Token redaction: always show `********`, regardless of source. Show **whether** the token is set and **where** it came from, never the value itself. Doctor never writes the token to any log line at any log level.

Because `doctor`'s HTTP probe exercises the same code path `run` uses at launch, a green `doctor` guarantees a successful `run` startup.

### `pipelines list`

Lists resolved scan types (embedded + user). Invalid files are skipped silently — matching `run`'s behavior — and are surfaced via `doctor` or `pipelines validate`. The `pipelines.Pipeline` struct currently carries `Name`, `Source`, and `Content` but no source path, so the list shows the source as `<embedded>` or `<user>` rather than a full path; surfacing per-file paths and the override relationship would require extending the package and is deferred.

```
$ g3tui pipelines list
NAME     SOURCE
kube     <user>
network  <embedded>
web      <user>
```

`g3tui pipelines` with no subcommand defaults to `list`.

### `pipelines validate [<path>...]`

Validates pipeline files without launching the TUI. With no path arguments, validates everything `run` would load (embedded + user dir). Reports per-file syntax errors. Exits `0`/`1`.

```
$ g3tui pipelines validate ~/.config/g3tui/pipelines/*.pipeline
✓ kube.pipeline
✗ broken.pipeline    line 4: unexpected '|' at start of line
```

### `completions <shell>`

Kong has no built-in completion support, so g3tui uses [`willabides/kongplete`](https://github.com/WillAbides/kongplete) as the Tab-completion engine. Two pieces:

1. **Tab-completion introspection** — `kongplete.Complete(parser)` is called once in `cli.go` before `parser.Parse`. When the shell invokes `g3tui` with `COMP_LINE`/`COMP_POINT` set (i.e. the user pressed Tab), kongplete walks the Kong model, prints candidates, and exits. When invoked normally, the call is a no-op.
2. **Install-snippet emission** — the `completions <shell>` subcommand is a thin local wrapper around the three install snippets kongplete uses internally (one each for bash, zsh, fish; ~10 lines of shell per snippet). The subcommand emits the snippet for the explicitly requested shell to stdout. We do not use kongplete's `InstallCompletions` type directly — that uses `riywo/loginshell` auto-detection, which doesn't match this design's explicit-shell positional. Snippets are MIT-licensed, vendored verbatim with attribution.

```
$ g3tui completions bash >> ~/.bashrc           # install
$ eval "$(g3tui completions bash)"              # one-shot for current shell
```

Supports `bash`, `zsh`, `fish` via the `enum:"bash,zsh,fish"` positional. Adds two transitive deps: `willabides/kongplete` and `posener/complete`.

## File layout

Subcommands move to a new internal package; `main.go` becomes a thin entrypoint.

```
src/g3tui/
  main.go                # ~15 lines: kong.Parse + dispatch into internal/cmd
  internal/
    cmd/
      cli.go             # CLI struct + Execute(version, ...) + run-flag-at-root suggestion handler
      run.go             # RunCmd (existing dashboard launch logic, parameterized)
      doctor.go          # DoctorCmd
      pipelines.go       # PipelinesCmd, PipelinesListCmd, PipelinesValidateCmd
      completions.go     # CompletionsCmd
      config.go          # config struct + loadConfig() with flag/env/.env merge
    client/              # unchanged
    pipelines/           # unchanged
    ui/                  # ui.Config gains PollInterval, NoWS, ReadOnly fields
```

This matches Go convention for hidden subcommand implementations (`internal/cmd/`) — same layering as kubectl, gh, and similar Kong/Cobra apps. The `internal/` prefix is enforced by the compiler: nothing outside this module can import these packages, even accidentally.

Layering: `main.go` → `internal/cmd` → `internal/{client,pipelines,ui}`. `internal/ui` must never import `internal/cmd`.

## Kong wiring sketch

```go
// internal/cmd/cli.go

var CLI struct {
    Server       string           `help:"Override G3_API_BASEURL."`
    WS           string           `help:"Override G3_API_WSURL."`
    TokenFile    string           `type:"existingfile" help:"Read bearer token from file."`
    PipelinesDir string           `type:"existingdir"  help:"Override G3_PIPELINES_DIR."`
    LogLevel     string           `enum:"CRITICAL,ERROR,WARN,INFO,DEBUG," help:"Log verbosity."`
    Version      kong.VersionFlag `help:"Show version and exit."`

    Run         RunCmd         `cmd:"" aliases:"r" default:"withargs" help:"Launch the interactive dashboard."`
    Doctor      DoctorCmd      `cmd:"" aliases:"d"                    help:"Diagnose environment and server reachability."`
    Pipelines   PipelinesCmd   `cmd:"" aliases:"p"                    help:"List or validate pipelines."`
    Completions CompletionsCmd `cmd:"" aliases:"c"                    help:"Emit shell completions."`
}

type RunCmd struct {
    NoWS         bool          `help:"Force HTTP polling; never open a WebSocket."`
    PollInterval time.Duration `default:"3s" help:"Polling cadence (applies to all pollers)."`
    ReadOnly     bool          `help:"Disable destructive keys (n/c/d)."`
    Theme        string        `enum:"dark,light,auto" default:"auto" help:"Force theme; skip OSC 11 probe."`
}

type PipelinesCmd struct {
    List     PipelinesListCmd     `cmd:"" aliases:"l" default:"withargs" help:"List resolved pipelines."`
    Validate PipelinesValidateCmd `cmd:"" aliases:"v"                    help:"Validate one or more pipeline files."`
}
```

`default:"withargs"` on `Run` is what routes bare `g3tui` to the dashboard. The same tag on `PipelinesListCmd` makes `g3tui pipelines` default to listing.

## Config plumbing

The current `loadConfig()` reads env vars only. The new version takes the parsed `CLI` struct and merges flags into the same config shape:

```go
// internal/cmd/config.go

type Config struct {
    BaseURL      string
    WSURL        string
    Token        string
    PipelinesDir string
    LogLevel     string
}

func loadConfig(cli *CLI) (Config, error) {
    g3lib.LoadDotEnvFile()  // .env contributes to os.Environ()

    cfg := Config{
        BaseURL:      pick(cli.Server, os.Getenv("G3_API_BASEURL")),
        WSURL:        pick(cli.WS, os.Getenv("G3_API_WSURL")),
        PipelinesDir: pick(cli.PipelinesDir, os.Getenv("G3_PIPELINES_DIR")),
        LogLevel:     pick(cli.LogLevel, os.Getenv("G3_CMD_LOG_LEVEL")),
    }

    if cli.TokenFile != "" {
        b, err := os.ReadFile(cli.TokenFile)
        if err != nil {
            return cfg, fmt.Errorf("--token-file: %w", err)
        }
        cfg.Token = strings.TrimSpace(string(b))
    } else {
        cfg.Token = os.Getenv("G3_API_TOKEN")
    }

    // Validate required fields for the active subcommand.
    return cfg, nil
}

func pick(flag, env string) string {
    if flag != "" {
        return flag
    }
    return env
}
```

`run` and `doctor` require `BaseURL`, `WSURL`, `Token`. `pipelines list/validate` and `completions` do **not** require server config and should not fail when those env vars are missing.

## ui.Config additions

```go
// internal/ui/...

type Config struct {
    BaseURL      string
    WSURL        string
    Token        string
    GlamourStyle string

    // added:
    PollInterval time.Duration
    NoWS         bool
    ReadOnly     bool
}
```

`main.go` (or `internal/cmd/run.go`) reads `cfg.NoWS` and decides whether to spawn the WebSocket goroutine. The `cli.Poll(ctx, cfg.PollInterval, …)` call replaces the hardcoded `3*time.Second`. The dashboard model's `Update` and footer-rendering both check `cfg.ReadOnly`.

## Behavior contracts (testable invariants)

- Bare `g3tui` launches the dashboard identically to `g3tui run` with no flags.
- `g3tui --server X` (no subcommand) launches the dashboard with the overridden server.
- `g3tui --no-ws` (no subcommand) prints `did you mean: g3tui run --no-ws ?` and exits non-zero.
- `g3tui doctor` exit code is `0` iff every check passes.
- `g3tui pipelines list` does not require server env vars to be set.
- `g3tui --version` does not require server env vars to be set.
- The bearer token never appears in any log line, regardless of log level or source (env, file, .env).
- Precedence `flag > env > .env > default` holds for every config field.

## Out of scope (deferred)

- Deep-linking flags (`--scan <id>`, `--view report|logs`, `--target <ip>` to prefill the wizard).
- Configuration file beyond `.env` (no TOML/YAML config support).
- An interactive `doctor --fix` mode.
- Persisting per-user dashboard preferences (theme, poll-interval) to a config file.
- Telemetry / usage flags (`--anonymous-stats`).

## References

- [src/g3cli/g3cli.go](../../src/g3cli/g3cli.go) — Kong CLI reference for command and flag conventions.
- [src/g3tui/main.go](../../src/g3tui/main.go) — current entrypoint to be split.
- [src/g3tui/README.md](../../src/g3tui/README.md) — coexistence table with g3cli; will be updated.
- [Kong](https://github.com/alecthomas/kong) — `default:"withargs"`, `aliases:""`, `VersionFlag`, completions.
