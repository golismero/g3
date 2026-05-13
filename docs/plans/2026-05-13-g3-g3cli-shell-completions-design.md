# g3 + g3cli shell completions — design

**Status:** design
**Date:** 2026-05-13
**Author:** Mario Vilas (with Claude)

## Background

`g3tui` shipped shell completions in commit `8bc0bc7` ("Added command line switches to g3tui"). The integration uses the [kongplete](https://github.com/willabides/kongplete) engine plus a `completions <shell>` subcommand that emits a one-line registration snippet the user pastes into their rc file. Tab-completion candidates come from the binary itself — the snippet just points the shell back at `g3tui` whenever Tab is pressed.

This spec extends the same feature to the other two Kong-based CLIs in `src/`: `g3` and `g3cli`. Both have rich subcommand surfaces (9 and 11 subcommands respectively, each with single-letter aliases) and benefit directly from Tab completion.

## Scope

In scope:

- **`g3lib`** — add a shared `EmitShellCompletion` helper so the three CLIs don't drift on snippet output.
- **`g3`** — add `completions` subcommand (alias `c`), wire `kongplete.Complete(parser)`.
- **`g3cli`** — add `completions` subcommand (no alias; `c` is taken by `Cancel`), wire `kongplete.Complete(parser)`.
- **`g3tui`** — delete `internal/cmd/completions.go` and fold the `CompletionsCmd` struct + 1-line `Run` into `internal/cmd/cli.go` next to the rest of the kong model. Public CLI surface is unchanged; the file disappears because once the snippet templates move to `g3lib`, what remains is too small to justify a dedicated file.
- **Root `Makefile`** — extend the `install` target to register completions for `g3`, `g3cli`, `g3tui` in system completion directories on Linux and macOS. Add a sibling `uninstall` target that reverses both the symlinks and the completion files.

Out of scope:

- **`g3api`, `g3scanner`, `g3worker`** — daemons. They take only environment variables, no flags or subcommands. Completion has no surface to drive.
- **`g3config`** — uses `spf13/pflag`, not Kong. `kongplete` is Kong-only, so adding completions there would require either rewriting its CLI on Kong or hand-rolling completion logic. Both are larger than this change warrants.
- **README install docs** for `g3` and `g3cli`. The subcommand's `--help` output documents the three shells; full install snippets can be added in a follow-up if the user wants them.

## Design

### Shared helper — `src/g3lib/completion.go` (new file)

Single exported function:

```go
// EmitShellCompletion writes a shell-registration snippet for cmdName to w.
// shell must be "bash", "zsh", or "fish"; any other value returns an error.
// The binary path embedded in the snippet is resolved via os.Executable()
// and made absolute, so the snippet keeps working regardless of $PATH.
func EmitShellCompletion(shell, cmdName string, w io.Writer) error
```

Implementation lifts the three templates verbatim from
`src/g3tui/internal/cmd/completions.go` (which were themselves adapted from
kongplete's MIT-licensed templates). The function:

1. Calls `os.Executable()` and `filepath.Abs()` to get the absolute binary path. Wraps both errors with descriptive context.
2. Looks up the template for `shell` from a `map[string]string`. Returns `fmt.Errorf("unsupported shell %q", shell)` if not found.
3. Switches on `shell` to fill in the template — `bash`/`zsh` take `(bin, cmdName)`; `fish` takes `(cmdName, bin, cmdName, cmdName)`.
4. Writes the formatted snippet to `w` via `fmt.Fprintf`.

Dependencies: stdlib only (`fmt`, `io`, `os`, `path/filepath`). No change to `src/g3lib/go.mod`.

### `g3` — `src/g3/g3.go` (edit)

**Imports** — add:
- `"strings"` (for the `kctx.Command()` prefix check)
- `"github.com/willabides/kongplete"`

**CLI struct** — add to the existing block at line 91:

```go
Completions CompletionsCmd `cmd:"" aliases:"c" help:"Emit shell completion registration snippet."`
```

`c` is free in `g3`'s alias set (the existing aliases are `s, t, p, i, r, m, j, f, o`).

**New type and method:**

```go
type CompletionsCmd struct {
    Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

func (c *CompletionsCmd) Run() error {
    return g3lib.EmitShellCompletion(c.Shell, "g3", os.Stdout)
}
```

The receiver method takes no arguments. Kong's reflection-based dispatcher will accept this and call it with no bindings — `CmdContext` (passed to `parser.Run(cmdctx)` at line 165) is registered but not required by this command.

**Parser construction (replace lines 113-118):**

```go
parser := kong.Must(&CLI,
    kong.Name("g3"),
    kong.Description("Golismero3 - The Pentesting Swiss Army Knife"),
    kong.UsageOnError(),
    kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
)
kongplete.Complete(parser)
kctx, err := parser.Parse(os.Args[1:])
parser.FatalIfErrorf(err)
```

`kong.Parse` is a convenience wrapper around `Must` + `Parse`. Splitting them lets `kongplete.Complete(parser)` hook in between construction and parsing. When the shell invokes the binary with `COMP_LINE` set, kongplete emits candidates and calls `os.Exit(0)` from inside `Complete`. In normal invocation it's a no-op.

**Early-exit for completions (new, immediately after the new `parser.FatalIfErrorf(err)`, before the existing `g3lib.LoadDotEnvFile()` call at line 121):**

```go
if strings.HasPrefix(kctx.Command(), "completions ") {
    parser.FatalIfErrorf(kctx.Run())
    return
}
```

Reason: `g3.go:130` calls `LoadPlugins()` and exits with `"No plugins found!"` if the registry is empty (e.g., a fresh install where `g3config` hasn't been run yet). Running `g3 completions bash` from such a setup must not fail — the user is trying to set up their shell, not run a scan. The early-exit branch bypasses `LoadDotEnvFile`, `LoadPlugins`, signal handling, and the cancellation goroutine for completion calls.

`kctx.Command()` returns the dotted path of the selected command. For `g3 completions bash` it returns `"completions <shell>"` (kong renders positional args with their `<name>` placeholder). The `HasPrefix` check is the documented way to match a subcommand regardless of which positional value was passed.

`parser.Run(cmdctx)` at line 165 stays as the final dispatch site for all other commands. Its argument (`cmdctx`) is constructed only on the non-completions path, so plugins/context/signals are still wired exactly as before for real scans.

### `g3cli` — `src/g3cli/g3cli.go` (edit)

Same pattern as `g3` with these differences:

1. **No alias** on the `Completions` field — `c` is taken by `Cancel` at line 107. The added line is:
   ```go
   Completions CompletionsCmd `cmd:"" help:"Emit shell completion registration snippet."`
   ```
2. The early-exit branch must precede the env-var checks at lines 144-162 (which `os.Exit(1)` on missing `G3_API_BASEURL` / `G3_API_WSURL` / `G3_API_TOKEN`). Place it immediately after the new `parser.FatalIfErrorf(err)`, before the existing `g3lib.LoadDotEnvFile()` call at line 127:
   ```go
   if strings.HasPrefix(kctx.Command(), "completions ") {
       parser.FatalIfErrorf(kctx.Run())
       return
   }
   ```
3. `CompletionsCmd.Run()` calls `g3lib.EmitShellCompletion(c.Shell, "g3cli", os.Stdout)`.

### `g3tui` — delete `src/g3tui/internal/cmd/completions.go`, consolidate into `cli.go`

Once the snippet templates move to `g3lib`, what's left for g3tui is a 5-line struct and a 1-line `Run` method — too small to justify its own file. Delete `internal/cmd/completions.go` and add the following to `internal/cmd/cli.go` alongside the existing CLI struct definition:

```go
type CompletionsCmd struct {
    Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

func (c *CompletionsCmd) Run(kctx *kong.Context) error {
    _ = kctx
    return g3lib.EmitShellCompletion(c.Shell, "g3tui", os.Stdout)
}
```

Notes:

- `cli.go` already imports `kong`; add `"os"` and `"golismero.com/g3lib"` to its import block.
- The `kong.Context` arg stays in the signature — kong always supplies it when a `Run` method requests it, and matching the current binding shape keeps dispatch behavior unchanged.
- The header comments in the deleted file (kongplete attribution) move with the templates into `g3lib/completion.go`.
- The kong wiring (`Completions CompletionsCmd` field, `kongplete.Complete(parser)` call) in `cli.go` is unchanged.

### Root `Makefile` — install/uninstall completions, fix install prefix

The existing `install` target creates symlinks under `/usr/bin/` for the seven binaries. That target has two problems beyond the missing completion install:

1. **`/usr/bin/` is SIP-protected on macOS** (10.11+). Even `sudo` cannot write there. The current target is silently broken on every macOS install.
2. **`/usr/bin/` is non-FHS on Linux.** FHS reserves `/usr/bin/` for package-manager-owned binaries and `/usr/local/bin/` for system-administrator out-of-tree installs. Works on Linux only because Linux doesn't enforce SIP-style protections.

This change fixes both alongside the completions work, since both touch the same recipe.

**New default install prefix:** `/usr/local/bin/`. Works on Linux (FHS-compliant), macOS Intel (Homebrew Intel's own path), and macOS Apple Silicon (in default `PATH` via `/etc/paths`, sudo-writable, not SIP-protected). Standard Unix `PREFIX ?= /usr/local` override lets Apple Silicon power users redirect to `/opt/homebrew` if they prefer Homebrew layout: `make install PREFIX=/opt/homebrew`.

Completion-snippet generation uses the same `$(BINDIR)` variable so the symlink path and the path embedded in `complete -C ...` snippets stay in sync.

Only the three user-facing CLIs (`g3`, `g3cli`, `g3tui`) get completions — the four daemons (`g3api`, `g3scanner`, `g3worker`, `g3config`) have no flags to complete. All seven binaries still get symlinks.

#### Completion directories to write to

| Shell | Path | When |
|---|---|---|
| bash | `/etc/bash_completion.d/` | Debian/Ubuntu, older convention |
| bash | `/usr/share/bash-completion/completions/` | Fedora/Arch, newer convention |
| bash | `/usr/local/etc/bash_completion.d/` | macOS Intel Homebrew |
| bash | `/opt/homebrew/etc/bash_completion.d/` | macOS Apple Silicon Homebrew |
| zsh  | `/usr/share/zsh/site-functions/` | All Linux distros, macOS system zsh |
| zsh  | `/usr/local/share/zsh/site-functions/` | macOS Intel Homebrew |
| zsh  | `/opt/homebrew/share/zsh/site-functions/` | macOS Apple Silicon Homebrew |
| fish | `/usr/share/fish/vendor_completions.d/` | All Linux distros |
| fish | `/usr/local/share/fish/vendor_completions.d/` | macOS Intel Homebrew |
| fish | `/opt/homebrew/share/fish/vendor_completions.d/` | macOS Apple Silicon Homebrew |

File-naming conventions per shell (matters because completion frameworks scan by name):

- bash: `<bin>` (no prefix, no extension)
- zsh: `_<bin>` (underscore prefix required by zsh's `compinit`)
- fish: `<bin>.fish` (extension required by fish's loader)

#### Make variables (top of Makefile, alongside existing `GO`/`DOCKER`/`PYTHON` block)

```makefile
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin

CLI_BINS  := g3 g3cli g3tui
BASH_DIRS := /etc/bash_completion.d \
             /usr/share/bash-completion/completions \
             /usr/local/etc/bash_completion.d \
             /opt/homebrew/etc/bash_completion.d
ZSH_DIRS  := /usr/share/zsh/site-functions \
             /usr/local/share/zsh/site-functions \
             /opt/homebrew/share/zsh/site-functions
FISH_DIRS := /usr/share/fish/vendor_completions.d \
             /usr/local/share/fish/vendor_completions.d \
             /opt/homebrew/share/fish/vendor_completions.d
```

#### `install` target — rewritten

Replace the entire `install` recipe. The existing seven `sudo ln -s -f $$(pwd)/bin/<bin> /usr/bin/<bin>` lines become:

```makefile
ifdef GO
install:
	sudo ln -s -f $$(pwd)/bin/g3        $(BINDIR)/g3
	sudo ln -s -f $$(pwd)/bin/g3api     $(BINDIR)/g3api
	sudo ln -s -f $$(pwd)/bin/g3cli     $(BINDIR)/g3cli
	sudo ln -s -f $$(pwd)/bin/g3config  $(BINDIR)/g3config
	sudo ln -s -f $$(pwd)/bin/g3scanner $(BINDIR)/g3scanner
	sudo ln -s -f $$(pwd)/bin/g3tui     $(BINDIR)/g3tui
	sudo ln -s -f $$(pwd)/bin/g3worker  $(BINDIR)/g3worker
	@for bin in $(CLI_BINS); do \
	    for dir in $(BASH_DIRS); do \
	        [ -d $$dir ] && sudo sh -c "$(BINDIR)/$$bin completions bash > $$dir/$$bin" || true; \
	    done; \
	    for dir in $(ZSH_DIRS); do \
	        [ -d $$dir ] && sudo sh -c "$(BINDIR)/$$bin completions zsh  > $$dir/_$$bin" || true; \
	    done; \
	    for dir in $(FISH_DIRS); do \
	        [ -d $$dir ] && sudo sh -c "$(BINDIR)/$$bin completions fish > $$dir/$$bin.fish" || true; \
	    done; \
	done
endif
```

Notes:

- Each `sudo sh -c` is a separate sudo call. On a fresh shell the user is prompted once; subsequent calls reuse the cached credential within the sudo timestamp window.
- The `|| true` keeps a failed snippet generation (e.g., a binary that errored) from aborting the whole loop. The `[ -d ]` short-circuit already covers the common "shell not installed" case.
- Make variable `$(CLI_BINS)` expands at recipe-build time; shell variables `$$bin`, `$$dir` are doubled to escape Make's `$`.
- Tabs (not spaces) for recipe indentation, matching the rest of the file.

#### `uninstall` target — new

```makefile
.PHONY: ... uninstall    # add to existing .PHONY line at top of file

ifdef GO
uninstall:
	sudo rm -f $(BINDIR)/g3        $(BINDIR)/g3api     $(BINDIR)/g3cli \
	           $(BINDIR)/g3config  $(BINDIR)/g3scanner $(BINDIR)/g3tui \
	           $(BINDIR)/g3worker
	@for bin in $(CLI_BINS); do \
	    for dir in $(BASH_DIRS); do sudo rm -f $$dir/$$bin; done; \
	    for dir in $(ZSH_DIRS);  do sudo rm -f $$dir/_$$bin; done; \
	    for dir in $(FISH_DIRS); do sudo rm -f $$dir/$$bin.fish; done; \
	done
endif
```

`rm -f` doesn't need the `[ -d ]` guard — it's silent on missing files. `uninstall` honors the same `PREFIX` override as `install`, so `make uninstall PREFIX=/opt/homebrew` removes from that prefix.

#### Help target update

Update line 49 to reflect the new install behavior, and add an uninstall line. Reference `$(BINDIR)` so the help text reflects whatever prefix the user (or the default) selected:

```
  install   Symlink ./bin/g3* into $(BINDIR) and register shell completions (override PREFIX=...; sudo)
  uninstall Remove the symlinks and completion files installed by `make install`
```

#### Known limitations (documented, not fixed)

- **`os.Executable()` resolves symlinks on Linux.** When `$(BINDIR)/g3` (a symlink to `<repo>/bin/g3`) runs `g3 completions bash`, the embedded path in the snippet will be the absolute symlink target (`<repo>/bin/g3`), not `$(BINDIR)/g3`. For dev installs this is fine — the snippet works and stays stable as long as the repo checkout exists. For packaged installs where the repo path shouldn't leak, a future `--bin` flag on the `completions` subcommand would let the Makefile override the path. Deferred until packaged installs are an actual goal.
- **Requires the user's shell to have a completion framework loaded.** Bash needs the `bash-completion` package and `. /etc/profile.d/bash_completion.sh` (or distro equivalent). Zsh needs `compinit` enabled. Fish auto-loads from `vendor_completions.d/` out of the box. We can't enforce framework presence from the Makefile.
- **No `make install` confirmation prompt.** Today's `install` target silently overwrites symlinks; the completion addition follows the same pattern — files are overwritten without prompting. Acceptable since both actions are idempotent.

### go.mod changes

| File | Change |
|---|---|
| `src/g3/go.mod` | Add `github.com/willabides/kongplete v0.4.0` to `require` block. |
| `src/g3cli/go.mod` | Same. |
| `src/g3lib/go.mod` | No change (stdlib-only helper). |
| `src/g3tui/go.mod` | No change (`kongplete` already a direct dep). |

`go.sum` updates for `g3` and `g3cli` will be handled by `go mod tidy` from `make`'s normal build chain. The user runs the build; the agent does not.

### Verification (lint + build only)

Per the user's preferences (no test writing, no binary execution):

```bash
cd src/g3lib && go vet ./...
cd src/g3   && go vet ./...
cd src/g3cli && go vet ./...
cd src/g3tui && go vet ./...

cd src && make ../bin/g3 && make ../bin/g3cli && make ../bin/g3tui

make -n install uninstall   # dry-run: confirm recipe syntax parses, sudo lines look right
```

The user is responsible for `go mod tidy`, the actual `make install`/`make uninstall` runs (sudo-gated), and any tab-completion smoke testing on bash/zsh/fish across distros.

## Risks and edge cases

**1. Plugin-registry assumption in g3.** `g3 completions bash` from a system that's never run `g3config` would print "No plugins found!" and exit `1` today, because plugin loading happens unconditionally in `main`. The early-exit branch is the load-bearing part of this design — without it, the feature is half-broken on fresh installs. Verified during design by reading `g3.go:130-134`.

**2. Env-var assumption in g3cli.** Same issue, different cause: `g3cli` exits on missing `G3_API_BASEURL`/`G3_API_WSURL`/`G3_API_TOKEN`. A user running `g3cli completions bash >> ~/.bashrc` for the first time likely hasn't set these yet. The early-exit branch must come before lines 144-162.

**3. `kctx.Command()` prefix shape.** Pinned to `"completions "` (with trailing space) so the check doesn't accidentally match a hypothetical future top-level command starting with the same letters. Documented inline.

**4. Single-letter alias collision in g3cli.** Already handled — no alias on `g3cli completions`. Users type the full word. The cost is small (running a completion-install command is a once-per-shell event) and avoids breaking any user scripts that rely on `g3cli c <scanid>` for cancel.

**5. Kongplete short-circuit timing.** `kongplete.Complete(parser)` reads `os.Args` and the `COMP_LINE` env var, emits candidates to stdout, and calls `os.Exit(0)` from inside the function — it never returns to `parser.Parse(...)` in completion mode. Confirmed by inspection of `g3tui/internal/cmd/cli.go:79-82`, which has been in production since 8bc0bc7.

**6. `kong.Must` panic semantics.** If the CLI struct contains an invalid kong tag, `kong.Must` panics where `kong.Parse` would also panic — both are intended to surface compile-time mistakes at first run. No behavior change.

## Non-goals

- Static completion of arguments like scan IDs, plugin names, target hosts. Kongplete supports custom completers, but wiring them is a separate piece of work and not part of "match g3tui's feature."
- Powershell or other shells. The three supported shells match g3tui exactly.
- Documentation updates beyond what `--help` already surfaces. README sections for install snippets can come later.

## Next step

Implementation plan in a sibling `2026-05-13-g3-g3cli-shell-completions-implementation.md` once this spec is approved.
