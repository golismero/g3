# g3 + g3cli shell completions — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Verification policy (user-owned):** This project does NOT write tests for these CLIs; verification is strictly `go vet` + `make` + `make -n` for the Makefile. Do not run binaries, hit live servers, or invoke `go test`. Do not run mutating git commands — the user commits at the end of the tier in one batch.

**Goal:** Add `completions <shell>` subcommand to `g3` and `g3cli`, centralize snippet emission in `g3lib`, simplify `g3tui` to use the shared helper, and extend the root Makefile to install completions and fix the install-prefix bug.

**Architecture:** Single tier across five tasks. New stdlib-only `g3lib.EmitShellCompletion` helper. Each Kong-based binary owns a tiny `CompletionsCmd` struct with a 1-line `Run` that delegates to the helper. `g3` and `g3cli` need their kong parser construction split (`kong.Must` + `kongplete.Complete` + `parser.Parse`) so kongplete can hook in, plus an early-exit branch before their respective setup code so `<bin> completions <shell>` works without plugins/env vars present. Makefile gains `PREFIX/BINDIR` indirection (default `/usr/local`), drops symlinks + completion snippets in one recipe, and a new `uninstall` reverses both.

**Tech Stack:** Go 1.26, [alecthomas/kong](https://github.com/alecthomas/kong) v1.15, [willabides/kongplete](https://github.com/willabides/kongplete) v0.4, GNU Make.

**Spec:** `docs/plans/2026-05-13-g3-g3cli-shell-completions-design.md`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `src/g3lib/completion.go` | create | Pure helper: format and emit the bash/zsh/fish snippet for a given binary name. Stdlib only. |
| `src/g3/g3.go` | modify | Add `CompletionsCmd` + Run, swap to `kong.Must`+`kongplete.Complete`+`parser.Parse`, early-exit branch before plugin loading. |
| `src/g3/go.mod` | modify | Add `kongplete` direct dep. |
| `src/g3cli/g3cli.go` | modify | Same as `g3.go`, no alias on `completions`, early-exit branch before env-var checks. |
| `src/g3cli/go.mod` | modify | Add `kongplete` direct dep. |
| `src/g3tui/internal/cmd/completions.go` | delete | Logic moves to `g3lib`; struct + Run move to `cli.go`. |
| `src/g3tui/internal/cmd/cli.go` | modify | Add `CompletionsCmd` struct + Run method; add `os` and `g3lib` imports. |
| `Makefile` | modify | `PREFIX`/`BINDIR` indirection, completion-dir constants, install rewrite, new `uninstall` target, help update. |

---

## Task 1: Create the `g3lib.EmitShellCompletion` helper

**Files:**
- Create: `src/g3lib/completion.go`

- [ ] **Step 1: Write the helper file**

Create `src/g3lib/completion.go` with this exact content:

```go
// Adapted from github.com/WillAbides/kongplete (MIT) — same snippet templates
// kongplete uses internally, centralized here so g3, g3cli, and g3tui can
// share one emitter via an explicit shell positional rather than kongplete's
// auto-detect login-shell behavior.

package g3lib

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// shellCompletionSnippets are the registration lines a user adds to their
// shell rc (or that the Makefile drops into a system completion directory)
// to enable Tab-completion. The actual completion engine is provided by
// kongplete inside each binary — these snippets only tell the shell to
// consult the binary on Tab.
var shellCompletionSnippets = map[string]string{
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

// EmitShellCompletion writes a shell-registration snippet for cmdName to w.
// shell must be "bash", "zsh", or "fish"; any other value returns an error.
// The binary path embedded in the snippet is resolved via os.Executable()
// and made absolute so the snippet keeps working regardless of $PATH.
func EmitShellCompletion(shell, cmdName string, w io.Writer) error {
	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return fmt.Errorf("resolve absolute path: %w", err)
	}

	tmpl, ok := shellCompletionSnippets[shell]
	if !ok {
		return fmt.Errorf("unsupported shell %q", shell)
	}

	switch shell {
	case "bash", "zsh":
		fmt.Fprintf(w, tmpl, bin, cmdName)
	case "fish":
		// fish template uses cmdName four times and bin once.
		fmt.Fprintf(w, tmpl, cmdName, bin, cmdName, cmdName)
	}
	return nil
}
```

- [ ] **Step 2: Lint check**

Run: `cd src/g3lib && go vet ./...`
Expected: no output (clean).

---

## Task 2: Add `completions` subcommand to `g3`

**Files:**
- Modify: `src/g3/g3.go`
- Modify: `src/g3/go.mod` (the user will run `go mod tidy`)

- [ ] **Step 1: Edit imports in `src/g3/g3.go`**

The existing import block (lines 3-17) is:

```go
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"

	"github.com/alecthomas/kong"
	"github.com/go-playground/validator/v10"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)
```

Add `"strings"` to the stdlib group and `"github.com/willabides/kongplete"` to the third-party group. After the edit:

```go
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/go-playground/validator/v10"
	"github.com/willabides/kongplete"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)
```

- [ ] **Step 2: Add `CompletionsCmd` type and `Run` method**

Find the `TargetCmd` block at line 46-51 (the last struct definition before `var CLI struct {`). Immediately after the closing `}` of `TargetCmd` and before the `var CLI struct {` block at line 91, insert:

```go
type CompletionsCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

func (c *CompletionsCmd) Run() error {
	return g3lib.EmitShellCompletion(c.Shell, "g3", os.Stdout)
}
```

(`Run` takes no parameters — kong's reflection dispatcher will call it with no bindings, which works whether `parser.Run(cmdctx)` or `kctx.Run()` invokes it.)

- [ ] **Step 3: Add `Completions` field to the `CLI` struct**

Find the `var CLI struct { ... }` block at line 91-101. After the last field (`Report ReportCmd ...` at line 100), add:

```go
	Completions CompletionsCmd `cmd:"" aliases:"c" help:"Emit shell completion registration snippet."`
```

The block becomes:

```go
var CLI struct {
	Scan        ScanCmd        `cmd:"" aliases:"s" help:"Run a scan script."`
	Target      TargetCmd      `cmd:"" aliases:"t" help:"Prepare a list of targets."`
	Tools       ToolsCmd       `cmd:"" aliases:"p" help:"List the available tools."`
	Import      ImportCmd      `cmd:"" aliases:"i" help:"Load the output of a tool."`
	Run         RunCmd         `cmd:"" aliases:"r" help:"Run a tool."`
	Merge       MergeCmd       `cmd:"" aliases:"m" help:"Launch issue merger plugins."`
	Join        JoinCmd        `cmd:"" aliases:"j" help:"Join multiple G3 output files into one."`
	Filter      FilterCmd      `cmd:"" aliases:"f" help:"Filter the input using a logical condition."`
	Report      ReportCmd      `cmd:"" aliases:"o" help:"Produce a Markdown vulnerability report."`
	Completions CompletionsCmd `cmd:"" aliases:"c" help:"Emit shell completion registration snippet."`
}
```

(Existing fields realigned for readability — Go doesn't care, but the gofmt-style alignment matches the rest of the codebase.)

- [ ] **Step 4: Replace `kong.Parse` with `kong.Must` + `kongplete.Complete` + manual parse**

The current `main` function starts at line 109. Replace lines 112-118:

```go
	// Parse the command line options.
	parser := kong.Parse(&CLI,
		kong.Name("g3"),
		kong.Description("Golismero3 - The Pentesting Swiss Army Knife"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
	)
```

with:

```go
	// Build the parser (without parsing) so kongplete can hook in for Tab
	// completion before os.Args is consumed.
	parser := kong.Must(&CLI,
		kong.Name("g3"),
		kong.Description("Golismero3 - The Pentesting Swiss Army Knife"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
	)
	// Short-circuits and exits when the shell invokes us with COMP_LINE set.
	// No-op in normal invocation.
	kongplete.Complete(parser)
	kctx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	// `<bin> completions <shell>` must work without plugins or .env present
	// — the user is setting up their shell, not running a scan. Short-circuit
	// before the expensive setup below.
	if strings.HasPrefix(kctx.Command(), "completions ") {
		parser.FatalIfErrorf(kctx.Run())
		return
	}
```

- [ ] **Step 5: Update the final dispatch site**

The current end of `main` (lines 160-166) reads:

```go
	// Process the command.
	var cmdctx CmdContext
	cmdctx.Ctx = ctx
	cmdctx.Cancelled = &cancelled
	cmdctx.Plugins = plugins
	err = parser.Run(cmdctx)
	parser.FatalIfErrorf(err)
```

`parser` is still in scope. `err` is the outer `var err error` declared at line 110. Replace `parser.Run(cmdctx)` with `kctx.Run(cmdctx)` — we already parsed, so we dispatch through the existing context:

```go
	// Process the command.
	var cmdctx CmdContext
	cmdctx.Ctx = ctx
	cmdctx.Cancelled = &cancelled
	cmdctx.Plugins = plugins
	err = kctx.Run(cmdctx)
	parser.FatalIfErrorf(err)
```

- [ ] **Step 6: Add `kongplete` to `src/g3/go.mod`**

The existing `require` block (lines 7-12) is:

```
require (
	github.com/alecthomas/kong v1.15.0
	github.com/go-playground/validator/v10 v10.30.2
	golismero.com/g3lib v0.0.0-00010101000000-000000000000
	golismero.com/g3log v0.0.0-00010101000000-000000000000
)
```

Add `github.com/willabides/kongplete v0.4.0` to the block:

```
require (
	github.com/alecthomas/kong v1.15.0
	github.com/go-playground/validator/v10 v10.30.2
	github.com/willabides/kongplete v0.4.0
	golismero.com/g3lib v0.0.0-00010101000000-000000000000
	golismero.com/g3log v0.0.0-00010101000000-000000000000
)
```

(The user will run `go mod tidy` to update `go.sum` and add any indirect deps kongplete pulls in.)

- [ ] **Step 7: Lint and build check**

Run: `cd src/g3 && go vet ./...`
Expected: no output (clean).

Run: `cd src && make ../bin/g3`
Expected: builds successfully. If the user hasn't run `go mod tidy` yet, the build itself triggers module download — that's fine.

---

## Task 3: Add `completions` subcommand to `g3cli`

**Files:**
- Modify: `src/g3cli/g3cli.go`
- Modify: `src/g3cli/go.mod`

- [ ] **Step 1: Edit imports in `src/g3cli/g3cli.go`**

The existing import block (lines 3-19) is:

```go
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/alexeyco/simpletable"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/websocket"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)
```

`"strings"` is already imported. Add `"github.com/willabides/kongplete"` to the third-party group:

```go
	"github.com/alecthomas/kong"
	"github.com/alexeyco/simpletable"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/websocket"
	"github.com/willabides/kongplete"
```

- [ ] **Step 2: Add `CompletionsCmd` type and `Run` method**

Find the `RmCmd` block at lines 93-96 (the last struct definition before `var CLI struct {`). After its closing `}` and before `var CLI struct {` at line 98, insert:

```go
type CompletionsCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

func (c *CompletionsCmd) Run() error {
	return g3lib.EmitShellCompletion(c.Shell, "g3cli", os.Stdout)
}
```

- [ ] **Step 3: Add `Completions` field to the `CLI` struct (no alias)**

Find the `var CLI struct { ... }` block at lines 98-112. After the last subcommand field (`Rm RmCmd ...` at line 111), add:

```go
	Completions CompletionsCmd `cmd:"" help:"Emit shell completion registration snippet."`
```

No alias — `c` is taken by `Cancel`.

- [ ] **Step 4: Replace `kong.Parse` with `kong.Must` + `kongplete.Complete` + manual parse, with early-exit before env-var checks**

The current `main` from line 117 to line 162 includes parser construction, .env loading, log setup, and three env-var checks that each `os.Exit(1)`. We need the completions branch to bypass all of that.

Replace lines 117-124:

```go
	// Parse the command line options.
	parser := kong.Parse(&CLI,
		kong.Name("g3cli"),
		kong.Description("Golismero3 - The Pentesting Swiss Army Knife"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
		kong.Vars{"version": Version},
	)
```

with:

```go
	// Build the parser (without parsing) so kongplete can hook in for Tab
	// completion before os.Args is consumed.
	parser := kong.Must(&CLI,
		kong.Name("g3cli"),
		kong.Description("Golismero3 - The Pentesting Swiss Army Knife"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
		kong.Vars{"version": Version},
	)
	// Short-circuits and exits when the shell invokes us with COMP_LINE set.
	// No-op in normal invocation.
	kongplete.Complete(parser)
	kctx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	// `g3cli completions <shell>` must work without G3_API_* env vars set
	// — the user is setting up their shell, not making API calls. Short-
	// circuit before the env-var checks below.
	if strings.HasPrefix(kctx.Command(), "completions ") {
		parser.FatalIfErrorf(kctx.Run())
		return
	}
```

This places the early-exit branch immediately after parse, before the `g3lib.LoadDotEnvFile()` call at the original line 127 and well before the env-var checks at original lines 144-162.

- [ ] **Step 5: Update the final dispatch site**

The current end of `main` (lines 193-195) reads:

```go
	// Process the command.
	err = parser.Run(cmdctx)
	parser.FatalIfErrorf(err)
```

Replace `parser.Run(cmdctx)` with `kctx.Run(cmdctx)`:

```go
	// Process the command.
	err = kctx.Run(cmdctx)
	parser.FatalIfErrorf(err)
```

- [ ] **Step 6: Add `kongplete` to `src/g3cli/go.mod`**

The existing `require` block (lines 7-14) is:

```
require (
	github.com/alecthomas/kong v1.15.0
	github.com/alexeyco/simpletable v1.0.0
	github.com/go-playground/validator/v10 v10.30.2
	github.com/gorilla/websocket v1.5.3
	golismero.com/g3lib v0.0.0-00010101000000-000000000000
	golismero.com/g3log v0.0.0-00010101000000-000000000000
)
```

Add `github.com/willabides/kongplete v0.4.0`:

```
require (
	github.com/alecthomas/kong v1.15.0
	github.com/alexeyco/simpletable v1.0.0
	github.com/go-playground/validator/v10 v10.30.2
	github.com/gorilla/websocket v1.5.3
	github.com/willabides/kongplete v0.4.0
	golismero.com/g3lib v0.0.0-00010101000000-000000000000
	golismero.com/g3log v0.0.0-00010101000000-000000000000
)
```

- [ ] **Step 7: Lint and build check**

Run: `cd src/g3cli && go vet ./...`
Expected: no output (clean).

Run: `cd src && make ../bin/g3cli`
Expected: builds successfully.

---

## Task 4: Refactor `g3tui` to use the shared helper

**Files:**
- Delete: `src/g3tui/internal/cmd/completions.go`
- Modify: `src/g3tui/internal/cmd/cli.go`

- [ ] **Step 1: Delete `src/g3tui/internal/cmd/completions.go`**

Remove the file entirely. Its contents are obsoleted by `g3lib.EmitShellCompletion` (snippet emission) and the new inline struct in `cli.go` (kong dispatch).

```bash
rm src/g3tui/internal/cmd/completions.go
```

- [ ] **Step 2: Add imports to `src/g3tui/internal/cmd/cli.go`**

The current import block (lines 7-15) is:

```go
import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/willabides/kongplete"
)
```

`"os"` is already there. Add `"golismero.com/g3lib"` to a new third-party group below kongplete:

```go
import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/willabides/kongplete"

	"golismero.com/g3lib"
)
```

- [ ] **Step 3: Add `CompletionsCmd` struct and `Run` method to `cli.go`**

Append at the end of the file (after `runOnlyFlagAtRoot` at line 140), with a one-line section comment matching the file's style:

```go

// CompletionsCmd implements the `completions <shell>` subcommand. The actual
// snippet templates live in g3lib so g3 and g3cli can share them.
type CompletionsCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

func (c *CompletionsCmd) Run(kctx *kong.Context) error {
	_ = kctx
	return g3lib.EmitShellCompletion(c.Shell, "g3tui", os.Stdout)
}
```

The `kctx *kong.Context` parameter is kept (rather than removed) to preserve the existing kong dispatch signature shape — g3tui's other Run methods all take `*kong.Context`. Removing it would be an unrelated refactor.

- [ ] **Step 4: Lint and build check**

Run: `cd src/g3tui && go vet ./...`
Expected: no output (clean).

Run: `cd src && make ../bin/g3tui`
Expected: builds successfully.

---

## Task 5: Update root `Makefile`

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add `uninstall` to the `.PHONY` line**

Line 1 currently reads:

```makefile
.PHONY: all bin clean misc docker plugins pull update install lint help
```

Add `uninstall`:

```makefile
.PHONY: all bin clean misc docker plugins pull update install uninstall lint help
```

- [ ] **Step 2: Add `PREFIX`/`BINDIR` and completion-directory variables**

After the existing `PYTHON := ...` line at line 8, add:

```makefile

# Install prefix. /usr/local works on Linux (FHS-compliant), macOS Intel
# (Homebrew Intel), and macOS Apple Silicon (in default PATH via /etc/paths,
# sudo-writable, not SIP-protected). /usr/bin is wrong on macOS (SIP) and
# non-FHS on Linux. Apple Silicon Homebrew users who prefer that layout can
# override: `make install PREFIX=/opt/homebrew`.
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin

# Binaries that get shell completions installed. The daemons have no flags.
CLI_BINS  := g3 g3cli g3tui

# System completion directories. Each is `-d`-gated at install time so missing
# shells are silently skipped. Bash has two Linux conventions (Debian vs
# Fedora/Arch) plus two macOS Homebrew layouts.
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

- [ ] **Step 3: Update the help text for `install` and add `uninstall`**

Find line 49:

```makefile
	@printf "  $(C_CYAN)install$(C_RESET)  Symlink ./bin/g3* into /usr/bin/ (requires sudo)\n"
```

Replace with:

```makefile
	@printf "  $(C_CYAN)install$(C_RESET)  Symlink ./bin/g3* into $(BINDIR) and register shell completions (sudo; override PREFIX=...)\n"
	@printf "  $(C_CYAN)uninstall$(C_RESET) Remove the symlinks and completion files installed by 'make install'\n"
```

(The `install` line gets pushed past the original 80-column boundary; the rest of the help block already exceeds 80 columns, so this matches the file's style.)

Also update the disabled-help block at line 60:

```makefile
	@printf "  $(C_DIM)install            (disabled — Go not detected)$(C_RESET)\n"
```

Add a sibling line for uninstall immediately after:

```makefile
	@printf "  $(C_DIM)install            (disabled — Go not detected)$(C_RESET)\n"
	@printf "  $(C_DIM)uninstall          (disabled — Go not detected)$(C_RESET)\n"
```

- [ ] **Step 4: Replace the `install` target body**

The current block (lines 92-102) is:

```makefile
# Install the binaries locally.
ifdef GO
install:
	sudo ln -s -f $$(pwd)/bin/g3 /usr/bin/g3
	sudo ln -s -f $$(pwd)/bin/g3api /usr/bin/g3api
	sudo ln -s -f $$(pwd)/bin/g3cli /usr/bin/g3cli
	sudo ln -s -f $$(pwd)/bin/g3config /usr/bin/g3config
	sudo ln -s -f $$(pwd)/bin/g3scanner /usr/bin/g3scanner
	sudo ln -s -f $$(pwd)/bin/g3tui /usr/bin/g3tui
	sudo ln -s -f $$(pwd)/bin/g3worker /usr/bin/g3worker
endif
```

Replace with:

```makefile
# Install the binaries locally and register shell completions in system dirs.
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

- [ ] **Step 5: Add the `uninstall` target**

Immediately after the closing `endif` of the `install` block, insert:

```makefile

# Reverse `make install`: drop symlinks and any completion files we wrote.
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

- [ ] **Step 6: Syntax check both targets**

Run: `make -n install`
Expected: prints the recipe commands without executing. Look for: 7 `sudo ln -s -f` lines pointing at `$(BINDIR)/...`, and a `for bin in g3 g3cli g3tui` loop. No "missing separator" or "unterminated variable reference" errors.

Run: `make -n uninstall`
Expected: prints a `sudo rm -f` line covering all 7 binaries under `$(BINDIR)`, and a `for bin in g3 g3cli g3tui` loop with three nested `rm -f` loops. No errors.

Run: `make help`
Expected: lists both `install` and `uninstall` with the new descriptions; `install` shows `$(BINDIR)` expanded to `/usr/local/bin` (or the user's override).

---

## Cross-cutting verification (after all tasks)

These are redundant if each task's per-task verification passed cleanly, but useful as a final sweep:

- [ ] **Lint all four affected Go modules**

```bash
cd src/g3lib && go vet ./...
cd src/g3   && go vet ./...
cd src/g3cli && go vet ./...
cd src/g3tui && go vet ./...
```

Expected: no output from any.

- [ ] **Rebuild all three affected binaries**

```bash
cd src && make ../bin/g3 ../bin/g3cli ../bin/g3tui
```

Expected: all three build successfully.

- [ ] **Hand off to user for commit**

Don't run `git add`/`git commit`. Summarize the changeset for the user — files created, files modified, files deleted, and the one-time follow-up (`go mod tidy` in `src/g3` and `src/g3cli` if the user wants the `go.sum` updated outside of the build chain; the user also needs to `sudo rm -f /usr/bin/g3*` to clean up the old install prefix).

---

## Self-review

- **Spec coverage:**
  - g3lib helper signature → Task 1 ✓
  - g3 changes (CompletionsCmd, kong.Must swap, early-exit, alias `c`, kongplete dep) → Task 2 ✓
  - g3cli changes (no alias, early-exit before env checks, kongplete dep) → Task 3 ✓
  - g3tui delete-and-fold → Task 4 ✓
  - Makefile (PREFIX/BINDIR fix, completion dirs, install rewrite, uninstall, help) → Task 5 ✓
  - go.mod kongplete adds → Steps 6 of Tasks 2 and 3 ✓
  - Verification (lint + build + `make -n`) → per-task and final ✓

- **Placeholder scan:** no "TBD", "TODO", "similar to", or vague references.

- **Type/identifier consistency:** `EmitShellCompletion(shell, cmdName, w)` signature is consistent across Tasks 1, 2, 3, 4. `CompletionsCmd` struct shape is identical across binaries (`Shell string` with the same kong tag). `kctx` is the canonical name for the parsed kong context in all three binaries.

- **Order constraints honored:**
  - Task 1 (g3lib) must come before Tasks 2/3/4 (which import it).
  - Tasks 2/3/4 are mutually independent.
  - Task 5 (Makefile) depends on the binaries supporting `completions` (Tasks 2/3/4) since the install recipe invokes them.
