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
