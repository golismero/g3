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
