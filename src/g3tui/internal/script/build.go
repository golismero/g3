// Package script assembles a complete g3 script string from the wizard's
// structured form values. Plain string templating; no parser round-trip
// in the render path (the wizard validates Custom… content separately
// via g3.ParseScript before reaching this builder).
package script

import (
	"errors"
	"fmt"
	"strings"
)

// ImportEntry mirrors the wizard's import row. Path is the value to
// substitute into the `import <tool> <path>` line — typically a
// server-side file id after /file/upload.
type ImportEntry struct {
	Tool string
	Path string
}

// Build returns the assembled script. Returns an error only on the
// degenerate case of zero targets and zero imports.
func Build(targets []string, imports []ImportEntry, mode string, content string) (string, error) {
	if len(targets) == 0 && len(imports) == 0 {
		return "", errors.New("script must include at least one target or import")
	}
	if mode == "" {
		mode = "parallel"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "mode %s\n", mode)
	for _, t := range targets {
		fmt.Fprintf(&sb, "target %s\n", t)
	}
	for _, imp := range imports {
		fmt.Fprintf(&sb, "import %s %s\n", imp.Tool, imp.Path)
	}
	sb.WriteString(content)
	if !strings.HasSuffix(content, "\n") {
		sb.WriteString("\n")
	}
	return sb.String(), nil
}
