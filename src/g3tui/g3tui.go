package main

import (
	"errors"
	"fmt"
	"os"

	"golismero.com/g3lib"
	"golismero.com/g3tui/internal/cmd"
)

func main() {
	err := cmd.Execute(g3lib.Version)
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
