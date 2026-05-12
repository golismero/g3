package cmd

import (
	"fmt"
	"os"
	"strings"
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
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".pipeline") {
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
