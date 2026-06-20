// Package pipelines loads the scan-type catalog: embedded defaults
// (compiled into the binary) plus optional user files dropped into a
// configurable directory. User files override embedded ones with the
// same basename. Validation is best-effort — invalid files are logged
// and skipped, never fatal.
package pipelines

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)

type Source string

const (
	SourceEmbedded Source = "embedded"
	SourceUser     Source = "user"
)

type Pipeline struct {
	Name    string
	Source  Source
	Content string
}

// Load returns the merged pipeline catalog. userDir may be empty (then the
// xdg fallback is used). A missing user dir is not an error. Returned slice
// is sorted alphabetically by Name.
func Load(userDir string) ([]Pipeline, error) {
	merged := map[string]Pipeline{}

	for name, content := range g3lib.GetBuiltInPipelines(true) {
		merged[name] = Pipeline{Name: name, Source: SourceEmbedded, Content: content}
	}

	resolved := userDir
	if resolved == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			resolved = filepath.Join(home, ".config", "g3tui", "pipelines")
		}
	}
	if resolved != "" {
		userPipelines, err := loadDir(resolved)
		if err != nil {
			return nil, err
		}
		for name, content := range userPipelines {
			merged[name] = Pipeline{Name: name, Source: SourceUser, Content: content}
		}
	}

	out := make([]Pipeline, 0, len(merged))
	for _, p := range merged {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func loadDir(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pipeline") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Warningf("skipping unreadable pipeline file: %s (%v)", path, err)
			continue
		}
		content := string(raw)
		if err := validate(content); err != nil {
			log.Warningf("skipping invalid pipeline file: %s (%v)", path, err)
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pipeline")
		out[name] = content
	}
	return out, nil
}

// validate confirms a pipeline file's content parses cleanly when wrapped
// with synthetic mode and target lines. Embedded files skip this — they
// were validated at PR review time and are part of the binary.
func validate(content string) error {
	wrapped := fmt.Sprintf("mode parallel\ntarget placeholder.local\n%s", content)
	_, err := g3lib.ParseScript(nil, wrapped)
	return err
}

// Validate is the exported wrapper around validate. It is used by g3tui's
// `pipelines validate` subcommand to check user files without launching the
// TUI. The accepted content is pipeline-only (no synthetic mode/target
// lines); Validate wraps it internally before parsing.
func Validate(content string) error {
	return validate(content)
}
