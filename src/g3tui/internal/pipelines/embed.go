package pipelines

import (
	"embed"
	"strings"
)

//go:embed *.pipeline
var embeddedFS embed.FS

func embedded() map[string]string {
	out := map[string]string{}
	entries, err := embeddedFS.ReadDir(".")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pipeline") {
			continue
		}
		raw, err := embeddedFS.ReadFile(e.Name())
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pipeline")
		out[name] = string(raw)
	}
	return out
}
