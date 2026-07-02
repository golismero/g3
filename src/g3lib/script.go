package g3lib

import (
	"maps"
	"slices"

	"github.com/golismero/g3/src/g3"
)

func ParseServerScript(plugins G3PluginMetadata, script string) (g3.ParsedScript, error) {
	parsed, err := g3.ParseScript(script)
	if err == nil {
		err = g3.IsScriptSupported(parsed, slices.Collect(maps.Keys(plugins)))
	}
	return parsed, err
}
