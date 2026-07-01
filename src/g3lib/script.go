package g3lib

import (
	"maps"
	"slices"

	"github.com/golismero/g3/src/g3"
)

type ParsedImport = g3.ParsedImport
type ParsedReport = g3.ParsedReport
type ParsedScript = g3.ParsedScript

func ParseScript(plugins []string, script string) (ParsedScript, error) {
	// TODO restore runtime validation of plugin names
	return g3.ParseScript(script)
}

func ParseServerScript(plugins G3PluginMetadata, script string) (ParsedScript, error) {
	return ParseScript(slices.Collect(maps.Keys(plugins)), script)
}
