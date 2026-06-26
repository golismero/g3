package g3lib

import (
	"maps"
	"slices"

	"github.com/golismero/g3/src/g3model"
)

type ParsedImport = g3model.ParsedImport
type ParsedReport = g3model.ParsedReport
type ParsedScript = g3model.ParsedScript

func ParseScript(plugins []string, script string) (ParsedScript, error) {
	// TODO restore runtime validation of plugin names
	return g3model.ParseScript(script)
}

func ParseServerScript(plugins G3PluginMetadata, script string) (ParsedScript, error) {
	return ParseScript(slices.Collect(maps.Keys(plugins)), script)
}
