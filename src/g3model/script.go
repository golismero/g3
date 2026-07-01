package g3model

import (
	"embed"
	"fmt"
	"os"
	"strings"

	"github.com/kballard/go-shellquote"
)

type ParsedImport struct {
	Tool string             `json:"tool"                validate:"required"`
	Path string             `json:"path"                validate:"required"`
}

type ParsedReport struct {
	Tool   string             `json:"tool"                validate:"required"`
	Preset string             `json:"preset,omitempty"`
}

type ParsedScript struct {
	Targets []string        `json:"targets,omitempty"   validate:"omitempty"`
	Imports []ParsedImport  `json:"imports,omitempty"   validate:"omitempty,dive"`
	Mode string             `json:"mode,omitempty"      validate:"omitempty"`
	Pipelines [][]string    `json:"pipelines,omitempty" validate:"omitempty"`
	Report *ParsedReport    `json:"report,omitempty"    validate:"omitempty"`
}

func (parsed ParsedScript) String() string {
	text := ""
	if parsed.Mode != "" {
		text = text + "mode " + parsed.Mode + "\n"
	}
	if len(parsed.Targets)  > 0 {
		if text != "" {
			text = text + "\n"
		}
		for _, token := range parsed.Targets {
			text = text + "target " + token + "\n"
		}
	}
	if len(parsed.Imports)  > 0 {
		if text != "" {
			text = text + "\n"
		}
		for _, parsedImport := range parsed.Imports {
			text = text + "import " + parsedImport.Tool + " \"" + parsedImport.Path + "\"\n"
		}
	}
	if len(parsed.Pipelines) > 0 {
		if text != "" {
			text = text + "\n"
		}
		for _, pipeline := range parsed.Pipelines {
			text = text + strings.Join(pipeline, " | ") + "\n"
		}
	}
	if parsed.Report != nil {
		if text != "" {
			text = text + "\n"
		}
		if parsed.Report.Preset != "" {
			text = text + "report " + parsed.Report.Tool + ":" + parsed.Report.Preset + "\n"
		} else {
			text = text + "report " + parsed.Report.Tool + "\n"
		}
	}
	return text
}

// On this very early version of the parser we're only going to support the most basic syntax possible.
//
//   # comment
//   mode parallel
//   target 192.168.1.1 example.com
//   import nmap samples/nmap.xml
//   dnsrecon
//   nmap | testssl
//
func ParseScript(script string) (ParsedScript, error) {
	var parsed ParsedScript
	for lineno, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)

		// Skip empty and comment lines.
		if len(line) == 0 {
			continue
		}
		if len(line) > 1 && line[0] == byte(35) {	// #
			continue
		}

		// Each line is split using a shell-like parser.
		commands, err := shellquote.Split(line)
		if err != nil {
			err = fmt.Errorf("syntax error on line %d: %s", lineno+1, err.Error())
			return ParsedScript{}, err
		}
		if len(commands) == 0 {
			continue
		}

		// Once a report directive has been parsed, no further directives are allowed
		// — report must be the LAST line of the script.
		if parsed.Report != nil {
			err = fmt.Errorf("syntax error on line %d: report directive must be the last line of the script", lineno+1)
			return ParsedScript{}, err
		}

		// The "target" command adds a target for scanning.
		// These are executed locally before starting the scan.
		if commands[0] == "target" {
			if len(commands) < 2 {
				err = fmt.Errorf("syntax error on line %d: invalid targets", lineno+1)
				return ParsedScript{}, err
			}
			for _, token := range commands {
				if token == "|" {
					err = fmt.Errorf("syntax error on line %d: cannot mix pipelines and targets", lineno+1)
					return ParsedScript{}, err
				}
			}

			// Check that the targets parse correctly.
			_, err = BuildTargets(commands[1:])
			if err != nil {
				err = fmt.Errorf("syntax error on line %d: %s", lineno+1, err.Error())
				return ParsedScript{}, err
			}

			// Add the target to the parsed structure.
			parsed.Targets = append(parsed.Targets, commands[1:]...)
			continue
		}

		// The "import" command loads an output file from a third party tool into the scan data.
		// These are executed locally before starting the scan.
		if commands[0] == "import" {
			if len(commands) < 3 {
				err = fmt.Errorf("syntax error on line %d: invalid import", lineno+1)
				return ParsedScript{}, err
			}
			for _, token := range commands {
				if token == "|" {
					err = fmt.Errorf("syntax error on line %d: cannot mix pipelines and imports", lineno+1)
					return ParsedScript{}, err
				}
			}

			// Check that the files to import actually exist.
			// We don't need to be very thorough here since we can also error out later when importing,
			// but it is useful to do some minimal checking here where we can report the script line number.
			for _, token := range commands[2:] {
				if Validate.Var(token, "required,uuid") == nil {
					continue
				}
				if _, err := os.Stat(token); err != nil {
					err = fmt.Errorf("runtime error on line %d: %s", lineno+1, err.Error())
					return ParsedScript{}, err
				}
			}

			// Add the import files to the parsed structure.
			for _, token := range commands[2:] {
				var parsedImport ParsedImport
				parsedImport.Tool = commands[1]
				parsedImport.Path = token
				parsed.Imports = append(parsed.Imports, parsedImport)
			}
			continue
		}

		// The "mode" command sets the execution mode of the script.
		// It can only be used once in the script.
		if commands[0] == "mode" {
			if len(commands) != 2 {
				err = fmt.Errorf("syntax error on line %d: invalid mode command", lineno+1)
				return ParsedScript{}, err
			}
			if parsed.Mode != "" {
				err = fmt.Errorf("syntax error on line %d: mode command can only be used once in a script", lineno+1)
				return ParsedScript{}, err
			}
			parsed.Mode = commands[1]
			if parsed.Mode != "sequential" && parsed.Mode != "parallel" {
				err = fmt.Errorf("syntax error on line %d: unknown mode", lineno+1)
				return ParsedScript{}, err
			}
			continue
		}

		// The "report" command declares a reporter to invoke after the pipeline finishes.
		// Must be the LAST directive in the script. At most one per script.
		// Syntax:
		//   report                      → magenta reporter plugin (the default)
		//   report <tool>[:<preset>]    → reporter plugin (dispatched to a worker)
		// The built-in reporter has been removed; reporting is always delegated
		// to a reporter plugin (magenta by default).
		if commands[0] == "report" {
			if parsed.Report != nil {
				err = fmt.Errorf("syntax error on line %d: only one report directive per script is allowed", lineno+1)
				return ParsedScript{}, err
			}
			if len(commands) > 2 {
				err = fmt.Errorf("syntax error on line %d: report directive takes at most one argument: <tool>[:<preset>]", lineno+1)
				return ParsedScript{}, err
			}
			// Resolve <tool>[:<preset>]. A bare "report" defaults to magenta.
			tool := "magenta"
			preset := ""
			if len(commands) == 2 {
				toolArg := commands[1]
				tool = toolArg
				if i := strings.Index(toolArg, ":"); i >= 0 {
					tool = toolArg[:i]
					preset = toolArg[i+1:]
					if tool == "" {
						err = fmt.Errorf("syntax error on line %d: missing tool name in report directive", lineno+1)
						return ParsedScript{}, err
					}
				}
			}
			parsed.Report = &ParsedReport{Tool: tool, Preset: preset}
			continue
		}

		// Any other command must be part of a pipeline.
		// Re-parse the script line using a simpler tokenizer.
		// We don't support arguments to tools and tools can't have spaces in their names.
		var pipeline []string
		for _, token := range strings.Split(line, "|") {
			token = strings.TrimSpace(token)
			if token == "" {
				err = fmt.Errorf("syntax error on line %d: missing tool in pipeline", lineno+1)
				return ParsedScript{}, err
			}
			if strings.Contains(token, " ") {
				err = fmt.Errorf("syntax error on line %d: tools do not take arguments", lineno+1)
				return ParsedScript{}, err
			}
			pipeline = append(pipeline, token)
		}

		// Add the pipeline to the parsed structure.
		parsed.Pipelines = append(parsed.Pipelines, pipeline)
	}

	// If no "mode" command was used, set it to the default.
	if parsed.Mode == "" {
		parsed.Mode = "parallel"
	}

	// Return the object with the parsed script.
	// This is not exactly the same object that is sent to g3scanner later,
	// since targets and imports are executed locally, and pipelines remotely.
	return parsed, nil
}

// Reusable pipelines for building scripts.
//go:embed res/*.pipeline
var pipelinesFS embed.FS
func GetBuiltInPipelines(compact bool) map[string]string {
	out := map[string]string{}
	entries, err := pipelinesFS.ReadDir("res")
	if err != nil {
		panic("internal error looking for embedded pipelines")
		//return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pipeline") {
			continue
		}
		raw, err := pipelinesFS.ReadFile("res/" + e.Name())
		if err != nil {
			panic("internal error reading embedded file: res/" + e.Name())
			//continue
		}
		name := strings.TrimSuffix(e.Name(), ".pipeline")
		script := string(raw)
		if compact {
			pipelines := []string{}
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				if len(line) > 1 && line[0] == byte(35) {	// #
					continue
				}
				var tools []string
				for _, token := range strings.Split(line, "|") {
					token = strings.TrimSpace(token)
					if token == "" {
						continue
					}
					tools = append(tools, token)
				}
				line = strings.Join(tools, "|")
				pipelines = append(pipelines, line)
			}
			script = strings.Join(pipelines, "\n") + "\n"
		}
		out[name] = script
	}
	return out
}
