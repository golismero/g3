package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/willabides/kongplete"

	"github.com/golismero/g3/src/g3lib"
	log "github.com/golismero/g3/src/g3log"
	"github.com/golismero/g3/src/g3model"
)

type InputCmd struct {
	Input string `short:"i" type:"existingfile" default:"-" help:"Input file."`
}

type OutputCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
}

type IOCmd struct {
	InputCmd
	OutputCmd
}

type FlagCmd struct {
	Beautify bool `short:"b" default:"false" help:"Beautify output data."`
	Force    bool `short:"f" default:"false" help:"Do not ask for confirmation for dangerous operations."`
	Quiet    bool `short:"q" default:"false" help:"Suppress stderr output except on fatal errors."`
}

type ScanCmd struct {
	IOCmd
	FlagCmd
}

type TargetCmd struct {
	Input string `short:"i" type:"existingfile" help:"Input file."`
	OutputCmd
	FlagCmd
	Targets []string `arg:"" optional:"" help:"Targets for a G3 scan."`
}

type ToolsCmd struct {
	OutputCmd
	FlagCmd
}

type ImportCmd struct {
	IOCmd
	FlagCmd
	Tool string `arg:"" required:"" help:"Tool to use to parse the input file."`
}

type RunCmd struct {
	IOCmd
	FlagCmd
	Tools []string `arg:"" required:"" help:"Tools to run."`
	Artifacts string `name:"artifacts" short:"a" type:"existingdir" help:"Directory to persist tool artifacts into (one sub-slot per invocation); omit to discard artifacts."`
}

type JoinCmd struct {
	OutputCmd
	FlagCmd
	Input []string `arg:"" required:"" type:"existingfile" help:"Input G3 file(s) to join."`
}

type FilterCmd struct {
	IOCmd
	FlagCmd
	Filter string `arg:"" required:"" help:"Logical condition to filter with."`
}

type ReportCmd struct {
	FlagCmd
	Tool      string `name:"tool" default:"magenta" help:"Reporter plugin to run."`
	Preset    string `name:"preset" default:"" help:"Reporter preset (when the plugin declares presets)."`
	Artifacts string `name:"artifacts" short:"a" type:"existingdir" required:"" help:"Directory of tool artifacts to report on."`
	Output    string `name:"output" short:"o" type:"path" required:"" help:"Output directory for the report."`
}

type CompletionsCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

func (c *CompletionsCmd) Run() error {
	return g3model.EmitShellCompletion(c.Shell, "g3", os.Stdout)
}

var CLI struct {
	Version kong.VersionFlag   `                   help:"Show version and exit."`

	Scan        ScanCmd        `cmd:"" aliases:"s" help:"Run a scan script."`
	Target      TargetCmd      `cmd:"" aliases:"t" help:"Prepare a list of targets."`
	Tools       ToolsCmd       `cmd:"" aliases:"p" help:"List the available tools."`
	Import      ImportCmd      `cmd:"" aliases:"i" help:"Load the output of a tool."`
	Run         RunCmd         `cmd:"" aliases:"r" help:"Run a tool."`
	Join        JoinCmd        `cmd:"" aliases:"j" help:"Join multiple G3 output files into one."`
	Filter      FilterCmd      `cmd:"" aliases:"f" help:"Filter the input using a logical condition."`
	Report      ReportCmd      `cmd:"" aliases:"o" help:"Generate a report by running a reporter plugin (magenta) over an artifacts directory."`
	Completions CompletionsCmd `cmd:"" aliases:"c" help:"Emit shell completion registration snippet."`
}

type CmdContext struct {
	Ctx       context.Context
	Cancelled *bool
	Plugins   g3lib.G3PluginMetadata
}

// Load a list of targets from a file.
func LoadTargetsFromFile(filepath string) ([]string, error) {
	targets := []string{}
	var fd *os.File
	var err error
	if filepath == "-" {
		fd = os.Stdin
	} else {
		fd, err = os.Open(filepath)
		if err != nil {
			return targets, err
		}
		defer fd.Close()
	}
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Trim(line, " \t\r\n")
		if len(line) > 1 && line[0:1] == "#" {		// only entire line comments are supported
			continue
		}
		if len(line) >= 2 && line[0:1] == "\"" && line[len(line)-1:] == "\"" {	// remove ""
			line = line[1:len(line)-1]
		}
		if len(line) == 0 {		// skip empty lines
			continue
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}

func main() {
	var err error

	// Build the parser (without parsing) so kongplete can hook in for Tab
	// completion before os.Args is consumed.
	parser := kong.Must(&CLI,
		kong.Name("g3"),
		kong.Description("Golismero3 - The Pentesting Swiss Army Knife"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
		kong.Vars{"version": g3lib.Version},
	)
	// Short-circuits and exits when the shell invokes us with COMP_LINE set.
	// No-op in normal invocation.
	kongplete.Complete(parser)
	kctx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	// `<bin> completions <shell>` must work without plugins or .env present
	// — the user is setting up their shell, not running a scan. Short-circuit
	// before the expensive setup below.
	if strings.HasPrefix(kctx.Command(), "completions ") {
		parser.FatalIfErrorf(kctx.Run())
		return
	}

	// Load the environment variables.
	g3lib.LoadDotEnvFile()

	// Initialize the logger.
	log.InitLogger()
	if ll := os.Getenv("G3_CMD_LOG_LEVEL"); ll != "" {
		log.SetLogLevel(ll)
	}

	// Load the plugins.
	plugins := g3lib.LoadPlugins()
	if len(plugins) == 0 {
		log.Critical("No plugins found!")
		os.Exit(1)
	}

	// Create the cancellation context for the plugins.
	// Inspired by: https://pace.dev/blog/2020/02/17/repond-to-ctrl-c-interrupt-signals-gracefully-with-context-in-golang-by-mat-ryer.html
	cancelled := false
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()
	go func() {
		select {
		case <-signalChan: // first signal, cancel context
			log.Critical("\nSIGINT received!")
			cancel()
			cancelled = true
		case <-ctx.Done():
			cancelled = true
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()

	// Process the command.
	var cmdctx CmdContext
	cmdctx.Ctx = ctx
	cmdctx.Cancelled = &cancelled
	cmdctx.Plugins = plugins
	err = kctx.Run(cmdctx)
	parser.FatalIfErrorf(err)
}

func (cmd *ScanCmd) Run(cmdctx CmdContext) error {
	ctx := cmdctx.Ctx
	plugins := cmdctx.Plugins

	// Change the log level based on the flags.
	var stderr io.Writer
	if cmd.Quiet {
		stderr = io.Discard
		log.SetLogLevel("CRITICAL")
	} else {
		stderr = os.Stderr
	}

	// Get the scan script.
	var scriptBytes []byte
	var err error
	if cmd.Input == "-" {
		scriptBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Critical(err)
			return err
		}
	} else {
		scriptBytes, err = os.ReadFile(cmd.Input)
		if err != nil {
			log.Critical("Error reading file " + cmd.Input + ": " + err.Error())
			return err
		}
	}
	script := string(scriptBytes)

	// Validate the scan script.
	parsed, err := g3lib.ParseServerScript(plugins, script)
	if err == nil {
		err = g3model.Validate.Struct(parsed)
	}
	if err != nil {
		log.Critical(err)
		return err
	}
	if len(parsed.Targets) == 0 { // TODO change the logic here so we can pass targets via cmdline
		log.Critical("Script does not specify any targets, aborting.")
		return errors.New("script does not specify any targets, aborting")
	}
	if parsed.Mode == "parallel" {
		log.Warning("Parallel mode not supported when running standalone, will run in sequential mode instead.")
	} else if parsed.Mode != "sequential" {
		log.Critical("Execution mode not supported: " + parsed.Mode)
		return errors.New("Execution mode not supported: " + parsed.Mode)
	}
	log.Debug(
		"\n" +
			"--------------------------------------------------------------------------------\n" +
			"--- Running script:\n" +
			"\n" +
			parsed.String() + "\n" +
			"--------------------------------------------------------------------------------\n")

	// Build the target objects.
	var targetData []g3model.Data
	if len(parsed.Targets) > 0 {
		targetData, err = g3model.BuildTargets(parsed.Targets)
		if err != nil {
			log.Critical(err)
			return err
		}
	}

	// Import the files into the database.
	for _, parsedImport := range parsed.Imports {

		// Get the requested importer plugin.
		plugin, ok := plugins[parsedImport.Tool]
		if !ok || plugin.Importer == nil {
			log.Critical("Tool not found: " + parsedImport.Tool)
			return errors.New("Tool not found: " + parsedImport.Tool)
		}

		// Pipe the input file.
		stdin, err := os.Open(parsedImport.Path)
		if err != nil {
			log.Critical("Cannot open file " + parsedImport.Path + ": " + err.Error())
			return errors.New("Cannot open file " + parsedImport.Path + ": " + err.Error())
		}
		defer stdin.Close()

		// Importers don't support conditions nor command templates.
		// The command is run directly and the raw data piped to it.
		parsedCommand, errA := g3lib.BuildImporterCommand(plugin)
		if len(errA) > 0 {
			log.Critical("Error executing importer " + plugin.Name + ":")
			for _, err := range errA {
				log.Critical(" - " + err.Error())
			}
			return errors.New("Error executing importer " + plugin.Name)
		}
		importedData, err := g3lib.RunPluginImporter(ctx, plugin, parsedCommand, stdin, stderr)
		if err != nil {
			log.Critical("Error executing importer " + plugin.Name + ": " + err.Error())
			return errors.New("Error executing importer " + plugin.Name + ": " + err.Error())
		}

		// We can only cancel a context once, so let's just quit now.
		if *cmdctx.Cancelled {
			return nil
		}

		// Add the imported data to the target data.
		targetData = append(targetData, importedData...)
		log.Debug("Imported file: " + parsedImport.Path)
	}

	// Calculate the total number of steps in the script.
	// This will be used later to determine the scan progress.
	totalScanSteps := 0
	for _, pipe := range parsed.Pipelines {
		for _, tool := range pipe {
			plugin, ok := plugins[tool]
			if !ok {
				log.Error("Missing plugin: " + tool)
				return errors.New("Missing plugin: " + tool)
			}
			totalScanSteps += len(plugin.Commands)
		}
	}

	// Instead of a database we keep an array of objects in memory.
	outputData := targetData

	// Skip the pipeline execution part if we have no pipelines.
	// This can happen if the scan script consisted entirely of imports.
	if len(parsed.Pipelines) == 0 {
		log.Debug("No pipelines to be executed, skipping to reporting phase.")
	} else {

		// Run the commands for each pipeline sequentially.
		currentScanStep := 0
		for pipeidx := 0; pipeidx < len(parsed.Pipelines); pipeidx++ {
			pipeline := parsed.Pipelines[pipeidx]
			log.Debugf("Entering pipeline %d", pipeidx)

			// Check for cancelation.
			if *cmdctx.Cancelled {
				return nil
			}

			// Pipelines always start with the target/imported data.
			currentData := targetData

			// Run the tools in the pipeline.
			for stepidx := 0; stepidx < len(pipeline); stepidx++ {
				tool := pipeline[stepidx]

				// Check for cancelation.
				if *cmdctx.Cancelled {
					return nil
				}

				// If the current pipeline is empty, end the pipeline now.
				if len(currentData) == 0 {
					break
				}

				// Fetch the plugin metadata.
				plugin, ok := plugins[tool]
				if !ok {
					log.Error("Missing plugin: " + tool)
					return errors.New("Missing plugin: " + tool)
				}

				// Here we will collect all the new data for this pipeline step.
				var newData []g3model.Data

				// Iterate over the data in the current pipeline.
				for _, data := range currentData {

					// Check for cancelation.
					if *cmdctx.Cancelled {
						return nil
					}

					// Iterate over each subcommand in the plugin.
					for index := 0; index < len(plugin.Commands); index++ {
						currentScanStep++

						// Check for cancelation.
						if *cmdctx.Cancelled {
							return nil
						}

						// Dynamically evaluate if this plugin accepts this type of data.
						// Skip if it does not apply.
						ok, err := g3lib.EvalToolCondition(plugin, index, data)
						if !ok {
							if err != nil {
								log.Error(err.Error())
								return err
							}
							continue
						}

						// Calculate the command that's going to be run.
						parsed, errorArray := g3lib.BuildToolCommand(plugin, index, data)
						if len(errorArray) > 0 {
							errorMsg := ""
							for _, err := range errorArray {
								errorMsg = errorMsg + "\n" + err.Error()
							}
							log.Error(errorMsg)
							return errors.New(errorMsg)
						}

						// If we have data matching this fingerprint,
						// use it instead of calling the plugin.
						var pastData []g3model.Data
						for _, tmp := range outputData {
							tmp1, ok := tmp["_fp"]
							if !ok {
								log.Critical("Malformed data found in pipeline")
								return errors.New("malformed data found in pipeline")
							}
							tmp2, ok := tmp1.([]interface{})
							if !ok {
								log.Critical("Malformed data found in pipeline")
								return errors.New("malformed data found in pipeline")
							}
							for _, tmp3 := range tmp2 {
								tmp4, ok := tmp3.(string)
								if !ok {
									log.Critical("Malformed data found in pipeline")
									return errors.New("malformed data found in pipeline")
								}
								for _, fp := range parsed.Fingerprint {
									if tmp4 == fp {
										pastData = append(pastData, tmp)
									}
								}
							}
						}
						if len(pastData) > 0 {
							log.Debugf("Matched %d results in database", len(pastData))
							newData = append(newData, pastData...)
							continue
						}

						// Run the plugin command.
						log.Infof(
							"\n"+
								"--------------------------------------------------------------------------------\n"+
								"--- Progress: %d%% (completed %d steps out of %d)\n"+
								"--- Running tool: %s\n"+
								"--- %s\n"+
								"--- %s\n"+
								"--------------------------------------------------------------------------------\n",
							int(((currentScanStep-1)*100)/totalScanSteps), currentScanStep-1, totalScanSteps,
							plugin.Name, plugin.Description, plugin.URL)
						slot, slotErr := g3lib.CreateEphemeralArtifactSlot()
						if slotErr != nil {
							log.Warningf("Cannot create ephemeral artifact slot, plugin will run without /artifacts: %s", slotErr.Error())
							slot = ""
						}
						resultData, err := g3lib.RunPluginCommand(ctx, plugin, parsed, data, slot, stderr)
						if slot != "" {
							os.RemoveAll(slot) //nolint:errcheck
						}
						if err != nil {
							log.Critical("Error executing tool " + plugin.Name + ": " + err.Error())
							return err
						}

						// Check for cancelation.
						if *cmdctx.Cancelled {
							return nil
						}

						// Add the result data into the pipeline.
						if len(resultData) > 0 {
							log.Debugf("Tool returned %d results", len(resultData))
							newData = append(newData, resultData...)
						}
					}
				}

				// Move on to the next step in the pipeline.
				outputData = append(outputData, newData...)
				currentData = newData
			}
		}
	}

	// Write the output array.
	err = g3lib.SaveDataToFile(cmd.Output, outputData, cmd.Beautify)
	if err != nil {
		return err
	}
	return nil
}

func (cmd *TargetCmd) Run(ctx CmdContext) error {

	// Targets can be specified both with -i or as positionals.
	arguments := cmd.Targets
	if cmd.Input != "" {
		targets, err := LoadTargetsFromFile(cmd.Input)
		if err != nil {
			log.Critical(err)
			return err
		}
		arguments = append(arguments, targets...)
	}

	// Parse each target string and generate a corresponding JSON array.
	jsonArray, err := g3model.BuildTargets(arguments)
	if err != nil {
		return err
	}

	// Write the output array.
	err = g3lib.SaveDataToFile(cmd.Output, jsonArray, cmd.Beautify)
	if err != nil {
		return err
	}
	return nil
}

func (cmd *ToolsCmd) Run(ctx CmdContext) error {
	output := cmd.Output

	// Sort the plugin names alphabetically.
	pluginNames := make([]string, len(ctx.Plugins))
	index := 0
	for key := range ctx.Plugins {
		pluginNames[index] = key
		index++
	}
	sort.Strings(pluginNames)

	// Open the output file.
	var fd *os.File
	var err error
	if output == "-" {
		fd = os.Stdout
	} else {
		fd, err = os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Critical("Error writing to file " + output + ": " + err.Error())
			return err
		}
		defer fd.Close()
	}

	// If -q is used, print only the names of the plugins.
	// If not, print a nicer looking output with all of the human descriptions and stuff.
	if !cmd.Quiet {
		fmt.Fprintln(fd, "")
	}
	for _, name := range pluginNames {
		if cmd.Quiet {
			fmt.Fprintln(fd, name)
		} else {
			plugin := ctx.Plugins[name]
			fmt.Fprintln(fd, plugin.String())
		}
	}
	return nil
}

func (cmd *RunCmd) Run(ctx CmdContext) error {

	// Change the log level based on the flags.
	var stderr io.Writer
	if cmd.Quiet {
		stderr = io.Discard
		log.SetLogLevel("CRITICAL")
	} else {
		stderr = os.Stderr
	}

	// Load only the selected plugins from the cache.
	tools := g3lib.G3PluginMetadata{}
	for _, name := range cmd.Tools {
		if metadata, ok := ctx.Plugins[name]; ok {
			tools[name] = metadata
		} else {
			log.Critical("Tool not found: " + name)
			return errors.New("Tool not found: " + name)
		}
	}

	// Parse the input JSON data.
	inputJson, err := g3lib.LoadDataFromFile(cmd.Input)
	if err != nil {
		log.Critical(err)
		return err
	}

	// Get all the past commands so we know we're not repeating any test.
	knownFingerprints := g3model.StringSet{}
	for _, data := range inputJson {
		for _, fp := range data["_fp"].([]interface{}) {
			knownFingerprints.Add(fp.(string))
		}
	}

	// Width for zero-padding artifact sub-slot indices so a lexical
	// directory listing matches numeric order. The input is shared across
	// all tools, so its width is computed once here; each plugin's command
	// width is computed per plugin below.
	inputIdxWidth := len(fmt.Sprintf("%d", len(inputJson)-1))

	// We're going to iterate over every selected plugin to see if we
	// can execute it with each of the objects in the input data.
	totalOutput := []g3model.Data{}
	for _, plugin := range tools {
		cmdIdxWidth := len(fmt.Sprintf("%d", len(plugin.Commands)-1))
		for inputIdx, data := range inputJson {
			for index := 0; index < len(plugin.Commands); index++ {

				// Dynamically evaluate if this plugin accepts this type of data.
				// Skip if it does not apply.
				ok, err := g3lib.EvalToolCondition(plugin, index, data)
				if !ok {
					if err != nil {
						log.Errorf("Error evaluating plugin %s: %s", plugin.Name, err.Error())
					}
					continue
				}

				// Calculate the command that's going to be run.
				parsed, errA := g3lib.BuildToolCommand(plugin, index, data)
				if len(errA) > 0 {
					log.Errorf("Error executing tool %s:", plugin.Name)
					for i, err := range errA {
						log.Errorf("%d) %s\n", i, err.Error())
					}
					return errA[0]
				}

				// Avoid running the same command twice.
				found := false
				for _, fp := range parsed.Fingerprint {
					if knownFingerprints.Exists(fp) {
						found = true
						continue
					}
					knownFingerprints.Add(fp)
				}
				if found {
					continue
				}

				// Run the plugin.
				log.Debug(
					"\n" +
						"--------------------------------------------------------------------------------\n" +
						"--- Running tool: " + plugin.Name + "\n" +
						"--- " + plugin.Description + "\n" +
						"--- " + plugin.URL + "\n" +
						"--------------------------------------------------------------------------------\n")

				// Resolve the artifact slot for this invocation. With
				// --artifacts, each (tool, input, command) triple gets its own
				// persistent sub-slot under the user's directory so the loop's
				// invocations never clobber each other's files; the deterministic
				// name also makes a re-run idempotent (it overwrites that exact
				// task's previous output rather than piling up copies). Without
				// --artifacts we fall back to a throwaway slot removed on exit.
				var slot string
				persistent := cmd.Artifacts != ""
				if persistent {
					name := fmt.Sprintf("g3-%s-%0*d-%0*d", plugin.Name, inputIdxWidth, inputIdx, cmdIdxWidth, index)
					slot = filepath.Join(cmd.Artifacts, name)
					if slotErr := os.MkdirAll(slot, 0o755); slotErr != nil {
						log.Warningf("Cannot create artifact slot %s, plugin will run without /artifacts: %s", slot, slotErr.Error())
						slot = ""
					}
				} else {
					var slotErr error
					slot, slotErr = g3lib.CreateEphemeralArtifactSlot()
					if slotErr != nil {
						log.Warningf("Cannot create ephemeral artifact slot, plugin will run without /artifacts: %s", slotErr.Error())
						slot = ""
					}
				}
				outputArray, err := g3lib.RunPluginCommand(ctx.Ctx, plugin, parsed, data, slot, stderr)
				if slot != "" && !persistent {
					os.RemoveAll(slot) //nolint:errcheck
				}
				if err != nil {
					log.Critical("Error executing tool " + plugin.Name + ": " + err.Error())
					return err
				}

				// We can only cancel a context once, so let's just quit now.
				if *ctx.Cancelled {
					return nil
				}

				// Validate the plugin output.
				for _, data := range outputArray {
					if err := data.Validate(); err != nil {
						jsonBytes, err2 := json.MarshalIndent(data, "", "  ")
						if err2 != nil {
							log.Critical("Malformed output data: " + err.Error() + "\n" + string(jsonBytes))
							return err
						}
						log.Critical("Malformed output data: " + err.Error() + "\n")
						return err
					}
				}

				// Append the output once all objects validated.
				totalOutput = append(totalOutput, outputArray...)
			}
		}
	}

	// Write the output array.
	err = g3lib.SaveDataToFile(cmd.Output, totalOutput, cmd.Beautify)
	if err != nil {
		log.Critical(err)
		return err
	}
	return nil
}

func (cmd *ImportCmd) Run(ctx CmdContext) error {
	var err error

	// Change the log level based on the flags.
	var stderr io.Writer
	if cmd.Quiet {
		stderr = io.Discard
		log.SetLogLevel("CRITICAL")
	} else {
		stderr = os.Stderr
	}

	// Get the requested importer plugin.
	plugin, ok := ctx.Plugins[cmd.Tool]
	if !ok || plugin.Importer == nil {
		log.Critical("Tool not found: " + cmd.Tool)
		return errors.New("Tool not found: " + cmd.Tool)
	}

	// Pipe the input file.
	stdin := os.Stdin
	if cmd.Input != "-" {
		stdin, err = os.Open(cmd.Input)
		if err != nil {
			log.Critical("Cannot open file " + cmd.Input + ": " + err.Error())
			return err
		}
		defer stdin.Close()
	}

	// Importers don't support conditions.
	// The command is run directly and the raw data piped to it.
	parsed, errA := g3lib.BuildImporterCommand(plugin)
	if len(errA) > 0 {
		log.Critical("Error executing importer " + plugin.Name + ":")
		for _, err := range errA {
			log.Critical(" - " + err.Error())
		}
		return errA[0]
	}
	outputArray, err := g3lib.RunPluginImporter(ctx.Ctx, plugin, parsed, stdin, stderr)
	if err != nil {
		log.Critical("Error executing importer " + plugin.Name + ": " + err.Error())
		return err
	}

	// We can only cancel a context once, so let's just quit now.
	if *ctx.Cancelled {
		return nil
	}

	// Write the output array.
	err = g3lib.SaveDataToFile(cmd.Output, outputArray, cmd.Beautify)
	if err != nil {
		log.Critical(err)
		return err
	}
	return nil
}

func (cmd *JoinCmd) Run(ctx CmdContext) error {

	// Open each input file and parse it, then append it to a single array.
	// If the special filename "-" is used, read from stdin. Can only be done once.
	usedStdin := false
	totalOutput := []g3model.Data{}
	for _, filepath := range cmd.Input {
		if filepath == "-" {
			if usedStdin {
				continue
			}
			usedStdin = true
		}
		inputJson, err := g3lib.LoadDataFromFile(filepath)
		if err != nil {
			log.Critical(err)
			return err
		}
		totalOutput = append(totalOutput, inputJson...)
	}

	// Write the output array.
	err := g3lib.SaveDataToFile(cmd.Output, totalOutput, cmd.Beautify)
	if err != nil {
		log.Critical(err)
		return err
	}
	return nil
}

func (cmd *FilterCmd) Run(ctx CmdContext) error {

	// Parse the input JSON data.
	inputJson, err := g3lib.LoadDataFromFile(cmd.Input)
	if err != nil {
		log.Critical(err)
		return err
	}

	// Filter the input data using the condition.
	filteredOutput := []g3model.Data{}
	for _, data := range inputJson {
		ok, err := g3lib.EvalCondition(cmd.Filter, data)
		if err != nil {
			log.Critical("Error evaluating condition: " + err.Error())
			return err
		}
		if ok {
			filteredOutput = append(filteredOutput, data)
		}
	}

	// Write the output array.
	err = g3lib.SaveDataToFile(cmd.Output, filteredOutput, cmd.Beautify)
	if err != nil {
		log.Critical(err)
		return err
	}
	return nil
}

// Run generates a report by running a reporter plugin (magenta by default)
// against a directory of tool artifacts. Reporting is delegated entirely to
// the plugin: the artifacts directory is mounted read-only as /input and the
// output directory read-write as /output, exactly like a server-side reporter
// task. The user is responsible for populating --artifacts (e.g. by directing
// `g3 run` output there).
func (cmd *ReportCmd) Run(ctx CmdContext) error {

	// Resolve the reporter plugin.
	plugin, ok := ctx.Plugins[cmd.Tool]
	if !ok || plugin.Reporter == nil {
		log.Critical("Reporter plugin not found: " + cmd.Tool)
		return errors.New("Reporter plugin not found: " + cmd.Tool)
	}

	// Build the reporter command line (resolves the preset, if any).
	parsed, errArr := g3lib.BuildReporterCommand(plugin, cmd.Preset)
	if len(errArr) > 0 {
		for _, e := range errArr {
			log.Error(e.Error())
		}
		return errArr[0]
	}

	// Resolve absolute host paths for the /input and /output mounts.
	inDir, err := filepath.Abs(cmd.Artifacts)
	if err != nil {
		log.Critical("Invalid artifacts directory: " + err.Error())
		return err
	}
	outDir, err := filepath.Abs(cmd.Output)
	if err != nil {
		log.Critical("Invalid output directory: " + err.Error())
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Critical("Cannot create output directory: " + err.Error())
		return err
	}

	// Pick the stderr sink (the reporter's live output).
	var stderr io.Writer = os.Stderr
	if cmd.Quiet {
		stderr = nil
	}

	// Docker-run the reporter plugin: <artifacts> → /input:ro, <output> → /output:rw.
	// Reporter plugins (e.g. magenta) close their own stdin, so we pass none.
	if err := g3lib.RunPluginReporter(ctx.Ctx, plugin, parsed, inDir, outDir, nil, stderr); err != nil {
		log.Critical("Reporter failed: " + err.Error())
		return err
	}
	log.Info("Report written to " + outDir)
	return nil
}
