package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"

	"github.com/alecthomas/kong"
	"github.com/go-playground/validator/v10"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
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
}

type MergeCmd struct {
	IOCmd
	FlagCmd
	Tools []string `arg:"" optional:"" help:"Tools to use for merging."`
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
	IOCmd
	FlagCmd
}

var CLI struct {
	Scan   ScanCmd   `cmd:"" aliases:"s" help:"Run a scan script."`
	Target TargetCmd `cmd:"" aliases:"t" help:"Prepare a list of targets."`
	Tools  ToolsCmd  `cmd:"" aliases:"p" help:"List the available tools."`
	Import ImportCmd `cmd:"" aliases:"i" help:"Load the output of a tool."`
	Run    RunCmd    `cmd:"" aliases:"r" help:"Run a tool."`
	Merge  MergeCmd  `cmd:"" aliases:"m" help:"Launch issue merger plugins."`
	Join   JoinCmd   `cmd:"" aliases:"j" help:"Join multiple G3 output files into one."`
	Filter FilterCmd `cmd:"" aliases:"f" help:"Filter the input using a logical condition."`
	Report ReportCmd `cmd:"" aliases:"o" help:"Produce a Markdown vulnerability report."`
}

type CmdContext struct {
	Ctx       context.Context
	Cancelled *bool
	Plugins   g3lib.G3PluginMetadata
}

func main() {
	var err error

	// Parse the command line options.
	parser := kong.Parse(&CLI,
		kong.Name("g3"),
		kong.Description("Golismero3 - The Pentesting Swiss Army Knife"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
	)

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
			log.Critical("\nSIGTERM received!")
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
	err = parser.Run(cmdctx)
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
	parsed, err := g3lib.ParseScript(plugins, script)
	if err == nil {
		err = validator.New().Struct(parsed)
	}
	if err != nil {
		log.Critical(err)
		return err
	}
	if len(parsed.Targets) == 0 { 		// TODO change the logic here so we can pass targets via cmdline
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
	var targetData []g3lib.G3Data
	if len(parsed.Targets) > 0 {
		targetData, err = g3lib.BuildTargets(parsed.Targets)
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
				var newData []g3lib.G3Data

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
						var pastData []g3lib.G3Data
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
							"\n" +
							"--------------------------------------------------------------------------------\n" +
							"--- Progress: %d%% (completed %d steps out of %d)\n" +
							"--- Running tool: %s\n" +
							"--- %s\n" +
							"--- %s\n" +
							"--------------------------------------------------------------------------------\n",
							int(((currentScanStep - 1) * 100) / totalScanSteps), currentScanStep - 1, totalScanSteps,
							plugin.Name, plugin.Description["en"], plugin.URL)
						resultData, err := g3lib.RunPluginCommand(ctx, plugin, parsed, data, stderr)
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
		targets, err := g3lib.LoadTargetsFromFile(cmd.Input)
		if err != nil {
			log.Critical(err)
			return err
		}
		arguments = append(arguments, targets...)
	}

	// Parse each target string and generate a corresponding JSON array.
	jsonArray, err := g3lib.BuildTargets(arguments)
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
	knownFingerprints := g3lib.StringSet{}
	for _, data := range inputJson {
		for _, fp := range data["_fp"].([]interface{}) {
			knownFingerprints.Add(fp.(string))
		}
	}

	// We're going to iterate over every selected plugin to see if we
	// can execute it with each of the objects in the input data.
	totalOutput := []g3lib.G3Data{}
	for _, plugin := range tools {
		for _, data := range inputJson {
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
					"--- " + plugin.Description["en"] + "\n" +
					"--- " + plugin.URL + "\n" +
					"--------------------------------------------------------------------------------\n")
				outputArray, err := g3lib.RunPluginCommand(ctx.Ctx, plugin, parsed, data, stderr)
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
					if ok, err := g3lib.IsValidData(data); !ok {
						jsonBytes, err2 := json.MarshalIndent(data, "", "  ")
						if err2 != nil {
							log.Critical("Internal error!" + err.Error())
						}
						if err != nil {
							log.Critical("Malformed output data: " + err.Error() + "\n" + string(jsonBytes))
							return err
						}
						log.Critical("Malformed output data:\n" + string(jsonBytes))
						return errors.New("Malformed output data:\n" + string(jsonBytes))
					}

					// Append the output.
					totalOutput = append(totalOutput, outputArray...)
				}
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
	totalOutput := []g3lib.G3Data{}
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
	filteredOutput := []g3lib.G3Data{}
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

func (cmd *MergeCmd) Run(ctx CmdContext) error {

	// Change the log level based on the flags.
	var stderr io.Writer
	if cmd.Quiet {
		stderr = io.Discard
		log.SetLogLevel("CRITICAL")
	} else {
		stderr = os.Stderr
	}

	// Parse the input JSON data.
	inputJson, err := g3lib.LoadDataFromFile(cmd.Input)
	if err != nil {
		log.Critical(err)
		return err
	}

	// Remove all data objects that are not issues.
	// Add fake IDs for the objects that do not have one.
	var nullid interface{} = "000000000000000000000000"
	filteredOutput := []g3lib.G3Data{}
	for _, data := range inputJson {
		if datatype, ok := data["_type"]; ok && datatype.(string) == "issue" {
			if _, ok := data["_id"]; !ok {
				data["_id"] = nullid
			}
			filteredOutput = append(filteredOutput, data)
		}
	}

	// Get the merger plugins.
	mergers := g3lib.G3PluginMetadata{}
	if len(cmd.Tools) > 0 {
		for _, name := range cmd.Tools {
			if metadata, ok := ctx.Plugins[name]; ok && metadata.Merger != nil {
				mergers[name] = metadata
			} else {
				log.Critical("Tool not found or does not implement a merger: " + name)
				return errors.New("Tool not found or does not implement a merger: " + name)
			}
		}
	} else {
		for name, metadata := range ctx.Plugins {
			if metadata.Merger != nil {
				mergers[name] = metadata
			}
		}
	}

	// Go through every plugin that has implemented a merger.
	totalOutput := []g3lib.G3Data{}
	for tool, plugin := range mergers {

		// Get the issues for this plugin.
		issues := []g3lib.G3Data{}
		for _, data := range filteredOutput {
			if name, ok := data["_tool"]; ok && name.(string) == tool {
				issues = append(issues, data)
			}
		}

		// If there are no issues reported by this plugin, skip the plugin.
		if len(issues) == 0 {
			log.Debugf("Skipped merger for tool %s since it reported no issues.", tool)
			continue
		}

		// If there is a single issue reported by this plugin, use that issue.
		if len(issues) == 1 {
			log.Debugf("Skipped merger for tool %s since it reported a single issue.", tool)
			totalOutput = append(totalOutput, issues[0])
			continue
		}

		// Build the merger command.
		parsed, errA := g3lib.BuildMergerCommand(plugin)
		if len(errA) > 0 {
			log.Critical("Error while running merger for " + plugin.Name + ":")
			for _, err := range errA {
				log.Critical(" - " + err.Error())
			}
			return errA[0]
		}

		// Run the merger.
		log.Info("Running merger for tool: " + tool)
		outputArray, err := g3lib.RunPluginMerger(context.Background(), plugin, parsed, issues, stderr)
		if err != nil {
			log.Criticalf("Error while running merger for %s: %s", tool, err.Error())
			return err
		}

		// Validate the plugin output. Drop any objects that don't pass the test.
		sanitizedOutput := []g3lib.G3Data{}
		for _, data := range outputArray {
			if ok, err := g3lib.IsValidData(data); !ok {
				if err != nil {
					log.Error("Malformed output data: " + err.Error() + "\n" + data.String())
				} else {
					log.Error("Malformed output data:\n" + data.String())
				}
			} else {
				sanitizedOutput = append(sanitizedOutput, data)
			}
		}

		// Count how many objects were preserved, created or deleted.
		// Remove the fake IDs we added at the beginning.
		newCount := 0
		preservedCount := 0
		for _, data := range sanitizedOutput {
			if id, ok := data["_id"]; ok {
				if id.(string) == nullid.(string) {
					delete(data, "_id")
				}
				preservedCount++
			} else {
				newCount++
			}
		}
		deletedCount := len(issues) - preservedCount
		log.Infof("Merger created %d new issue(s), deleted %d old issue(s), and left %d issue(s) intact.", newCount, deletedCount, preservedCount)

		// Add the merged objects to the output of this command.
		totalOutput = append(totalOutput, sanitizedOutput...)
	}

	// Write the output array.
	err = g3lib.SaveDataToFile(cmd.Output, totalOutput, cmd.Beautify)
	if err != nil {
		log.Critical(err)
		return err
	}
	return nil
}

func (cmd *ReportCmd) Run(ctx CmdContext) error {
	var err error

	// Parse the input JSON data.
	var inputJson []g3lib.G3Data
	var tools []string
	inputJson, err = g3lib.LoadDataFromFile(cmd.Input)
	if err != nil {
		log.Critical(err)
		return err
	}
	for _, data := range inputJson {
		name := data["_tool"].(string)
		if !g3lib.ContainsStr(tools, name) {
			tools = append(tools, name)
		}
	}

	// Load the main i18n strings.
	i18nStrings := g3lib.LoadG3Strings()

	// Load the plugins i18n templates.
	pluginTemplatesCache := g3lib.LoadPluginTemplates()

	// Build the report.
	reporter := g3lib.NewMarkdownReporter(g3lib.DefaultConfig, ctx.Plugins, pluginTemplatesCache, i18nStrings)
	textOutput, errorArray := reporter.Build("en", "Golismero3 Scan Report", inputJson, tools)
	if len(errorArray) > 0 {
		for _, err := range errorArray {
			log.Error(err.Error())
		}
	}

	// Save the report text.
	if cmd.Output == "-" {
		fmt.Print(textOutput)
	} else {
		err = os.WriteFile(cmd.Output, []byte(textOutput), 0644)
		if err != nil {
			log.Critical("Error writing to file " + cmd.Output + ": " + err.Error())
			return err
		}
	}
	return nil
}
