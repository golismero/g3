package g3lib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kballard/go-shellquote"

	log "golismero.com/g3log"
)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const G3_DOCKER_NETWORK = "G3_DOCKER_NETWORK"

type G3ToolCommand struct {
	Condition   string              `json:"condition"           validate:"required"`        // Execution condition for a tool.
	Fingerprint []string            `json:"fingerprint"         validate:"required"`        // Fingerprint for the command.
	Command     []string            `json:"command,omitempty"`                              // (Optional) Command template for a tool.
	DockerOpt   []string            `json:"dockeropt,omitempty"`                            // (Optional) Docker options for the tool.
	Returns     string              `json:"returns,omitempty"`                              // (Optional) Data type returned by the tool.
}

type G3ImporterCommand struct {
	Command     []string            `json:"command,omitempty"`                              // (Optional) Command to execute when importing. Not a template.
	DockerOpt   []string            `json:"dockeropt,omitempty"`                            // (Optional) Docker options for the importer.
	Fingerprint []string            `json:"fingerprint,omitempty"`                          // (Optional) Fingerprint for the command.
	Returns     string              `json:"returns,omitempty"`                              // (Optional) Data type returned by the importer.
}

type G3MergerCommand struct {
	Command     []string            `json:"command,omitempty"`                              // (Optional) Command template for a tool.
	DockerOpt   []string            `json:"dockeropt,omitempty"`                            // (Optional) Docker options for the tool.
}

type G3Plugin struct {
	Name        string              `json:"name"`                                           // Tool name. Must be unique.
	Description map[string]string   `json:"description"`                                    // Description for humans, translated.
	URL         string              `json:"url"                 validate:"url"`             // URL for humans.
	Image       string              `json:"image"`                                          // Docker image.
	Commands    []G3ToolCommand     `json:"commands,omitempty"  validate:"omitempty,dive"`  // (Optional) Array of commands and conditions.
	Importer    *G3ImporterCommand  `json:"importer,omitempty"  validate:"omitempty,dive"`  // (Optional) Command for importing files.
	Merger      *G3MergerCommand    `json:"merger,omitempty"    validate:"omitempty,dive"`  // (Optional) Command for merging issues.
}
func (plugin G3Plugin) String() string {
	output := ""
	output = output + fmt.Sprintln("Name:        " + plugin.Name)
	output = output + fmt.Sprintln("Homepage:    " + plugin.URL)
	output = output + fmt.Sprintln("Description: " + plugin.Description["en"])
	return output
}

type G3PluginMetadata map[string]G3Plugin

// Runtime struct for the parsed plugin command, after applying the condition and executing the template.
type ParsedPluginCommand struct {
	Command 	[]string
	DockerOpt	[]string
	Fingerprint []string
	ParsedFP	bool
	Returns     string
}

// i18n templates for the plugins.
type G3PluginTemplates map[string]string							// language -> text template
type G3PluginTemplatesCache map[string]G3PluginTemplates			// plugin name -> language

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Load all plugins from the plugins cache.
// This function will panic on error.
func LoadPlugins() G3PluginMetadata {

	// Get the G3HOME directory.
	g3home := GetHomeDirectory()

	// Load the plugins cache JSON file.
	path := filepath.Join(g3home, G3CONFIG, G3PLUGINS)
	data, err := os.ReadFile(path)
	if err != nil {
		panic("Failed to process " + path + ": " + err.Error())
	}

	// Parse the JSON file.
	plugins := G3PluginMetadata{}
	err = json.Unmarshal(data, &plugins)
	if err != nil {
		panic("Failed to process " + path + ": " + err.Error())
	}

	// Return the map.
	return plugins
}

// Load plugin i18n templates from the cache.
// This function will panic on error.
func LoadPluginTemplates() G3PluginTemplatesCache {

	// Get the G3HOME directory.
	g3home := GetHomeDirectory()

	// Load the plugin templates cache JSON file.
	path := filepath.Join(g3home, G3CONFIG, G3TEMPLATES)
	data, err := os.ReadFile(path)
	if err != nil {
		panic("Failed to process " + path + ": " + err.Error())
	}

	// Parse the JSON file.
	pluginTemplates := G3PluginTemplatesCache{}
	err = json.Unmarshal(data, &pluginTemplates)
	if err != nil {
		panic("Failed to process " + path + ": " + err.Error())
	}

	// Return the map.
	return pluginTemplates
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Evaluate a logical condition.
func EvalCondition(condition string, data G3Data) (bool, error) {

	// Evaluate the template. We expect it to generate a text with the
	// string "true" or "false", anything else we treat as an error.
	value, err := ExpandTemplate(condition, data)
	if err != nil {
		return false, err
	}
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "\t", "")
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	if value == "true" {
		return true, nil
	}
	if value == "false" {
		return false, nil
	}
	return false, fmt.Errorf("invalid result from condition: \"%s\"", value)
}

// Evaluate the condition for the tool to run or not.
func EvalToolCondition(plugin G3Plugin, index int, data G3Data) (bool, error) {

	// Do not send data back to the plugin that created it.
	if plugin.Name == data["_tool"] {
		return false, nil
	}

	// Evaluate the condition.
	return EvalCondition(plugin.Commands[index].Condition, data)
}

// Build the command line for the plugin to execute inside the container, and its matching Docker options.
func BuildToolCommand(plugin G3Plugin, index int, data G3Data) (ParsedPluginCommand, []error) {
	var errorArray []error
	var command []string
	var tmpErrA []error

	// Build the tool command line.
	// This template gets expanded using the data object.
	command, errorArray = ExpandTemplateArray(plugin.Commands[index].Command, data)

	// Build the Docker options.
	// This template gets expanded using the environment variables.
	dockerOpt := []string{"-i", "--rm"}
	if plugin.Commands[index].DockerOpt != nil {
		dockerOpt, tmpErrA = ExpandTemplateArray(plugin.Commands[index].DockerOpt, GetEnvironmentMap())
		errorArray = append(errorArray, tmpErrA...)
	}

	// Build the plugin fingerprint.
	// This template gets expanded using the data object.
	fingerprint, tmpErrA := BuildPluginFingerprint(plugin.Commands[index].Fingerprint, data)
	errorArray = append(errorArray, tmpErrA...)

	// Return a non conditional command and an array of parsing errors.
	var parsed ParsedPluginCommand
	parsed.Command = command
	parsed.DockerOpt = dockerOpt
	parsed.Fingerprint = fingerprint
	parsed.ParsedFP = true
	parsed.Returns = plugin.Commands[index].Returns
	return parsed, errorArray
}

// Build the command line and Docker options for the importer.
func BuildImporterCommand(plugin G3Plugin) (ParsedPluginCommand, []error) {
	var parsed ParsedPluginCommand
	var errorArray []error
	var tmpErrA []error

	// Trivial case, the plugin did not define an importer.
	if plugin.Importer == nil {
		errorArray = append(errorArray, fmt.Errorf("plugin %s does not implement an importer", plugin.Name))
		return parsed, errorArray
	}

	// Build the tool command line and docker options.
	// These templates are expanded using the environment variables.
	// Note how this is different from running a tool against a live target.
	environment := GetEnvironmentMap()
	command := []string{}
	if len(plugin.Importer.Command) > 0 {
		command, tmpErrA = ExpandTemplateArray(plugin.Importer.Command, environment)
		errorArray = append(errorArray, tmpErrA...)
	}
	dockerOpt := []string{"-i", "--rm", "--entrypoint", "/usr/bin/g3i"}
	if len(plugin.Importer.DockerOpt) > 0 {
		dockerOpt, tmpErrA = ExpandTemplateArray(plugin.Importer.DockerOpt, environment)
		errorArray = append(errorArray, tmpErrA...)
	}

	// Return a non conditional command and an array of parsing errors.
	parsed.Command = command
	parsed.DockerOpt = dockerOpt
	parsed.Fingerprint = plugin.Importer.Fingerprint
	parsed.ParsedFP = false
	parsed.Returns = plugin.Importer.Returns
	return parsed, errorArray
}

// Build the command line and Docker options for the merger.
func BuildMergerCommand(plugin G3Plugin) (ParsedPluginCommand, []error) {
	var parsed ParsedPluginCommand
	var errorArray []error
	var tmpErrA []error

	// Trivial case, the plugin did not define a merger.
	if plugin.Merger == nil {
		errorArray = append(errorArray, fmt.Errorf("plugin %s does not implement an merger", plugin.Name))
		return parsed, errorArray
	}

	// Build the tool command line and docker options.
	// These templates are expanded using the environment variables.
	// Note how this is different from running a tool against a live target.
	environment := GetEnvironmentMap()
	command := []string{}
	if len(plugin.Merger.Command) > 0 {
		command, tmpErrA = ExpandTemplateArray(plugin.Merger.Command, environment)
		errorArray = append(errorArray, tmpErrA...)
	}
	dockerOpt := []string{"-i", "--rm", "--entrypoint", "/usr/bin/g3m"}
	if len(plugin.Merger.DockerOpt) > 0 {
		dockerOpt, tmpErrA = ExpandTemplateArray(plugin.Merger.DockerOpt, environment)
		errorArray = append(errorArray, tmpErrA...)
	}

	// Return a non conditional command and an array of parsing errors.
	parsed.Command = command
	parsed.DockerOpt = dockerOpt
	parsed.Returns = "issue"
	return parsed, errorArray
}

// Build the plugin fingerprint.
func BuildPluginFingerprint(fingerprintTemplate []string, data G3Data) ([]string, []error) {
	var errorArray []error
	var fingerprint []string
	for _, token := range fingerprintTemplate {

		// Parse the token as a template.
		value, err := ExpandTemplate(token, data)

		// Missing values on expansion cause the entry to be ignored automatically.
		// This should not generate an error.
		if err != nil {
			continue
		}

		// Add the parsed string to the fingerprint array.
		fingerprint = append(fingerprint, value)
	}

	// Return the parsed fingerprint and errors.
	return fingerprint, errorArray
}

// Run the command on the plugin's container.
func RunPluginCommand(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, data G3Data, stderr io.Writer) ([]G3Data, error) {

	// Convert the input data to JSON format.
	jsonData, err := json.Marshal(data)
	if err != nil {
		return []G3Data{}, err
	}

	// Write the input JSON into stdin for the plugin.
	var stdin bytes.Buffer
	stdin.Write(jsonData)

	// Run the command on the plugin's container.
	return runPluginInternal(ctx, plugin, parsed, &stdin, stderr)
}

// Run an importer, passing the input file as a reader.
func RunPluginImporter(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, stdin io.Reader, stderr io.Writer) ([]G3Data, error) {
	return runPluginInternal(ctx, plugin, parsed, stdin, stderr)
}

// Run a merger, passing a list of issues as input.
func RunPluginMerger(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, issues []G3Data, stderr io.Writer) ([]G3Data, error) {

	// Convert the input data to JSON format.
	jsonData, err := json.Marshal(issues)
	if err != nil {
		return []G3Data{}, err
	}

	// Write the input JSON into stdin for the plugin.
	var stdin bytes.Buffer
	stdin.Write(jsonData)

	// Run the command on the plugin's container.
	return runPluginInternal(ctx, plugin, parsed, &stdin, stderr)
}

// Run a plugin but take the input from a reader.
func runPluginInternal(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, stdin io.Reader, stderr io.Writer) ([]G3Data, error) {
	var outputArray []G3Data
	var stdout bytes.Buffer

	// Get the network name for Golismero.
	network := os.Getenv(G3_DOCKER_NETWORK)

	// Create a temporary file so we can get the ID of the container.
	tempfile, err := os.CreateTemp(os.TempDir(), "g3-")
	if err != nil {
		return outputArray, err
	}
	os.Remove(tempfile.Name())
	defer os.Remove(tempfile.Name())

	// Prepare the full command line to execute.
	commandLine := []string{"docker", "run", "-q", "--cidfile", tempfile.Name(), "-v", "./resources:/resources:ro"}
	if network != "" {
		commandLine = append(commandLine, "--network", network)
	}
	commandLine = append(commandLine, parsed.DockerOpt...)
	commandLine = append(commandLine, plugin.Image)
	commandLine = append(commandLine, parsed.Command...)
	//fmt.Println(commandLine)		// XXX DEBUG

	// Run the command, with cancellation.
	// When cancelled, stop the Docker container.
	cancelled := false
	process := exec.Command(commandLine[0], commandLine[1:]...)
	process.Stdin = stdin
	process.Stdout = &stdout
	if stderr != nil {
		process.Stderr = stderr
	} else {
		process.Stderr = io.Discard
	}
	startTime := time.Now().Unix()
	c := make(chan error)

	err = process.Start()
	if err != nil {
		return outputArray, err
	}
	go func(c chan error, process *exec.Cmd) {
		c <- process.Wait()
	}(c, process)
	select {
	case <-ctx.Done():
		cancelled = true
		log.Info("Cancellation requested, stopping container...")
		b, e := os.ReadFile(tempfile.Name())
		if e != nil {
			log.Error(e.Error())
		} else {
			log.Debug("Container ID: " + string(b))
			cmd := []string{"stop", string(b)}
			c := exec.Command("docker", cmd...)
			c.Dir = GetHomeDirectory()
			e = c.Run()
			if e != nil {
				log.Error(e.Error())
			}
		}
		log.Info("Container stopped.")
	case e := <-c:
		err = e
	}
	if cancelled || err != nil {
		return outputArray, err
	}
	endTime := time.Now().Unix()

	// Parse the output JSON array and add some needed properties.
	// On error we will try to return the malformed data anyway.
	// If the output array is empty, add a dummy object to generate a valid fingerprint.
	raw := stdout.Bytes()
	//fmt.Println(string(raw))		// XXX DEBUG
	err = json.Unmarshal(raw, &outputArray)
	if err == nil && len(outputArray) == 0 {
		dummy := G3Data{}
		dummy["_type"] = "nil"
		outputArray = append(outputArray, dummy)
	}
	for _, data := range outputArray {
		if _, ok := data["_type"]; !ok {
			data["_type"] = parsed.Returns
		}
		if _, ok := data["_tool"]; !ok {
			data["_tool"] = plugin.Name
		}
		if _, ok := data["_fp"]; !ok {
			fingerprint := parsed.Fingerprint
			if !parsed.ParsedFP {
				var errorArray []error
				fingerprint, errorArray = BuildPluginFingerprint(parsed.Fingerprint, data)
				if len(errorArray) > 0 {
					err = errorArray[0]
					fingerprint = parsed.Fingerprint	// still better than nothing
				}
			}
			fpiarr := make([]interface{}, len(fingerprint))
			for i, v := range fingerprint {
				fpiarr[i] = v
			}
			data["_fp"] = fpiarr
		}
		if _, ok := data["_cmd"]; !ok {
			data["_cmd"] = shellquote.Join(parsed.Command...)
		}
		if _, ok := data["_start"]; !ok {
			data["_start"] = startTime
		}
		if _, ok := data["_end"]; !ok {
			data["_end"] = endTime
		}
	}

	// Return the parsed output and error condition if any.
	return outputArray, err
}
