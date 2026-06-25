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

	log "github.com/golismero/g3/src/g3log"
)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const G3_PLUGINS_CACHE_FILE = "G3_PLUGINS_CACHE_FILE"
const G3_DOCKER_NETWORK = "G3_DOCKER_NETWORK"

// Environment variables for the shared artifacts volume.
//   G3_ARTIFACTS_ROOT      — path the worker process itself reads/writes (mkdir, manifest).
//   G3_ARTIFACTS_HOST_ROOT — path passed to `docker run -v` (the host daemon's view).
// They hold the same value when the artifacts root is mounted at an identical
// absolute path on the host and inside the worker container; G3_ARTIFACTS_HOST_ROOT
// is the escape hatch for deployments that cannot achieve that parity.
const G3_ARTIFACTS_ROOT = "G3_ARTIFACTS_ROOT"
const G3_ARTIFACTS_HOST_ROOT = "G3_ARTIFACTS_HOST_ROOT"
const G3_ARTIFACTS_ROOT_DEFAULT = "/app/artifacts"

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

type G3ReporterCommand struct {
	Name      string   `json:"name"               validate:"required"`         // Preset name; uniqueness validated in g3config.
	Command   []string `json:"command,omitempty"`                              // (Optional) Command template, env-var expansion only.
	DockerOpt []string `json:"dockeropt,omitempty"`                            // (Optional) Docker options, env-var expansion only.
}

type G3ReporterPhase struct {
	Default  string              `json:"default,omitempty"`                            // (Optional) Name of the default preset; must reference an existing command.
	Commands []G3ReporterCommand `json:"commands,omitempty" validate:"omitempty,dive"` // (Optional) Named presets. Empty means "entrypoint runs with no args".
}

type G3Plugin struct {
	Name        string              `json:"name"`                                           // Tool name. Must be unique.
	Category    string              `json:"category"`                                       // Defaults to parent directory name.
	Description string              `json:"description"`                                    // Description for humans.
	URL         string              `json:"url"                 validate:"url"`             // URL for humans.
	Image       string              `json:"image"`                                          // Docker image.
	Commands    []G3ToolCommand     `json:"commands,omitempty"  validate:"omitempty,dive"`  // (Optional) Array of commands and conditions.
	Importer    *G3ImporterCommand  `json:"importer,omitempty"  validate:"omitempty"`       // (Optional) Command for importing files.
	Merger      *G3MergerCommand    `json:"merger,omitempty"    validate:"omitempty"`       // (Optional) Command for merging issues.
	Reporter    *G3ReporterPhase    `json:"reporter,omitempty"  validate:"omitempty"`       // (Optional) Phase for generating downloadable reports.
}
func (plugin G3Plugin) String() string {
	output := ""
	output = output + fmt.Sprintln("Name:        " + plugin.Name)
	output = output + fmt.Sprintln("Category:    " + plugin.Category)
	output = output + fmt.Sprintln("Homepage:    " + plugin.URL)
	output = output + fmt.Sprintln("Description: " + plugin.Description)
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Load all plugins from the plugins cache.
// This function will panic on error.
func LoadPlugins() G3PluginMetadata {

	// Pull the location of the plugins cache file from the environment, if available.
	// If not, use the default location.
	path := os.Getenv(G3_PLUGINS_CACHE_FILE)
	if path == "" {
		g3home := GetHomeDirectory()
		path = filepath.Join(g3home, G3CONFIG, G3PLUGINS)
	}

	// Load the plugins cache JSON file.
	data, err := os.ReadFile(path)
	if err != nil {
		panic("Failed to process " + path + ": " + err.Error())
	}
	log.Debug("Loaded plugins from: " + path)

	// Parse the JSON file.
	plugins := G3PluginMetadata{}
	err = json.Unmarshal(data, &plugins)
	if err != nil {
		panic("Failed to process " + path + ": " + err.Error())
	}

	// Return the map.
	return plugins
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

// Build the command line and Docker options for a reporter run. presetName is
// the caller-supplied preset; resolution order is:
//   1. presetName, if non-empty (must match a declared command name)
//   2. plugin.Reporter.Default, if non-empty
//   3. first command in plugin.Reporter.Commands
//   4. no command at all (the container entrypoint runs with no args)
// The default DockerOpt overrides the image entrypoint to /usr/bin/g3r,
// mirroring how importer/merger override to /usr/bin/g3i and /usr/bin/g3m.
func BuildReporterCommand(plugin G3Plugin, presetName string) (ParsedPluginCommand, []error) {
	var parsed ParsedPluginCommand
	var errorArray []error

	// Trivial case: plugin did not declare a reporter phase.
	if plugin.Reporter == nil {
		errorArray = append(errorArray, fmt.Errorf("plugin %s does not implement a reporter", plugin.Name))
		return parsed, errorArray
	}

	// Resolve which command (if any) the caller wants.
	var resolved *G3ReporterCommand
	if len(plugin.Reporter.Commands) > 0 {
		chosen := presetName
		if chosen == "" {
			chosen = plugin.Reporter.Default
		}
		if chosen == "" {
			resolved = &plugin.Reporter.Commands[0]
		} else {
			for i := range plugin.Reporter.Commands {
				if plugin.Reporter.Commands[i].Name == chosen {
					resolved = &plugin.Reporter.Commands[i]
					break
				}
			}
			if resolved == nil {
				errorArray = append(errorArray, fmt.Errorf("plugin %s has no reporter preset named %q", plugin.Name, chosen))
				return parsed, errorArray
			}
		}
	} else if presetName != "" {
		errorArray = append(errorArray, fmt.Errorf("plugin %s declares no reporter presets, but preset %q was requested", plugin.Name, presetName))
		return parsed, errorArray
	}

	// Build command and dockeropt arrays. Templates are expanded against the
	// environment only — reporters never see G3Data templates.
	environment := GetEnvironmentMap()
	command := []string{}
	dockerOpt := []string{"-i", "--rm", "--entrypoint", "/usr/bin/g3r"}
	if resolved != nil {
		var tmpErrA []error
		if len(resolved.Command) > 0 {
			command, tmpErrA = ExpandTemplateArray(resolved.Command, environment)
			errorArray = append(errorArray, tmpErrA...)
		}
		if len(resolved.DockerOpt) > 0 {
			dockerOpt, tmpErrA = ExpandTemplateArray(resolved.DockerOpt, environment)
			errorArray = append(errorArray, tmpErrA...)
		}
	}

	parsed.Command = command
	parsed.DockerOpt = dockerOpt
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

// Run the command on the plugin's container. artifactsHostDir, if non-empty,
// is bind-mounted into the plugin container as /artifacts:rw — the per-task
// slot the plugin may write into. Pass "" if no artifact slot is wanted.
func RunPluginCommand(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, data G3Data, artifactsHostDir string, stderr io.Writer) ([]G3Data, error) {

	// Convert the input data to JSON format.
	jsonData, err := json.Marshal(data)
	if err != nil {
		return []G3Data{}, err
	}

	// Write the input JSON into stdin for the plugin.
	var stdin bytes.Buffer
	stdin.Write(jsonData)

	// Run the command on the plugin's container.
	return runPluginInternal(ctx, plugin, parsed, &stdin, artifactsHostDir, stderr)
}

// Run an importer, passing the input file as a reader. Importers do not write
// artifact files; the /artifacts mount is intentionally not provided.
func RunPluginImporter(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, stdin io.Reader, stderr io.Writer) ([]G3Data, error) {
	return runPluginInternal(ctx, plugin, parsed, stdin, "", stderr)
}

// Run a merger, passing a list of issues as input. Mergers do not write
// artifact files; the /artifacts mount is intentionally not provided.
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
	return runPluginInternal(ctx, plugin, parsed, &stdin, "", stderr)
}

// Build the "-e NAME" docker args for every host env var matching G3_ENV_*.
// Values are not duplicated on the command line; Docker reads them from the
// worker process. Plugin authors can also reference these via the `env`
// template function.
func ForwardedPluginEnvArgs() []string {
	var args []string
	for _, e := range os.Environ() {
		if i := strings.Index(e, "="); i >= 0 {
			name := e[:i]
			if strings.HasPrefix(name, "G3_ENV_") {
				args = append(args, "-e", name)
			}
		}
	}
	return args
}

// Build the "--sysctl" docker args that disable IPv6 inside the plugin
// container's network namespace, or nil. The Docker daemon (root) performs the
// write; the worker only stats the sysctl path (unprivileged). Three cases:
//   - deployment supports IPv6 (G3_ENV_IPV6_SUPPORTED=true): leave the stack on
//   - no IPv6: disable it, so tools that resolve hostnames internally (nikto,
//     wafw00f, ...) never attempt IPv6 connections
//   - kernel has IPv6 compiled out (sysctl path absent): nothing to do, and
//     passing --sysctl would error — so skip. This is also the case where IPv6
//     is already off, making the skip both safe and correct.
func DisableContainerIPv6Args() []string {
	if strings.EqualFold(os.Getenv("G3_ENV_IPV6_SUPPORTED"), "true") {
		return nil
	}
	if _, err := os.Stat("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err != nil {
		return nil
	}
	return []string{
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
		"--sysctl", "net.ipv6.conf.default.disable_ipv6=1",
	}
}

// Run a reporter plugin container. Differs from RunPluginCommand in three ways:
//   - binds two host directories (hostInDir → /input:ro, hostOutDir → /output:rw)
//     instead of a single /artifacts mount;
//   - pipes the caller-supplied stdin reader straight to the container (the
//     caller is responsible for closing the reader; see ReporterStdinStream);
//   - does NOT parse stdout as G3Data — reporters write files to /output, so
//     stdout/stderr are both routed to the task log writer.
//
// Returns nil on container exit 0, ctx.Err() on cancellation, or the underlying
// exec error otherwise.
func RunPluginReporter(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, hostInDir, hostOutDir string, stdin io.Reader, stderr io.Writer) error {
	network := os.Getenv(G3_DOCKER_NETWORK)

	tempfile, err := os.CreateTemp(os.TempDir(), "g3-")
	if err != nil {
		return err
	}
	os.Remove(tempfile.Name()) //nolint:errcheck
	defer os.Remove(tempfile.Name()) //nolint:errcheck

	commandLine := []string{"docker", "run", "-q", "--cidfile", tempfile.Name(), "-v", "./resources:/resources:ro"}
	if hostInDir != "" {
		commandLine = append(commandLine, "-v", hostInDir+":/input:ro")
	}
	if hostOutDir != "" {
		commandLine = append(commandLine, "-v", hostOutDir+":/output:rw")
	}
	if network != "" {
		commandLine = append(commandLine, "--network", network)
	}
	commandLine = append(commandLine, ForwardedPluginEnvArgs()...)
	commandLine = append(commandLine, DisableContainerIPv6Args()...)
	commandLine = append(commandLine, parsed.DockerOpt...)
	commandLine = append(commandLine, plugin.Image)
	commandLine = append(commandLine, parsed.Command...)

	process := exec.Command(commandLine[0], commandLine[1:]...)
	if stdin != nil {
		process.Stdin = stdin
	}
	if stderr != nil {
		process.Stdout = stderr
		process.Stderr = stderr
	} else {
		process.Stdout = io.Discard
		process.Stderr = io.Discard
	}

	c := make(chan error)
	if err := process.Start(); err != nil {
		return err
	}
	go func() { c <- process.Wait() }()

	select {
	case <-ctx.Done():
		log.Info("Cancellation requested, stopping reporter container...")
		if b, e := os.ReadFile(tempfile.Name()); e != nil {
			log.Error(e.Error())
		} else {
			log.Debug("Container ID: " + string(b))
			stop := exec.Command("docker", "stop", string(b))
			stop.Dir = GetHomeDirectory()
			if e := stop.Run(); e != nil {
				log.Error(e.Error())
			}
		}
		log.Info("Reporter container stopped.")
		return ctx.Err()
	case e := <-c:
		return e
	}
}

// Run a plugin but take the input from a reader.
func runPluginInternal(ctx context.Context, plugin G3Plugin, parsed ParsedPluginCommand, stdin io.Reader, artifactsHostDir string, stderr io.Writer) ([]G3Data, error) {
	var outputArray []G3Data
	var stdout bytes.Buffer

	// Get the network name for Golismero.
	network := os.Getenv(G3_DOCKER_NETWORK)

	// Create a temporary file so we can get the ID of the container.
	tempfile, err := os.CreateTemp(os.TempDir(), "g3-")
	if err != nil {
		return outputArray, err
	}
	os.Remove(tempfile.Name()) //nolint:errcheck
	defer os.Remove(tempfile.Name()) //nolint:errcheck

	// Prepare the full command line to execute.
	commandLine := []string{"docker", "run", "-q", "--cidfile", tempfile.Name(), "-v", "./resources:/resources:ro"}

	// Mount the caller-supplied artifact slot as /artifacts inside the plugin
	// container. Empty means "no artifact slot" (used by importers and mergers,
	// and by callers that don't need plugins to persist files).
	if artifactsHostDir != "" {
		commandLine = append(commandLine, "-v", artifactsHostDir+":/artifacts:rw")
	}

	if network != "" {
		commandLine = append(commandLine, "--network", network)
	}
	commandLine = append(commandLine, ForwardedPluginEnvArgs()...)
	commandLine = append(commandLine, DisableContainerIPv6Args()...)
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
		// Propagate the cancellation up to the caller. Without this the
		// function would return (outputArray, nil) and the worker would
		// be unable to distinguish a cancelled task from a successful
		// run, leading to a spurious [g3:done] state=DONE marker.
		err = ctx.Err()
	case e := <-c:
		err = e
	}
	// Cancellation short-circuits: propagate ctx.Err() and discard any output.
	if cancelled {
		return outputArray, err
	}
	endTime := time.Now().Unix()

	// Parse stdout regardless of the container's exit code, so a tool that
	// failed but still produced data can be classified downstream (WARNING).
	// A parse error must not clobber a non-nil exit error: keep the exit error.
	raw := stdout.Bytes()
	//fmt.Println(string(raw))		// XXX DEBUG
	if perr := json.Unmarshal(raw, &outputArray); perr != nil && err == nil {
		err = perr
	}
	// Inject a nil placeholder for any empty result (success OR error) so the
	// worker can seed the negative-result cache. Cancellation already returned.
	if len(outputArray) == 0 {
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
					if err == nil {
						err = errorArray[0]
					}
					fingerprint = parsed.Fingerprint	// still better than nothing
				}
			}
			fpiarr := make([]interface{}, len(fingerprint))
			for i, v := range fingerprint {
				fpiarr[i] = v
			}
			data["_fp"] = fpiarr
		}
		if existing, ok := data["_cmd"]; !ok {
			data["_cmd"] = shellquote.Join(parsed.Command...)
		} else if _, isString := existing.(string); !isString {
			log.Debugf("Plugin %s returned _cmd as %T, expected string; coercing", plugin.Name, existing)
			data["_cmd"] = coerceCmdString(existing)
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

// coerceCmdString normalizes a non-string _cmd (e.g. a plugin that emitted a
// token array instead of a command string) into the string shape the data
// model documents.
func coerceCmdString(value interface{}) string {
	if list, ok := value.([]interface{}); ok {
		parts := make([]string, 0, len(list))
		for _, item := range list {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			} else {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
		}
		return shellquote.Join(parts...)
	}
	return fmt.Sprintf("%v", value)
}
