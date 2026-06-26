package g3lib

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/joho/godotenv"

	"github.com/golismero/g3/src/g3model"
	log "github.com/golismero/g3/src/g3log"
)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Environment variable pointing to the data directory.
// Required for most commands.
const G3HOME = "G3HOME"

// Configuration directory name.
const G3CONFIG = "config"

// Plugins cache file name.
const G3PLUGINS = "g3plugins.json"

// Version is overwritten at link time by release builds via
// -ldflags "-X github.com/golismero/g3/src/g3lib.Version=...". The -X path must
// be the full module import path, not the short "g3lib" — the short form
// silently no-ops. Stays "dev" for local builds.
var Version = "dev"

// Re-export the g3model stuff.
type G3Data = g3model.G3Data
type StringSet = g3model.StringSet
type SyncStringSet = g3model.SyncStringSet
func IsValidData(data G3Data) (bool, error) {
	return data.IsValidData()
}
func NewSyncStringSet() *SyncStringSet {
	return g3model.NewSyncStringSet()
}
func BuildTargets(arguments []string) ([]G3Data, error) {
	return g3model.BuildTargets(arguments)
}
func GetBuiltInPipelines(compact bool) map[string]string {
	return g3model.GetBuiltInPipelines(compact)
}
func EmitShellCompletion(shell, cmdName string, w io.Writer) error {
	return g3model.EmitShellCompletion(shell, cmdName, w)
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Get the G3HOME directory.
func GetHomeDirectory() string {

	// Ideally we should have a G3HOME environment variable already present.
	g3home := os.Getenv(G3HOME)
	if g3home != "" {
		return g3home
	}

	// If the environment variable is missing, we'll have to get creative.
	// We can use the real location of the binary (resolving all symlinks).
	ex, err := os.Executable()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	if target, err := filepath.EvalSymlinks(ex); err != nil {
		ex = target
	}
	ex, err = filepath.Abs(ex)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	dir := filepath.Dir(ex)
	if bin := filepath.Base(dir); bin == "bin" {
		dir = filepath.Dir(dir)
	}

	// Save the calculated path into the environment.
	// This will make future calls quicker.
	os.Setenv(G3HOME, dir) //nolint:errcheck

	// Return the calculated path.
	return dir
}

// Load the .env file.
func LoadDotEnvFile() error {
	g3home := GetHomeDirectory()
	if g3home != "" {
		godotenv.Load(filepath.Join(g3home, ".env")) //nolint:errcheck
	}
	return godotenv.Load()
}

// Get the environment variables as a map.
// https://stackoverflow.com/a/29294251/426293
func GetEnvironmentMap() map[string]string {
	m := make(map[string]string)
	for _, e := range os.Environ() {
		if i := strings.Index(e, "="); i >= 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	return m
}

// GetSharedEnv returns the subset of environment variables whose names begin
// with the "G3_ENV_" prefix. These are the deployment-wide capability flags
// g3worker injects into every plugin container (e.g. G3_ENV_IPV6_SUPPORTED).
// Exposed read-only via the g3api /config/env endpoint.
func GetSharedEnv() map[string]string {
	shared := make(map[string]string)
	for name, value := range GetEnvironmentMap() {
		if strings.HasPrefix(name, "G3_ENV_") {
			shared[name] = value
		}
	}
	return shared
}

// resolveInstanceID computes the MQTT client ID for this g3scanner or g3worker
// process. Three modes, in precedence order:
//
//  1. Explicit: envKey (G3_SCANNER_ID / G3_WORKER_ID) is set → use verbatim.
//     Prefix and transient flag are not allowed alongside (would be ignored
//     silently; we fail loud instead so contradictory configs surface at startup).
//  2. Transient: G3_INSTANCE_TRANSIENT=true → fresh "[prefix]transient-<uuid>"
//     per restart. MQTT session won't persist across restarts; queued messages
//     for the prior session will be dropped by the broker.
//  3. Hostname-derived (default): "[prefix]<container-hostname>". Stable across
//     restarts of the same container; changes when the container is recreated.
//
// On error: caller should log and exit. The error message names the conflicting
// env vars and how to resolve.
func ResolveInstanceID(envKey string) (string, error) {
	explicitID := os.Getenv(envKey)
	prefix     := os.Getenv("G3_INSTANCE_PREFIX")
	transient  := strings.EqualFold(os.Getenv("G3_INSTANCE_TRANSIENT"), "true")

	if explicitID != "" {
		if prefix != "" {
			return "", fmt.Errorf(
				"%s=%q is set together with G3_INSTANCE_PREFIX=%q; "+
					"explicit IDs are used verbatim and would ignore the prefix. "+
					"Choose one: explicit ID for full control, or unset %s to let the prefix apply.",
				envKey, explicitID, prefix, envKey)
		}
		if transient {
			return "", fmt.Errorf(
				"%s=%q is set together with G3_INSTANCE_TRANSIENT=true; "+
					"explicit IDs cannot also be transient. "+
					"Choose one: explicit ID for a stable name, or unset %s for a random per-restart ID.",
				envKey, explicitID, envKey)
		}
		return explicitID, nil
	}

	if transient {
		return prefix + "transient-" + uuid.NewString(), nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	switch hostname {
	case "", "(none)", "localhost", "localhost.localdomain":
		return "", fmt.Errorf(
			"cannot derive instance ID: hostname is %q. "+
				"Set %s explicitly, set G3_INSTANCE_PREFIX to disambiguate, "+
				"or set G3_INSTANCE_TRANSIENT=true for a random per-restart ID",
			hostname, envKey)
	}
	return prefix + hostname, nil
}

// Read an array of G3Data objects from a file.
func LoadDataFromFile(filepath string) ([]G3Data, error) {
	var inputJson []G3Data
	var err error

	// Open the file.
	var fd *os.File
	if filepath == "-" {
		fd = os.Stdin
	} else {
		fd, err = os.Open(filepath)
		if err != nil {
			return inputJson, errors.New("Error reading file " + filepath + ": " + err.Error())
		}
		defer fd.Close()
	}

	// Parse the JSON data from the file.
	err = json.NewDecoder(bufio.NewReader(fd)).Decode(&inputJson)
	if err != nil {
		return inputJson, errors.New("Error parsing input JSON data from file " + filepath + ": " + err.Error())
	}

	// Do some minimal validation.
	for index, data := range inputJson {
		if ok, err := IsValidData(data); !ok {
			if err != nil {
				return inputJson, fmt.Errorf("malformed data received, file: %s, index %d: %s", filepath, index, err.Error())
			}
			return inputJson, fmt.Errorf("malformed data received, file: %s, index %d", filepath, index)
		}
	}

	// Return the input array.
	return inputJson, nil
}

// Write an array of G3Data objects into a file.
func SaveDataToFile(filepath string, outputArray []G3Data, beautify bool) error {

	// Save the combined output in JSON format.
	var jsonOutput []byte
	var err error
	if beautify {
		jsonOutput, err = json.MarshalIndent(outputArray, "", "  ")
	} else {
		jsonOutput, err = json.Marshal(outputArray)
	}
	if err != nil {
		return errors.New("error parsing output data: " + err.Error())
	}
	if beautify {
		jsonOutput = append(jsonOutput, []byte("\n")...)
	}

	// Save the output data where requested.
	if filepath == "-" {
		fmt.Print(string(jsonOutput))
	} else {
		err = os.WriteFile(filepath, jsonOutput, 0644)
		if err != nil {
			return errors.New("Error writing to file " + filepath + ": " + err.Error())
		}
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Miscellaneous helper functions.

// Remove duplicates from a string slice.
// https://stackoverflow.com/a/66751055/426293
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// Removes a string from a string slice.
// https://stackoverflow.com/a/34070691/426293
func RemoveStr(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

// Checks if a string exists in a string slice.
func ContainsStr(s []string, r string) bool {
	for _, v := range s {
		if v == r {
			return true
		}
	}
	return false
}

// Remove ANSI escapes from a string.
// https://github.com/acarl005/stripansi/blob/master/stripansi.go
var RE_ANSI = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))")
func StripAnsi(s string) string {
	return RE_ANSI.ReplaceAllString(s, "")
}

// Pretty print a JSON object. Ignores errors.
func PrettyPrintJSON(data interface{}) string {
	var jsonOutput []byte
	var err error
	jsonOutput, err = json.MarshalIndent(data, "", "  ")
	if err == nil {
		return string(jsonOutput)
	}
	return `{\n  "error": "Could not JSON encode the data!"\n}\n`
}

// Asks the user for confirmation.
// https://gist.github.com/r0l1/3dcbb0c8f6cfe9c66ab8008f55f8f28b
func AskForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [y/N]: ", s)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		response = strings.ToLower(strings.TrimSpace(response))
		switch response {
		case "y", "yes":
			return true
		case "", "n", "no":
			return false
		}
	}
}
