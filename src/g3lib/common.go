package g3lib

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/joho/godotenv"

	log "github.com/golismero/g3/src/g3/log"
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Miscellaneous helper functions.

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
