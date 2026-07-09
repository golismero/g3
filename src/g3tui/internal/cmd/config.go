package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

const (
	EnvBaseURL      = "G3_API_BASEURL"
	EnvWSURL        = "G3_API_WSURL"
	EnvToken        = "G3_API_TOKEN"
	EnvPipelinesDir = "G3_PIPELINES_DIR"
	EnvLogLevel     = "G3_CMD_LOG_LEVEL"
)

// Config is the resolved runtime configuration after merging flags, env vars,
// .env, and built-in defaults. It does not contain the run-only behavior
// flags (NoWS, PollInterval, ReadOnly, Theme); those live on RunCmd and are
// applied directly by RunCmd.Run.
type Config struct {
	BaseURL      string
	WSURL        string
	Token        string
	PipelinesDir string
	LogLevel     string

	// *Source fields record provenance for doctor's resolved-config table.
	// Values: "flag", "env" (covers both real env vars and .env since we
	// cannot distinguish after godotenv.Load()), or "default".
	BaseURLSource      string
	WSURLSource        string
	TokenSource        string
	PipelinesDirSource string
	LogLevelSource     string
}

// loadConfig merges CLI flags, environment, and built-in defaults.
//
// requireServer == true means BaseURL, WSURL, and Token must all be set (by
// some level of the precedence chain); a missing one is a hard error. This
// is true for run and doctor; false for pipelines and completions.
func loadConfig(requireServer bool) (Config, error) {
	_ = godotenv.Load() // best-effort; missing .env is fine

	cfg := Config{}

	cfg.BaseURL, cfg.BaseURLSource = pick(CLI.Server, EnvBaseURL)
	cfg.WSURL, cfg.WSURLSource = pick(CLI.WS, EnvWSURL)
	cfg.PipelinesDir, cfg.PipelinesDirSource = pick(CLI.PipelinesDir, EnvPipelinesDir)
	cfg.LogLevel, cfg.LogLevelSource = pick(CLI.LogLevel, EnvLogLevel)

	// Token: --token-file always wins. If unset, fall back to env.
	if CLI.TokenFile != "" {
		b, err := os.ReadFile(CLI.TokenFile)
		if err != nil {
			return cfg, fmt.Errorf("--token-file: %w", err)
		}
		cfg.Token = strings.TrimSpace(string(b))
		cfg.TokenSource = "flag"
	} else if v := os.Getenv(EnvToken); v != "" {
		cfg.Token = v
		cfg.TokenSource = "env"
	} else {
		cfg.Token = ""
		cfg.TokenSource = "default"
	}

	if requireServer {
		var missing []string
		if cfg.BaseURL == "" {
			missing = append(missing, EnvBaseURL)
		}
		if cfg.WSURL == "" {
			missing = append(missing, EnvWSURL)
		}
		if cfg.Token == "" {
			missing = append(missing, EnvToken)
		}
		if len(missing) > 0 {
			return cfg, fmt.Errorf("missing required configuration: %s (set via flag, env var, or .env)", strings.Join(missing, ", "))
		}
	}

	return cfg, nil
}

// pick returns the flag value when non-empty, else the env-var value, along
// with a source label ("flag", "env", or "default").
func pick(flag, envName string) (string, string) {
	if flag != "" {
		return flag, "flag"
	}
	if v := os.Getenv(envName); v != "" {
		return v, "env"
	}
	return "", "default"
}
