package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// Environment variable key for JWTSVIDs JSON array
	envJWTSVIDsKey = "SPIFFE_HLP_JWT_SVIDS"
	// Environment variable key for DaemonMode
	envDaemonModeKey = "SPIFFE_HLP_DAEMON_MODE"
)

// populateJWTSVIDsFromEnv parses SPIFFE_HLP_JWT_SVIDS as a YAML/JSON array.
// If SPIFFE_HLP_JWT_SVIDS is set, it replaces any existing JWTSVIDs from config file.
// Expected format:
//   SPIFFE_HLP_JWT_SVIDS='[{"jwt_audience":"aud","jwt_svid_file_name":"file.token","jwt_extra_audiences":["extra"]}]'
func populateJWTSVIDsFromEnv(config *Config) error {
	jwtSVIDsJSON := strings.TrimSpace(os.Getenv(envJWTSVIDsKey))
	if jwtSVIDsJSON == "" {
		return nil
	}

	var jwtSVIDs []JWTConfig
	if err := yaml.Unmarshal([]byte(jwtSVIDsJSON), &jwtSVIDs); err != nil {
		return fmt.Errorf("invalid value for %s: must be a YAML/JSON array of JWT SVID objects: %w", envJWTSVIDsKey, err)
	}

	config.JWTSVIDs = jwtSVIDs
	return nil
}

// populateDaemonModeFromEnv parses the DAEMON_MODE environment variable and sets the DaemonMode pointer.
// Supports boolean values: "true", "false", "1", "0", "t", "f", "TRUE", "FALSE", "yes", "no", "on", "off", etc.
// If the environment variable is not set, this function does nothing (preserves nil state).
// If the environment variable is set, it will override any value from config file.
func populateDaemonModeFromEnv(config *Config) error {
	daemonModeStr := os.Getenv(envDaemonModeKey)
	if daemonModeStr == "" {
		return nil // Not set, preserve nil state
	}

	daemonModeStr = strings.ToLower(strings.TrimSpace(daemonModeStr))
	var daemonMode bool

	switch daemonModeStr {
	case "true", "1", "t", "yes", "y", "on":
		daemonMode = true
	case "false", "0", "f", "no", "n", "off":
		daemonMode = false
	default:
		return fmt.Errorf("invalid value for %s: %s (must be true/false, 1/0, yes/no, on/off)", envDaemonModeKey, daemonModeStr)
	}

	config.DaemonMode = &daemonMode
	return nil
}
