package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// Environment variable key for JWTSVIDs index list or count
	envJWTSVIDsKey = "SPIFFE_HLP_JWT_SVIDS"
	// Suffixes for indexed JWTSVIDs environment variables
	envJWTSVIDsAudienceSuffix       = "_AUDIENCE"
	envJWTSVIDsSVIDFileSuffix       = "_SVID_FILE_NAME"
	envJWTSVIDsExtraAudiencesSuffix = "_EXTRA_AUDIENCES"
	// Environment variable key for DaemonMode
	envDaemonModeKey = "SPIFFE_HLP_DAEMON_MODE"
)

// populateJWTSVIDsFromEnv parses indexed environment variables to populate JWTSVIDs array.
// Supports two formats:
// 1. SPIFFE_HLP_JWT_SVIDS="0,1,2" - comma-separated list of indices
// 2. SPIFFE_HLP_JWT_SVIDS="3" - count (will use indices 0, 1, 2)
// For each index i, reads:
//   - SPIFFE_HLP_JWT_SVIDS_i_AUDIENCE
//   - SPIFFE_HLP_JWT_SVIDS_i_EXTRA_AUDIENCES (comma-separated)
//   - SPIFFE_HLP_JWT_SVIDS_i_SVID_FILE_NAME
//
// If SPIFFE_HLP_JWT_SVIDS is not set or empty, this function does nothing.
// If indexed env vars are found, they will replace any existing JWTSVIDs from config file.
func populateJWTSVIDsFromEnv(config *Config) error {
	indicesStr := os.Getenv(envJWTSVIDsKey)
	if indicesStr == "" {
		return nil // No JWTSVIDs configured via indexed env vars
	}

	indicesStr = strings.TrimSpace(indicesStr)
	var indices []int

	// Check if it's a count (single number) or a list of indices
	if count, err := strconv.Atoi(indicesStr); err == nil {
		// It's a count - generate indices 0, 1, 2, ..., count-1
		if count < 0 {
			return fmt.Errorf("%s count must be non-negative, got: %d", envJWTSVIDsKey, count)
		}
		indices = make([]int, count)
		for i := range count {
			indices[i] = i
		}
	} else {
		// It's a comma-separated list of indices
		indexParts := strings.Split(indicesStr, ",")
		indices = make([]int, 0, len(indexParts))
		for _, part := range indexParts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("invalid index in %s: %s", envJWTSVIDsKey, part)
			}
			indices = append(indices, idx)
		}
	}

	if len(indices) == 0 {
		return nil // No valid indices found
	}

	// Build JWTSVIDs array from indexed environment variables
	jwtSVIDs := make([]JWTConfig, 0, len(indices))

	for _, idx := range indices {
		// Build environment variable names for this index
		audienceKey := fmt.Sprintf("%s_%d%s", envJWTSVIDsKey, idx, envJWTSVIDsAudienceSuffix)
		svidFileKey := fmt.Sprintf("%s_%d%s", envJWTSVIDsKey, idx, envJWTSVIDsSVIDFileSuffix)
		extraAudiencesKey := fmt.Sprintf("%s_%d%s", envJWTSVIDsKey, idx, envJWTSVIDsExtraAudiencesSuffix)

		audience := os.Getenv(audienceKey)
		svidFile := os.Getenv(svidFileKey)
		extraAudiencesStr := os.Getenv(extraAudiencesKey)

		// If no audience is set, skip this index (allows sparse arrays)
		if audience == "" {
			continue
		}

		// Parse extra audiences (comma-separated)
		var extraAudiences []string
		if extraAudiencesStr != "" {
			parts := strings.Split(extraAudiencesStr, ",")
			extraAudiences = make([]string, 0, len(parts))
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					extraAudiences = append(extraAudiences, part)
				}
			}
		}

		jwtSVIDs = append(jwtSVIDs, JWTConfig{
			JWTAudience:       audience,
			JWTSVIDFilename:   svidFile,
			JWTExtraAudiences: extraAudiences,
		})
	}

	// Replace existing JWTSVIDs with env-based ones if any were found
	if len(jwtSVIDs) > 0 {
		config.JWTSVIDs = jwtSVIDs
	}

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
