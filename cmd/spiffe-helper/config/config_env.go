package config

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// Environment variable key for JWTSVIDs JSON array
	envJWTSVIDsKey = "SPIFFE_HLP_JWT_SVIDS"
)

// parseJWTSVIDsEnv parses SPIFFE_HLP_JWT_SVIDS as a YAML/JSON array.
// Expected format:
//
//	SPIFFE_HLP_JWT_SVIDS='[{"jwt_audience":"aud","jwt_svid_file_name":"file.token","jwt_extra_audiences":["extra"]}]'
func parseJWTSVIDsEnv(value string) (interface{}, error) {
	jwtSVIDsJSON := strings.TrimSpace(value)
	if jwtSVIDsJSON == "" {
		return []JWTConfig{}, nil
	}

	var jwtSVIDs []JWTConfig
	if err := yaml.Unmarshal([]byte(jwtSVIDsJSON), &jwtSVIDs); err != nil {
		return nil, fmt.Errorf("invalid value for %s: must be a YAML/JSON array of JWT SVID objects: %w", envJWTSVIDsKey, err)
	}

	return jwtSVIDs, nil
}

func parseFileModeEnv(value string) (interface{}, error) {
	mode, err := strconv.ParseInt(value, 0, 32)
	if err != nil {
		return nil, err
	}

	return FileMode(mode), nil
}
