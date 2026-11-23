//go:build integration

package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spiffe/spiffe-helper/test/integration/internal/dockercompose"
	"github.com/stretchr/testify/require"
)

func TestEnvironmentConfiguration(t *testing.T) {
	dockerCompose := dockercompose.New()
	dockerCompose.AddFile(t, "env/compose.yaml")
	dockerCompose.AddGlobalEnv(t, "GO_VERSION", readGoVersion(t))
	t.Cleanup(func() { dockerCompose.Cleanup(t) })

	baseEnv := map[string]string{
		"SPIFFE_HELPER_AGENT_ADDRESS":         "/tmp/test-agent.sock",
		"SPIFFE_HELPER_CERT_DIR":              "/tmp/certs",
		"SPIFFE_HELPER_SVID_FILE_NAME":        "svid.pem",
		"SPIFFE_HELPER_SVID_KEY_FILE_NAME":    "svid-key.pem",
		"SPIFFE_HELPER_SVID_BUNDLE_FILE_NAME": "bundle.pem",
	}

	tests := []struct {
		name        string
		env         map[string]string
		expectError string
	}{
		{
			name: "required values",
			env:  baseEnv,
		},
		{
			name: "boolean and file mode values",
			env: mergeEnv(baseEnv, map[string]string{
				"SPIFFE_HELPER_ADD_INTERMEDIATES_TO_BUNDLE": "true",
				"SPIFFE_HELPER_INCLUDE_FEDERATED_DOMAINS":   "false",
				"SPIFFE_HELPER_OMIT_EXPIRED":                "true",
				"SPIFFE_HELPER_CERT_FILE_MODE":              "0644",
				"SPIFFE_HELPER_KEY_FILE_MODE":               "0600",
			}),
		},
		{
			name: "health check values",
			env: mergeEnv(baseEnv, map[string]string{
				"SPIFFE_HELPER_HEALTH_LISTENER_ENABLED": "true",
				"SPIFFE_HELPER_HEALTH_BIND_PORT":        "8081",
				"SPIFFE_HELPER_HEALTH_LIVENESS_PATH":    "/live",
				"SPIFFE_HELPER_HEALTH_READINESS_PATH":   "/ready",
			}),
		},
		{
			name: "JWT SVID array",
			env: mergeEnv(baseEnv, map[string]string{
				"SPIFFE_HELPER_JWT_BUNDLE_FILE_NAME": "jwt-bundle.json",
				"SPIFFE_HELPER_JWT_SVIDS": `[{
					"jwt_audience":"audience-0",
					"jwt_svid_file_name":"file-0.token",
					"jwt_extra_audiences":["extra1","extra2"]
				}]`,
			}),
		},
		{
			name: "missing required values",
			env: map[string]string{
				"SPIFFE_HELPER_AGENT_ADDRESS": "/tmp/test-agent.sock",
			},
			expectError: "invalid configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dockerCompose.Run("spiffe-helper-env", tt.env, "--daemon-mode=false")
			output := result.Stdout + result.Stderr
			if tt.expectError != "" {
				require.Contains(t, output, tt.expectError)
				return
			}

			require.Contains(t, output, "Error starting spiffe-helper")
			require.NotContains(t, output, "invalid configuration")
		})
	}
}

func mergeEnv(base, overrides map[string]string) map[string]string {
	env := make(map[string]string, len(base)+len(overrides))
	for key, value := range base {
		env[key] = value
	}
	for key, value := range overrides {
		env[key] = value
	}
	return env
}

func readGoVersion(t *testing.T) string {
	t.Helper()

	goMod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	require.NoError(t, err)

	for _, line := range strings.Split(string(goMod), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "go" {
			return fields[1]
		}
	}

	require.FailNow(t, "go version not found in go.mod")
	return ""
}
