package config

import (
	"flag"
	"os"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	daemonModeFlagName = "daemon-mode"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfigFile("testdata/helper.conf", "hcl")

	assert.NoError(t, err)
	assert.NoError(t, c.checkForUnknownConfig())

	expectedAgentAddress := "/tmp/spire-agent/public/api.sock"
	expectedCmd := "hot-restarter.py"
	expectedCmdArgs := "start_envoy.sh"
	expectedCertDir := "certs"
	expectedRenewSignal := "SIGHUP"
	expectedSVIDFilename := "svid.pem"
	expectedKeyFilename := "svid_key.pem"
	expectedSVIDBundleFilename := "svid_bundle.pem"
	expectedJWTSVIDFilename := "jwt_svid.token"
	expectedJWTBundleFilename := "jwt_bundle.json"
	expectedJWTAudience := "your-audience"
	expectedJWTExtraAudiences := []string{"your-extra-audience-1", "your-extra-audience-2"}

	assert.Equal(t, expectedAgentAddress, c.AgentAddress)
	assert.Equal(t, expectedCmd, c.Cmd)
	assert.Equal(t, expectedCmdArgs, c.CmdArgs)
	assert.Equal(t, expectedCertDir, c.CertDir)
	assert.Equal(t, expectedRenewSignal, c.RenewSignal)
	assert.Equal(t, expectedSVIDFilename, c.SVIDFilename)
	assert.Equal(t, expectedKeyFilename, c.SVIDKeyFilename)
	assert.Equal(t, expectedSVIDBundleFilename, c.SVIDBundleFilename)
	assert.Equal(t, expectedJWTSVIDFilename, c.JWTSVIDs[0].JWTSVIDFilename)
	assert.Equal(t, expectedJWTBundleFilename, c.JWTBundleFilename)
	assert.Equal(t, expectedJWTAudience, c.JWTSVIDs[0].JWTAudience)
	assert.Equal(t, expectedJWTExtraAudiences, c.JWTSVIDs[0].JWTExtraAudiences)
	assert.True(t, c.AddIntermediatesToBundle)
	assert.False(t, c.OmitExpired)
	assert.Equal(t, 444, c.CertFileMode)
	assert.Equal(t, 444, c.KeyFileMode)
	assert.Equal(t, 444, c.JWTBundleFileMode)
	assert.Equal(t, 444, c.JWTSVIDFileMode)
}

func TestValidateConfig(t *testing.T) {
	for _, tt := range []struct {
		name        string
		config      *Config
		expectError string
		skipWindows bool
	}{
		{
			name: "no error",
			config: &Config{
				AgentAddress:       "path",
				SVIDFilename:       "cert.pem",
				SVIDKeyFilename:    "key.pem",
				SVIDBundleFilename: "bundle.pem",
			},
		},
		{
			name: "no error",
			config: &Config{
				AgentAddress: "path",
				JWTSVIDs: []JWTConfig{{
					JWTSVIDFilename: "jwt.token",
					JWTAudience:     "your-audience",
				}},
				JWTBundleFilename: "bundle.json",
			},
		},
		{
			name: "no error",
			config: &Config{
				AgentAddress:      "path",
				JWTBundleFilename: "bundle.json",
			},
		},
		{
			name: "no error in oneshot mode",
			config: &Config{
				DaemonMode:         &[]bool{false}[0],
				AgentAddress:       "path",
				SVIDFilename:       "cert.pem",
				SVIDKeyFilename:    "key.pem",
				SVIDBundleFilename: "bundle.pem",
			},
		},
		{
			name: "no set specified",
			config: &Config{
				AgentAddress: "path",
			},
			expectError: "at least one of the sets ('svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name'), 'jwt_svids', or 'jwt_bundle_file_name' must be fully specified",
		},
		{
			name: "missing svid config",
			config: &Config{
				AgentAddress: "path",
				SVIDFilename: "cert.pem",
			},
			expectError: "all or none of 'svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name' must be specified",
		},
		{
			name: "missing jwt audience",
			config: &Config{
				AgentAddress: "path",
				JWTSVIDs: []JWTConfig{{
					JWTSVIDFilename: "jwt.token",
				}},
			},
			expectError: "'jwt_audience' is required in 'jwt_svids'",
		},
		{
			name: "missing jwt path",
			config: &Config{
				AgentAddress: "path",
				JWTSVIDs: []JWTConfig{{
					JWTAudience: "my-audience",
				}},
			},
			expectError: "'jwt_file_name' is required in 'jwt_svids'",
		},
		{
			name: "no error with pid_file_name and renew_signal",
			config: &Config{
				PIDFilename:        "pidfile",
				RenewSignal:        "SIGHUP",
				AgentAddress:       "path",
				SVIDFilename:       "cert.pem",
				SVIDKeyFilename:    "key.pem",
				SVIDBundleFilename: "bundle.pem",
			},
			skipWindows: true,
		},
		{
			// There's no test for 'cmd' and 'renew_signal' set in
			// daemon_mode here because they just log warnings
			name: "pid_file_name set in !daemon_mode",
			config: &Config{
				DaemonMode:  &[]bool{false}[0],
				PIDFilename: "pidfile",
			},
			expectError: "pid_file_name is set but daemon_mode is false. pid_file_name is only supported in daemon_mode",
			skipWindows: true,
		},
		{
			// renew_signal is required if setting a pid_file_name.
			// It is NOT required for 'cmd' since that would break
			// the mode where spiffe-helper calls a reloader
			// command when certs are renewed.
			name: "renew_signal required if pid_file_name set",
			config: &Config{
				PIDFilename: "pidfile",
				RenewSignal: "",
			},
			expectError: "must specify renew_signal when using pid_file_name",
			skipWindows: true,
		},
		{
			// A renew_signal is allowed without a pid_file_name
			// because it can also be sent to the 'cmd' process if
			// one is configured. We could raise a warning if
			// renew_signal is set but neither cmd or pid_file_name
			// are, but presently do not.
			name: "renew_signal allowed without pid_file_name",
			config: &Config{
				Cmd:                "echo",
				RenewSignal:        "SIGHUP",
				AgentAddress:       "path",
				SVIDFilename:       "cert.pem",
				SVIDKeyFilename:    "key.pem",
				SVIDBundleFilename: "bundle.pem",
			},
			skipWindows: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipWindows && os.Getenv("GOOS") == "windows" {
				t.Skip("skipping test on windows")
			}
			log, _ := test.NewNullLogger()
			err := tt.config.ValidateConfig(log)

			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestDetectsUnknownHCLConfig(t *testing.T) {
	tempDir := t.TempDir()
	for _, tt := range []struct {
		name        string
		config      string
		expectError string
	}{
		{
			name: "Unknown configuration at top level",
			config: `
				agent_address = "/tmp"
				foo = "bar"
				bar = "foo"
				`,
			expectError: "unknown top level key(s): bar,foo",
		},
		{
			name: "Unknown configuration in first jwt svid",
			config: `
				cmd = "echo"
				jwt_svids = [
						{
							jwt_audience="your-audience",
							jwt_svid_file_name="jwt_svid.token",
							foo = "bar", 
							bar = "foo"
						}
					    ]
				`,
			expectError: "unknown key(s) in jwt_svids[0]: bar,foo",
		},
		{
			name: "Unknown configuration in second jwt svid",
			config: `
				cmd = "echo"
				jwt_svids = [
						{
							jwt_audience = "your-audience-0",
							jwt_svid_file_name="jwt_svid-0.token",
						},
						{
							jwt_audience = "your-audience-1",
							jwt_svid_file_name = "jwt_svid-1.token",
							foo = "bar", 
							bar = "foo"
						}
					    ]
				`,
			expectError: "unknown key(s) in jwt_svids[1]: bar,foo",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			configFile, err := os.CreateTemp(tempDir, "spiffe-helper")
			require.NoError(t, err)

			_, err = configFile.WriteString(tt.config)
			require.NoError(t, err)

			c, err := ParseConfigFile(configFile.Name(), "hcl")
			require.NoError(t, err)

			log, _ := test.NewNullLogger()
			err = c.ValidateConfig(log)
			require.EqualError(t, err, tt.expectError)

			err = configFile.Close()
			require.NoError(t, err)
		})
	}
}

func TestDetectsUnknownJSONConfig(t *testing.T) {
	tempDir := t.TempDir()
	for _, tt := range []struct {
		name        string
		config      string
		expectError string
	}{
		{
			name: "Unknown configuration at top level",
			config: `{
				"agent_address": "/tmp",
				"foo": "bar",
				"bar": "foo"
			}`,
			expectError: "unknown top level key(s): bar,foo",
		},
		{
			name: "Unknown configuration in first jwt svid",
			config: `{
				"cmd": "echo",
				"jwt_svids": [
					{
						"jwt_audience": "your-audience",
						"jwt_svid_file_name": "jwt_svid.token",
						"foo": "bar",
						"bar": "foo"
					}
				]
			}`,
			expectError: "unknown key(s) in jwt_svids[0]: bar,foo",
		},
		{
			name: "Unknown configuration in second jwt svid",
			config: `{
				"cmd": "echo",
				"jwt_svids": [
					{
						"jwt_audience": "your-audience-0",
						"jwt_svid_file_name": "jwt_svid-0.token"
					},
					{
						"jwt_audience": "your-audience-1",
						"jwt_svid_file_name": "jwt_svid-1.token",
						"foo": "bar",
						"bar": "foo"
					}
				]
			}`,
			expectError: "unknown key(s) in jwt_svids[1]: bar,foo",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			configFile, err := os.CreateTemp(tempDir, "spiffe-helper-*.json")
			require.NoError(t, err)

			_, err = configFile.WriteString(tt.config)
			require.NoError(t, err)

			c, err := ParseConfigFile(configFile.Name(), "json")
			require.NoError(t, err)

			log, _ := test.NewNullLogger()
			err = c.ValidateConfig(log)
			require.EqualError(t, err, tt.expectError)

			err = configFile.Close()
			require.NoError(t, err)
		})
	}
}

func TestDetectsUnknownYAMLConfig(t *testing.T) {
	tempDir := t.TempDir()
	for _, tt := range []struct {
		name        string
		config      string
		expectError string
	}{
		{
			name: "Unknown configuration at top level",
			config: `agent_address: "/tmp"
foo: "bar"
bar: "foo"`,
			expectError: "unknown top level key(s): bar,foo",
		},
		{
			name: "Unknown configuration in first jwt svid",
			config: `cmd: "echo"
jwt_svids:
  - jwt_audience: "your-audience"
    jwt_svid_file_name: "jwt_svid.token"
    foo: "bar"
    bar: "foo"`,
			expectError: "unknown key(s) in jwt_svids[0]: bar,foo",
		},
		{
			name: "Unknown configuration in second jwt svid",
			config: `cmd: "echo"
jwt_svids:
  - jwt_audience: "your-audience-0"
    jwt_svid_file_name: "jwt_svid-0.token"
  - jwt_audience: "your-audience-1"
    jwt_svid_file_name: "jwt_svid-1.token"
    foo: "bar"
    bar: "foo"`,
			expectError: "unknown key(s) in jwt_svids[1]: bar,foo",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			configFile, err := os.CreateTemp(tempDir, "spiffe-helper-*.yaml")
			require.NoError(t, err)

			_, err = configFile.WriteString(tt.config)
			require.NoError(t, err)

			c, err := ParseConfigFile(configFile.Name(), "yaml")
			require.NoError(t, err)

			log, _ := test.NewNullLogger()
			err = c.ValidateConfig(log)
			require.EqualError(t, err, tt.expectError)

			err = configFile.Close()
			require.NoError(t, err)
		})
	}
}

func TestDefaultAgentAddress(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		agentAddress            string
		envSPIREAgentAddress    string
		envSPIFFEEndpointSocket string
		expectedAgentAddress    string
		expectError             string
	}{
		{
			name:                 "Agent Address not set in config or env",
			expectedAgentAddress: defaultAgentAddress,
		},
		{
			name:                 "Agent Address set in config but not in env",
			agentAddress:         "MY_ADDRESS",
			expectedAgentAddress: "MY_ADDRESS",
		},
		{
			name:                 "Agent Address not set in config but SPIRE_AGENT_ADDRESS is set in env",
			envSPIREAgentAddress: "MY_ENV_ADDRESS",
			expectedAgentAddress: "MY_ENV_ADDRESS",
		},
		{
			name:                    "Agent Address not set in config but SPIFFE_ENDPOINT_SOCKET is set in env",
			envSPIFFEEndpointSocket: "MY_ENV_ADDRESS",
			expectedAgentAddress:    "MY_ENV_ADDRESS",
		},
		{
			name:                    "Both SPIRE_AGENT_ADDRESS and SPIFFE_ENDPOINT_SOCKET are set in env",
			envSPIREAgentAddress:    "MY_SPIRE_AGENT_ADDRESS",
			envSPIFFEEndpointSocket: "MY_SPIFFE_ENDPOINT_SOCKET",
			expectError:             "both SPIRE_AGENT_ADDRESS and SPIFFE_ENDPOINT_SOCKET set. Use SPIFFE_ENDPOINT_SOCKET only. Support for SPIRE_AGENT_ADDRESS is deprecated and will be removed in 0.10.0",
		},
		{
			name:                    "Agent Address set in config and set in env",
			agentAddress:            "MY_ADDRESS",
			envSPIFFEEndpointSocket: "MY_ENV_ADDRESS",
			expectedAgentAddress:    "MY_ADDRESS",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("SPIRE_AGENT_ADDRESS", tt.envSPIREAgentAddress)
			os.Setenv("SPIFFE_ENDPOINT_SOCKET", tt.envSPIFFEEndpointSocket)

			config := &Config{
				AgentAddress:       tt.agentAddress,
				SVIDFilename:       "cert.pem",
				SVIDKeyFilename:    "key.pem",
				SVIDBundleFilename: "bundle.pem",
			}

			log, hook := test.NewNullLogger()
			err := config.ValidateConfig(log)
			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.expectedAgentAddress, config.AgentAddress)

			if tt.envSPIREAgentAddress != "" && tt.envSPIFFEEndpointSocket == "" {
				require.NotNil(t, hook.LastEntry())
				assert.Equal(t, "SPIRE_AGENT_ADDRESS is deprecated and will be removed in 0.10.0. Use SPIFFE_ENDPOINT_SOCKET instead.", hook.LastEntry().Message)
			}
		})
	}
}

func TestNewSidecarConfig(t *testing.T) {
	config := &Config{
		AgentAddress:            "my-agent-address",
		Cmd:                     "my-cmd",
		CertDir:                 "my-cert-dir",
		SVIDKeyFilename:         "my-key",
		IncludeFederatedDomains: true,
		OmitExpired:             true,
		JWTSVIDs: []JWTConfig{
			{
				JWTAudience:     "my-audience",
				JWTSVIDFilename: "my-jwt-filename",
			},
		},
	}

	sidecarConfig := NewSidecarConfig(config, nil)

	// Ensure fields were populated correctly
	assert.Equal(t, config.AgentAddress, sidecarConfig.AgentAddress)
	assert.Equal(t, config.Cmd, sidecarConfig.Cmd)
	assert.Equal(t, config.CertDir, sidecarConfig.CertDir)
	assert.Equal(t, config.SVIDKeyFilename, sidecarConfig.SVIDKeyFilename)
	assert.Equal(t, config.IncludeFederatedDomains, sidecarConfig.IncludeFederatedDomains)
	assert.Equal(t, config.OmitExpired, sidecarConfig.OmitExpired)

	// Ensure JWT Config was populated correctly
	require.Len(t, sidecarConfig.JWTSVIDs, len(config.JWTSVIDs))
	for i := range config.JWTSVIDs {
		assert.Equal(t, config.JWTSVIDs[i].JWTAudience, sidecarConfig.JWTSVIDs[i].JWTAudience)
		assert.Equal(t, config.JWTSVIDs[i].JWTSVIDFilename, sidecarConfig.JWTSVIDs[i].JWTSVIDFilename)
	}

	// Ensure empty fields were not populated
	assert.Empty(t, sidecarConfig.SVIDFilename)
	assert.Empty(t, sidecarConfig.RenewSignal)
}

func TestDaemonModeFlag(t *testing.T) {
	config := &Config{
		SVIDFilename:       "cert.pem",
		SVIDKeyFilename:    "key.pem",
		SVIDBundleFilename: "bundle.pem",
	}

	daemonModeFlag := flag.Bool(daemonModeFlagName, true, "Toggle running as a daemon to rotate X.509/JWT or just fetch and exit")
	flag.Parse()

	err := flag.Set(daemonModeFlagName, "false")
	require.NoError(t, err)

	config.ParseConfigFlagOverrides(*daemonModeFlag, daemonModeFlagName)
	require.NotNil(t, config.DaemonMode)
	assert.False(t, *config.DaemonMode)
}

func TestConfigFromEnvVarsOnly(t *testing.T) {
	for _, tt := range []struct {
		name           string
		envVars        map[string]string
		expectedConfig func(*Config)
		expectError    bool
		expectErrorMsg string
	}{
		{
			name: "Basic configuration from env vars",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":         "/tmp/test-agent.sock",
				"SPIFFE_HLP_SVID_FILE_NAME":        "test-svid.pem",
				"SPIFFE_HLP_SVID_KEY_FILE_NAME":    "test-key.pem",
				"SPIFFE_HLP_SVID_BUNDLE_FILE_NAME": "test-bundle.pem",
				"SPIFFE_HLP_CERT_DIR":              "test-certs",
				"SPIFFE_HLP_CMD":                   "test-cmd",
				"SPIFFE_HLP_CMD_ARGS":              "test-args",
			},
			expectedConfig: func(c *Config) {
				assert.Equal(t, "/tmp/test-agent.sock", c.AgentAddress)
				assert.Equal(t, "test-svid.pem", c.SVIDFilename)
				assert.Equal(t, "test-key.pem", c.SVIDKeyFilename)
				assert.Equal(t, "test-bundle.pem", c.SVIDBundleFilename)
				assert.Equal(t, "test-certs", c.CertDir)
				assert.Equal(t, "test-cmd", c.Cmd)
				assert.Equal(t, "test-args", c.CmdArgs)
			},
		},
		{
			name: "Boolean and integer fields from env vars",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":               "/tmp/test-agent.sock",
				"SPIFFE_HLP_SVID_FILE_NAME":              "test-svid.pem",
				"SPIFFE_HLP_SVID_KEY_FILE_NAME":          "test-key.pem",
				"SPIFFE_HLP_SVID_BUNDLE_FILE_NAME":       "test-bundle.pem",
				"SPIFFE_HLP_ADD_INTERMEDIATES_TO_BUNDLE": "true",
				"SPIFFE_HLP_OMIT_EXPIRED":                "true",
				"SPIFFE_HLP_CERT_FILE_MODE":              "0644",
				"SPIFFE_HLP_KEY_FILE_MODE":               "0600",
			},
			expectedConfig: func(c *Config) {
				assert.True(t, c.AddIntermediatesToBundle)
				assert.True(t, c.OmitExpired)
				assert.Equal(t, 0644, c.CertFileMode)
				assert.Equal(t, 0600, c.KeyFileMode)
			},
		},
		{
			name: "Nested HealthCheck struct from env vars",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":         "/tmp/test-agent.sock",
				"SPIFFE_HLP_SVID_FILE_NAME":        "test-svid.pem",
				"SPIFFE_HLP_SVID_KEY_FILE_NAME":    "test-key.pem",
				"SPIFFE_HLP_SVID_BUNDLE_FILE_NAME": "test-bundle.pem",
				// cleanenv reads nested field env tags directly (does not combine with parent)
				"SPIFFE_HLP_LISTENER_ENABLED": "true",
				"SPIFFE_HLP_BIND_PORT":        "9090",
				"SPIFFE_HLP_LIVENESS_PATH":    "/health",
				"SPIFFE_HLP_READINESS_PATH":   "/ready",
			},
			expectedConfig: func(c *Config) {
				assert.True(t, c.HealthCheck.ListenerEnabled)
				assert.Equal(t, 9090, c.HealthCheck.BindPort)
				assert.Equal(t, "/health", c.HealthCheck.LivenessPath)
				assert.Equal(t, "/ready", c.HealthCheck.ReadinessPath)
			},
		},
		{
			name: "JWT configuration with JWTBundleFilename from env vars",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":        "/tmp/test-agent.sock",
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME": "test-bundle.json",
			},
			expectedConfig: func(c *Config) {
				// Verify JWT-related fields can be configured via env vars
				assert.Equal(t, "/tmp/test-agent.sock", c.AgentAddress)
				assert.Equal(t, "test-bundle.json", c.JWTBundleFilename)
				// Note: JWTSVIDs (array of JWTConfig) cannot be set via env vars alone
				// due to cleanenv limitation with arrays of structs. Use a config file for JWTSVIDs.
				// JWTBundleFilename is sufficient for JWT validation when no JWTSVIDs are needed.
				assert.Empty(t, c.JWTSVIDs)
			},
		},
		{
			name: "Attempt to set JWTSVIDs nested fields via env vars (env-only mode)",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":        "/tmp/test-agent.sock",
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME": "test-bundle.json",
				// Attempt to set nested fields within JWTSVIDs array
				"SPIFFE_HLP_JWT_AUDIENCE":        "env-audience",
				"SPIFFE_HLP_JWT_SVID_FILE_NAME":  "env-file.token",
				"SPIFFE_HLP_JWT_EXTRA_AUDIENCES": "env-extra1,env-extra2",
			},
			expectedConfig: func(c *Config) {
				// Verify that nested fields in JWTSVIDs cannot be set via env vars when array is empty
				// cleanenv does not support arrays of structs via environment variables
				assert.Equal(t, "/tmp/test-agent.sock", c.AgentAddress)
				assert.Equal(t, "test-bundle.json", c.JWTBundleFilename)
				// JWTSVIDs array remains empty - env vars for nested fields are ignored
				assert.Empty(t, c.JWTSVIDs)
			},
		},
		{
			name: "JWTSVIDs from indexed env vars using count",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":               "/tmp/test-agent.sock",
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME":        "test-bundle.json",
				"SPIFFE_HLP_JWT_SVIDS":                   "2",
				"SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE":        "audience-0",
				"SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME":  "file-0.token",
				"SPIFFE_HLP_JWT_SVIDS_0_EXTRA_AUDIENCES": "extra0-1,extra0-2",
				"SPIFFE_HLP_JWT_SVIDS_1_AUDIENCE":        "audience-1",
				"SPIFFE_HLP_JWT_SVIDS_1_SVID_FILE_NAME":  "file-1.token",
				"SPIFFE_HLP_JWT_SVIDS_1_EXTRA_AUDIENCES": "extra1-1",
			},
			expectedConfig: func(c *Config) {
				assert.Equal(t, "/tmp/test-agent.sock", c.AgentAddress)
				assert.Equal(t, "test-bundle.json", c.JWTBundleFilename)
				require.Len(t, c.JWTSVIDs, 2)
				assert.Equal(t, "audience-0", c.JWTSVIDs[0].JWTAudience)
				assert.Equal(t, "file-0.token", c.JWTSVIDs[0].JWTSVIDFilename)
				assert.Equal(t, []string{"extra0-1", "extra0-2"}, c.JWTSVIDs[0].JWTExtraAudiences)
				assert.Equal(t, "audience-1", c.JWTSVIDs[1].JWTAudience)
				assert.Equal(t, "file-1.token", c.JWTSVIDs[1].JWTSVIDFilename)
				assert.Equal(t, []string{"extra1-1"}, c.JWTSVIDs[1].JWTExtraAudiences)
			},
		},
		{
			name: "JWTSVIDs from indexed env vars using index list",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":               "/tmp/test-agent.sock",
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME":        "test-bundle.json",
				"SPIFFE_HLP_JWT_SVIDS":                   "0,2,5",
				"SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE":        "audience-0",
				"SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME":  "file-0.token",
				"SPIFFE_HLP_JWT_SVIDS_2_AUDIENCE":        "audience-2",
				"SPIFFE_HLP_JWT_SVIDS_2_SVID_FILE_NAME":  "file-2.token",
				"SPIFFE_HLP_JWT_SVIDS_2_EXTRA_AUDIENCES": "extra2-1,extra2-2,extra2-3",
				"SPIFFE_HLP_JWT_SVIDS_5_AUDIENCE":        "audience-5",
				"SPIFFE_HLP_JWT_SVIDS_5_SVID_FILE_NAME":  "file-5.token",
			},
			expectedConfig: func(c *Config) {
				assert.Equal(t, "/tmp/test-agent.sock", c.AgentAddress)
				assert.Equal(t, "test-bundle.json", c.JWTBundleFilename)
				require.Len(t, c.JWTSVIDs, 3)
				assert.Equal(t, "audience-0", c.JWTSVIDs[0].JWTAudience)
				assert.Equal(t, "file-0.token", c.JWTSVIDs[0].JWTSVIDFilename)
				assert.Empty(t, c.JWTSVIDs[0].JWTExtraAudiences)
				assert.Equal(t, "audience-2", c.JWTSVIDs[1].JWTAudience)
				assert.Equal(t, "file-2.token", c.JWTSVIDs[1].JWTSVIDFilename)
				assert.Equal(t, []string{"extra2-1", "extra2-2", "extra2-3"}, c.JWTSVIDs[1].JWTExtraAudiences)
				assert.Equal(t, "audience-5", c.JWTSVIDs[2].JWTAudience)
				assert.Equal(t, "file-5.token", c.JWTSVIDs[2].JWTSVIDFilename)
				assert.Empty(t, c.JWTSVIDs[2].JWTExtraAudiences)
			},
		},
		{
			name: "JWTSVIDs from indexed env vars with sparse array (missing index)",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":              "/tmp/test-agent.sock",
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME":       "test-bundle.json",
				"SPIFFE_HLP_JWT_SVIDS":                  "0,1,2",
				"SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE":       "audience-0",
				"SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME": "file-0.token",
				// Index 1 is missing - should be skipped
				"SPIFFE_HLP_JWT_SVIDS_2_AUDIENCE":       "audience-2",
				"SPIFFE_HLP_JWT_SVIDS_2_SVID_FILE_NAME": "file-2.token",
			},
			expectedConfig: func(c *Config) {
				assert.Equal(t, "/tmp/test-agent.sock", c.AgentAddress)
				assert.Equal(t, "test-bundle.json", c.JWTBundleFilename)
				// Only indices 0 and 2 should be present (1 is skipped because no AUDIENCE)
				require.Len(t, c.JWTSVIDs, 2)
				assert.Equal(t, "audience-0", c.JWTSVIDs[0].JWTAudience)
				assert.Equal(t, "file-0.token", c.JWTSVIDs[0].JWTSVIDFilename)
				assert.Equal(t, "audience-2", c.JWTSVIDs[1].JWTAudience)
				assert.Equal(t, "file-2.token", c.JWTSVIDs[1].JWTSVIDFilename)
			},
		},
		{
			name: "DaemonMode from env vars (true)",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":         "/tmp/test-agent.sock",
				"SPIFFE_HLP_SVID_FILE_NAME":        "test-svid.pem",
				"SPIFFE_HLP_SVID_KEY_FILE_NAME":    "test-key.pem",
				"SPIFFE_HLP_SVID_BUNDLE_FILE_NAME": "test-bundle.pem",
				"SPIFFE_HLP_DAEMON_MODE":           "true",
			},
			expectedConfig: func(c *Config) {
				require.NotNil(t, c.DaemonMode)
				assert.True(t, *c.DaemonMode)
			},
		},
		{
			name: "DaemonMode from env vars (false)",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":         "/tmp/test-agent.sock",
				"SPIFFE_HLP_SVID_FILE_NAME":        "test-svid.pem",
				"SPIFFE_HLP_SVID_KEY_FILE_NAME":    "test-key.pem",
				"SPIFFE_HLP_SVID_BUNDLE_FILE_NAME": "test-bundle.pem",
				"SPIFFE_HLP_DAEMON_MODE":           "false",
			},
			expectedConfig: func(c *Config) {
				require.NotNil(t, c.DaemonMode)
				assert.False(t, *c.DaemonMode)
			},
		},
		{
			name: "DaemonMode from env vars (alternative formats)",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS":         "/tmp/test-agent.sock",
				"SPIFFE_HLP_SVID_FILE_NAME":        "test-svid.pem",
				"SPIFFE_HLP_SVID_KEY_FILE_NAME":    "test-key.pem",
				"SPIFFE_HLP_SVID_BUNDLE_FILE_NAME": "test-bundle.pem",
				"SPIFFE_HLP_DAEMON_MODE":           "1",
			},
			expectedConfig: func(c *Config) {
				require.NotNil(t, c.DaemonMode)
				assert.True(t, *c.DaemonMode)
			},
		},
		{
			name: "Missing required fields should fail validation",
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS": "/tmp/test-agent.sock",
				// Missing SVID files - validation should fail
			},
			expectedConfig: func(c *Config) {
				// Config should load successfully, but validation will fail
				assert.Equal(t, "/tmp/test-agent.sock", c.AgentAddress)
			},
			expectError:    true,
			expectErrorMsg: "at least one of the sets",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				t.Cleanup(func() {
					os.Unsetenv(key)
				})
			}

			// Load config from env vars only
			config, err := ProcessConfigFileAndEnv("")
			require.NoError(t, err)
			require.NotNil(t, config)

			// Verify expected values
			if tt.expectedConfig != nil {
				tt.expectedConfig(config)
			}

			// Validate the config
			log, _ := test.NewNullLogger()
			err = config.ValidateConfig(log)
			if tt.expectError {
				require.Error(t, err)
				if tt.expectErrorMsg != "" {
					assert.Contains(t, err.Error(), tt.expectErrorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigFileWithEnvOverrides(t *testing.T) {
	tempDir := t.TempDir()
	for _, tt := range []struct {
		name           string
		configFile     string
		configFormat   string
		envVars        map[string]string
		expectedConfig func(*Config)
		expectError    bool
		expectErrorMsg string
	}{
		{
			name:         "JSON config file with string field override",
			configFormat: "json",
			configFile: `{
				"agent_address": "/tmp/file-agent.sock",
				"svid_file_name": "file-svid.pem",
				"svid_key_file_name": "file-key.pem",
				"svid_bundle_file_name": "file-bundle.pem",
				"cmd": "file-cmd",
				"cert_dir": "file-certs"
			}`,
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS": "/tmp/env-agent.sock",
				"SPIFFE_HLP_CMD":           "env-cmd",
			},
			expectedConfig: func(c *Config) {
				// Env vars should override file values
				assert.Equal(t, "/tmp/env-agent.sock", c.AgentAddress)
				assert.Equal(t, "env-cmd", c.Cmd)
				// Non-overridden values should come from file
				assert.Equal(t, "file-svid.pem", c.SVIDFilename)
				assert.Equal(t, "file-key.pem", c.SVIDKeyFilename)
				assert.Equal(t, "file-bundle.pem", c.SVIDBundleFilename)
				assert.Equal(t, "file-certs", c.CertDir)
			},
		},
		{
			name:         "YAML config file with boolean and integer overrides",
			configFormat: "yaml",
			configFile: `agent_address: "/tmp/file-agent.sock"
svid_file_name: "file-svid.pem"
svid_key_file_name: "file-key.pem"
svid_bundle_file_name: "file-bundle.pem"
add_intermediates_to_bundle: false
omit_expired: false
cert_file_mode: 0644
key_file_mode: 0600`,
			envVars: map[string]string{
				"SPIFFE_HLP_ADD_INTERMEDIATES_TO_BUNDLE": "true",
				"SPIFFE_HLP_CERT_FILE_MODE":              "0755",
			},
			expectedConfig: func(c *Config) {
				// Env vars should override file values
				assert.True(t, c.AddIntermediatesToBundle)
				assert.Equal(t, 0755, c.CertFileMode)
				// Non-overridden values should come from file
				assert.False(t, c.OmitExpired)
				assert.Equal(t, 0600, c.KeyFileMode)
			},
		},
		{
			name:         "JSON config file with nested HealthCheck override",
			configFormat: "json",
			configFile: `{
				"agent_address": "/tmp/file-agent.sock",
				"svid_file_name": "file-svid.pem",
				"svid_key_file_name": "file-key.pem",
				"svid_bundle_file_name": "file-bundle.pem",
				"health_checks": {
					"listener_enabled": false,
					"bind_port": 8080,
					"liveness_path": "/file-live",
					"readiness_path": "/file-ready"
				}
			}`,
			envVars: map[string]string{
				// cleanenv reads nested field env tags directly (does not combine with parent)
				"SPIFFE_HLP_LISTENER_ENABLED": "true",
				"SPIFFE_HLP_BIND_PORT":        "9090",
			},
			expectedConfig: func(c *Config) {
				// Env vars should override file values
				assert.True(t, c.HealthCheck.ListenerEnabled)
				assert.Equal(t, 9090, c.HealthCheck.BindPort)
				// Non-overridden values should come from file
				assert.Equal(t, "/file-live", c.HealthCheck.LivenessPath)
				assert.Equal(t, "/file-ready", c.HealthCheck.ReadinessPath)
			},
		},
		{
			name:         "YAML config file with multiple overrides",
			configFormat: "yaml",
			configFile: `agent_address: "/tmp/file-agent.sock"
svid_file_name: "file-svid.pem"
svid_key_file_name: "file-key.pem"
svid_bundle_file_name: "file-bundle.pem"
cmd: "file-cmd"
cert_dir: "file-certs"
renew_signal: "SIGUSR1"`,
			envVars: map[string]string{
				"SPIFFE_HLP_AGENT_ADDRESS": "/tmp/env-agent.sock",
				"SPIFFE_HLP_CMD":           "env-cmd",
				"SPIFFE_HLP_CERT_DIR":      "env-certs",
			},
			expectedConfig: func(c *Config) {
				// All env vars should override file values
				assert.Equal(t, "/tmp/env-agent.sock", c.AgentAddress)
				assert.Equal(t, "env-cmd", c.Cmd)
				assert.Equal(t, "env-certs", c.CertDir)
				// Non-overridden value should come from file
				assert.Equal(t, "SIGUSR1", c.RenewSignal)
			},
		},
		{
			name:         "JSON config file with JWTSVIDs and JWTExtraAudiences",
			configFormat: "json",
			configFile: `{
				"agent_address": "/tmp/file-agent.sock",
				"jwt_bundle_file_name": "file-bundle.json",
				"jwt_svids": [
					{
						"jwt_audience": "file-audience",
						"jwt_svid_file_name": "file-jwt.token",
						"jwt_extra_audiences": ["file-extra1", "file-extra2"]
					}
				]
			}`,
			envVars: map[string]string{
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME": "env-bundle.json",
			},
			expectedConfig: func(c *Config) {
				// JWTBundleFilename should be overridden by env var
				assert.Equal(t, "env-bundle.json", c.JWTBundleFilename)
				// JWTSVIDs should come from file (arrays of structs can't be overridden via env vars)
				require.Len(t, c.JWTSVIDs, 1)
				assert.Equal(t, "file-audience", c.JWTSVIDs[0].JWTAudience)
				assert.Equal(t, "file-jwt.token", c.JWTSVIDs[0].JWTSVIDFilename)
				assert.Equal(t, []string{"file-extra1", "file-extra2"}, c.JWTSVIDs[0].JWTExtraAudiences)
			},
		},
		{
			name:         "Attempt to override JWTSVIDs nested fields via env vars (file with override)",
			configFormat: "json",
			configFile: `{
				"agent_address": "/tmp/file-agent.sock",
				"jwt_bundle_file_name": "file-bundle.json",
				"jwt_svids": [
					{
						"jwt_audience": "file-audience",
						"jwt_svid_file_name": "file-jwt.token",
						"jwt_extra_audiences": ["file-extra1", "file-extra2"]
					}
				]
			}`,
			envVars: map[string]string{
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME": "env-bundle.json",
				// Attempt to override nested fields within JWTSVIDs array
				"SPIFFE_HLP_JWT_AUDIENCE":        "env-audience",
				"SPIFFE_HLP_JWT_SVID_FILE_NAME":  "env-file.token",
				"SPIFFE_HLP_JWT_EXTRA_AUDIENCES": "env-extra1,env-extra2",
			},
			expectedConfig: func(c *Config) {
				// JWTBundleFilename should be overridden by env var
				assert.Equal(t, "env-bundle.json", c.JWTBundleFilename)
				// JWTSVIDs nested fields cannot be overridden via env vars
				// cleanenv does not support overriding individual fields within array elements
				require.Len(t, c.JWTSVIDs, 1)
				// Values should remain from file, not from env vars
				assert.Equal(t, "file-audience", c.JWTSVIDs[0].JWTAudience)
				assert.Equal(t, "file-jwt.token", c.JWTSVIDs[0].JWTSVIDFilename)
				assert.Equal(t, []string{"file-extra1", "file-extra2"}, c.JWTSVIDs[0].JWTExtraAudiences)
			},
		},
		{
			name:         "YAML config file with multiple JWTSVIDs and JWTExtraAudiences",
			configFormat: "yaml",
			configFile: `agent_address: "/tmp/file-agent.sock"
jwt_bundle_file_name: "file-bundle.json"
jwt_svids:
  - jwt_audience: "file-audience-1"
    jwt_svid_file_name: "file-jwt-1.token"
    jwt_extra_audiences: ["file-extra1-1", "file-extra1-2"]
  - jwt_audience: "file-audience-2"
    jwt_svid_file_name: "file-jwt-2.token"
    jwt_extra_audiences: ["file-extra2-1"]`,
			envVars: map[string]string{},
			expectedConfig: func(c *Config) {
				// Verify JWTSVIDs are loaded correctly from file
				require.Len(t, c.JWTSVIDs, 2)
				assert.Equal(t, "file-audience-1", c.JWTSVIDs[0].JWTAudience)
				assert.Equal(t, "file-jwt-1.token", c.JWTSVIDs[0].JWTSVIDFilename)
				assert.Equal(t, []string{"file-extra1-1", "file-extra1-2"}, c.JWTSVIDs[0].JWTExtraAudiences)
				assert.Equal(t, "file-audience-2", c.JWTSVIDs[1].JWTAudience)
				assert.Equal(t, "file-jwt-2.token", c.JWTSVIDs[1].JWTSVIDFilename)
				assert.Equal(t, []string{"file-extra2-1"}, c.JWTSVIDs[1].JWTExtraAudiences)
			},
		},
		{
			name:         "Attempt to override JWTExtraAudiences in YAML JWTSVIDs via env vars",
			configFormat: "yaml",
			configFile: `agent_address: "/tmp/file-agent.sock"
jwt_bundle_file_name: "file-bundle.json"
jwt_svids:
  - jwt_audience: "file-audience"
    jwt_svid_file_name: "file-jwt.token"
    jwt_extra_audiences: ["file-extra1", "file-extra2"]`,
			envVars: map[string]string{
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME": "env-bundle.json",
				// Attempt to override JWTExtraAudiences within JWTSVIDs array
				"SPIFFE_HLP_JWT_EXTRA_AUDIENCES": "env-extra1,env-extra2,env-extra3",
			},
			expectedConfig: func(c *Config) {
				// JWTBundleFilename should be overridden by env var
				assert.Equal(t, "env-bundle.json", c.JWTBundleFilename)
				// JWTExtraAudiences cannot be overridden via env vars when it's nested in an array element
				// cleanenv does not support overriding individual fields within array elements
				require.Len(t, c.JWTSVIDs, 1)
				assert.Equal(t, "file-audience", c.JWTSVIDs[0].JWTAudience)
				assert.Equal(t, "file-jwt.token", c.JWTSVIDs[0].JWTSVIDFilename)
				// Values should remain from file, not from env vars
				assert.Equal(t, []string{"file-extra1", "file-extra2"}, c.JWTSVIDs[0].JWTExtraAudiences)
			},
		},
		{
			name:         "Override file-based JWTSVIDs with indexed env vars",
			configFormat: "json",
			configFile: `{
				"agent_address": "/tmp/file-agent.sock",
				"jwt_bundle_file_name": "file-bundle.json",
				"jwt_svids": [
					{
						"jwt_audience": "file-audience",
						"jwt_svid_file_name": "file-jwt.token",
						"jwt_extra_audiences": ["file-extra1", "file-extra2"]
					}
				]
			}`,
			envVars: map[string]string{
				"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME":        "env-bundle.json",
				"SPIFFE_HLP_JWT_SVIDS":                   "2",
				"SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE":        "env-audience-0",
				"SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME":  "env-file-0.token",
				"SPIFFE_HLP_JWT_SVIDS_0_EXTRA_AUDIENCES": "env-extra0-1,env-extra0-2",
				"SPIFFE_HLP_JWT_SVIDS_1_AUDIENCE":        "env-audience-1",
				"SPIFFE_HLP_JWT_SVIDS_1_SVID_FILE_NAME":  "env-file-1.token",
				"SPIFFE_HLP_JWT_SVIDS_1_EXTRA_AUDIENCES": "env-extra1-1",
			},
			expectedConfig: func(c *Config) {
				// JWTBundleFilename should be overridden by env var
				assert.Equal(t, "env-bundle.json", c.JWTBundleFilename)
				// JWTSVIDs from indexed env vars should completely replace file-based JWTSVIDs
				require.Len(t, c.JWTSVIDs, 2)
				assert.Equal(t, "env-audience-0", c.JWTSVIDs[0].JWTAudience)
				assert.Equal(t, "env-file-0.token", c.JWTSVIDs[0].JWTSVIDFilename)
				assert.Equal(t, []string{"env-extra0-1", "env-extra0-2"}, c.JWTSVIDs[0].JWTExtraAudiences)
				assert.Equal(t, "env-audience-1", c.JWTSVIDs[1].JWTAudience)
				assert.Equal(t, "env-file-1.token", c.JWTSVIDs[1].JWTSVIDFilename)
				assert.Equal(t, []string{"env-extra1-1"}, c.JWTSVIDs[1].JWTExtraAudiences)
			},
		},
		{
			name:         "JSON config file with DaemonMode override via env var",
			configFormat: "json",
			configFile: `{
				"agent_address": "/tmp/file-agent.sock",
				"svid_file_name": "file-svid.pem",
				"svid_key_file_name": "file-key.pem",
				"svid_bundle_file_name": "file-bundle.pem",
				"daemon_mode": true
			}`,
			envVars: map[string]string{
				"SPIFFE_HLP_DAEMON_MODE": "false",
			},
			expectedConfig: func(c *Config) {
				// Env var should override file value
				require.NotNil(t, c.DaemonMode)
				assert.False(t, *c.DaemonMode)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			var fileExt string
			if tt.configFormat == "json" {
				fileExt = ".json"
			} else {
				fileExt = ".yaml"
			}
			configFile, err := os.CreateTemp(tempDir, "spiffe-helper-*"+fileExt)
			require.NoError(t, err)

			_, err = configFile.WriteString(tt.configFile)
			require.NoError(t, err)
			err = configFile.Close()
			require.NoError(t, err)

			// Set environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				t.Cleanup(func() {
					os.Unsetenv(key)
				})
			}

			// Load config from file (env vars will override)
			config, err := ProcessConfigFileAndEnv(configFile.Name())
			if tt.expectError {
				require.Error(t, err)
				if tt.expectErrorMsg != "" {
					assert.Contains(t, err.Error(), tt.expectErrorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, config)

			// Verify expected values
			if tt.expectedConfig != nil {
				tt.expectedConfig(config)
			}

			// Validate the config
			log, _ := test.NewNullLogger()
			err = config.ValidateConfig(log)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
