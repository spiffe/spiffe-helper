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
	c, err := ParseConfigFile("testdata/helper.conf")

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

func TestDetectsUnknownConfig(t *testing.T) {
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

			c, err := ParseConfigFile(configFile.Name())
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
