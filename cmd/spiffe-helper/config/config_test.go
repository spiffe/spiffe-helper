package config

import (
	"flag"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	daemonModeFlagName = "daemon-mode"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig("testdata/helper.conf")

	assert.NoError(t, err)

	expectedAgentAddress := "/tmp/spire-agent/public/api.sock"
	expectedCmd := "hot-restarter.py"
	expectedCmdArgs := "start_envoy.sh"
	expectedCertDir := "certs"
	expectedRenewSignal := "SIGHUP"
	expectedSVIDFileName := "svid.pem"
	expectedKeyFileName := "svid_key.pem"
	expectedSVIDBundleFileName := "svid_bundle.pem"
	expectedJWTSVIDFileName := "jwt_svid.token"
	expectedJWTBundleFileName := "jwt_bundle.json"
	expectedJWTAudience := "your-audience"

	assert.Equal(t, expectedAgentAddress, c.AgentAddress)
	assert.Equal(t, expectedCmd, c.Cmd)
	assert.Equal(t, expectedCmdArgs, c.CmdArgs)
	assert.Equal(t, expectedCertDir, c.CertDir)
	assert.Equal(t, expectedRenewSignal, c.RenewSignal)
	assert.Equal(t, expectedSVIDFileName, c.SVIDFileName)
	assert.Equal(t, expectedKeyFileName, c.SVIDKeyFileName)
	assert.Equal(t, expectedSVIDBundleFileName, c.SVIDBundleFileName)
	assert.Equal(t, expectedJWTSVIDFileName, c.JWTSVIDs[0].JWTSVIDFilename)
	assert.Equal(t, expectedJWTBundleFileName, c.JWTBundleFilename)
	assert.Equal(t, expectedJWTAudience, c.JWTSVIDs[0].JWTAudience)
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
		expectLogs  []shortEntry
	}{
		{
			name: "no error",
			config: &Config{
				AgentAddress:       "path",
				SVIDFileName:       "cert.pem",
				SVIDKeyFileName:    "key.pem",
				SVIDBundleFileName: "bundle.pem",
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
				SVIDFileName: "cert.pem",
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
		// Duplicated field error:
		{
			name: "Both agent_address & agentAddress in use",
			config: &Config{
				AgentAddress:           "path",
				AgentAddressDeprecated: "path",
				SVIDFileName:           "cert.pem",
				SVIDKeyFileName:        "key.pem",
				SVIDBundleFileName:     "bundle.pem",
			},
			expectError: "use of agent_address and agentAddress found, use only agent_address",
		},
		{
			name: "Both cmd_args & cmdArgs in use",
			config: &Config{
				AgentAddress:       "path",
				CmdArgs:            "start_envoy.sh",
				CmdArgsDeprecated:  "start_envoy.sh",
				SVIDFileName:       "cert.pem",
				SVIDKeyFileName:    "key.pem",
				SVIDBundleFileName: "bundle.pem",
			},
			expectError: "use of cmd_args and cmdArgs found, use only cmd_args",
		},
		{
			name: "Both cert_dir & certDir in use",
			config: &Config{
				AgentAddress:       "path",
				CertDir:            "certs",
				CertDirDeprecated:  "certs",
				SVIDFileName:       "cert.pem",
				SVIDKeyFileName:    "key.pem",
				SVIDBundleFileName: "bundle.pem",
			},
			expectError: "use of cert_dir and certDir found, use only cert_dir",
		},
		{
			name: "Both svid_file_name & svidFileName in use",
			config: &Config{
				AgentAddress:           "path",
				SVIDFileName:           "cert.pem",
				SVIDFileNameDeprecated: "cert.pem",
				SVIDKeyFileName:        "key.pem",
				SVIDBundleFileName:     "bundle.pem",
			},
			expectError: "use of svid_file_name and svidFileName found, use only svid_file_name",
		},
		{
			name: "Both svid_key_file_name & svidKeyFileName in use",
			config: &Config{
				AgentAddress:              "path",
				SVIDFileName:              "cert.pem",
				SVIDKeyFileName:           "key.pem",
				SVIDKeyFileNameDeprecated: "key.pem",
				SVIDBundleFileName:        "bundle.pem",
			},
			expectError: "use of svid_key_file_name and svidKeyFileName found, use only svid_key_file_name",
		},
		{
			name: "Both svid_bundle_file_name & svidBundleFileName in use",
			config: &Config{
				AgentAddress:                 "path",
				SVIDFileName:                 "cert.pem",
				SVIDKeyFileName:              "key.pem",
				SVIDBundleFileName:           "bundle.pem",
				SVIDBundleFileNameDeprecated: "bundle.pem",
			},
			expectError: "use of svid_bundle_file_name and svidBundleFileName found, use only svid_bundle_file_name",
		},
		{
			name: "Both renew_signal & renewSignal in use",
			config: &Config{
				AgentAddress:          "path",
				SVIDFileName:          "cert.pem",
				SVIDKeyFileName:       "key.pem",
				SVIDBundleFileName:    "bundle.pem",
				RenewSignal:           "SIGHUP",
				RenewSignalDeprecated: "SIGHUP",
			},
			expectError: "use of renew_signal and renewSignal found, use only renew_signal",
		},
		// Deprecated field warning:
		{
			name: "Using AgentAddressDeprecated",
			config: &Config{
				AgentAddressDeprecated: "path",
				SVIDFileName:           "cert.pem",
				SVIDKeyFileName:        "key.pem",
				SVIDBundleFileName:     "bundle.pem",
			},
			expectLogs: []shortEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "agentAddress will be deprecated, should be used as agent_address",
				},
			},
		},
		{
			name: "Using CmdArgsDeprecated",
			config: &Config{
				AgentAddress:       "path",
				CmdArgsDeprecated:  "start_envoy.sh",
				SVIDFileName:       "cert.pem",
				SVIDKeyFileName:    "key.pem",
				SVIDBundleFileName: "bundle.pem",
			},
			expectLogs: []shortEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "cmdArgs will be deprecated, should be used as cmd_args",
				},
			},
		},
		{
			name: "Using CertDirDeprecated",
			config: &Config{
				AgentAddress:       "path",
				CertDirDeprecated:  "certs",
				SVIDFileName:       "cert.pem",
				SVIDKeyFileName:    "key.pem",
				SVIDBundleFileName: "bundle.pem",
			},
			expectLogs: []shortEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "certDir will be deprecated, should be used as cert_dir",
				},
			},
		},
		{
			name: "Using SVIDFileNameDeprecated",
			config: &Config{
				AgentAddress:           "path",
				SVIDFileNameDeprecated: "cert.pem",
				SVIDKeyFileName:        "key.pem",
				SVIDBundleFileName:     "bundle.pem",
			},
			expectLogs: []shortEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "svidFileName will be deprecated, should be used as svid_file_name",
				},
			},
		},
		{
			name: "Using SVIDKeyFileNameDeprecated",
			config: &Config{
				AgentAddress:              "path",
				SVIDFileName:              "cert.pem",
				SVIDKeyFileNameDeprecated: "key.pem",
				SVIDBundleFileName:        "bundle.pem",
			},
			expectLogs: []shortEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "svidKeyFileName will be deprecated, should be used as svid_key_file_name",
				},
			},
		},
		{
			name: "Using SVIDBundleFileNameDeprecated",
			config: &Config{
				AgentAddress:                 "path",
				SVIDFileName:                 "cert.pem",
				SVIDKeyFileName:              "key.pem",
				SVIDBundleFileNameDeprecated: "bundle.pem",
			},
			expectLogs: []shortEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "svidBundleFileName will be deprecated, should be used as svid_bundle_file_name",
				},
			},
		},
		{
			name: "Using RenewSignalDeprecated",
			config: &Config{
				AgentAddress:          "path",
				SVIDFileName:          "cert.pem",
				SVIDKeyFileName:       "key.pem",
				SVIDBundleFileName:    "bundle.pem",
				RenewSignalDeprecated: "SIGHUP",
			},
			expectLogs: []shortEntry{{
				Level:   logrus.WarnLevel,
				Message: "renewSignal will be deprecated, should be used as renew_signal",
			}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			err := tt.config.ValidateConfig(log)

			require.ElementsMatch(t, tt.expectLogs, getShortEntries(hook.AllEntries()))

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

			c, err := ParseConfig(configFile.Name())
			require.NoError(t, err)

			log, _ := test.NewNullLogger()
			err = c.ValidateConfig(log)
			require.EqualError(t, err, tt.expectError)
		})
	}
}

func TestDefaultAgentAddress(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		agentAddress         string
		envAgentAddress      string
		expectedAgentAddress string
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
			name:                 "Agent Address not set in config but set in env",
			envAgentAddress:      "MY_ENV_ADDRESS",
			expectedAgentAddress: "MY_ENV_ADDRESS",
		},
		{
			name:                 "Agent Address set in config and set in env",
			agentAddress:         "MY_ADDRESS",
			envAgentAddress:      "MY_ENV_ADDRESS",
			expectedAgentAddress: "MY_ADDRESS",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("SPIRE_AGENT_ADDRESS", tt.envAgentAddress)
			config := &Config{
				AgentAddress:       tt.agentAddress,
				SVIDFileName:       "cert.pem",
				SVIDKeyFileName:    "key.pem",
				SVIDBundleFileName: "bundle.pem",
			}
			log, _ := test.NewNullLogger()
			err := config.ValidateConfig(log)
			require.NoError(t, err)
			assert.Equal(t, config.AgentAddress, tt.expectedAgentAddress)
		})
	}
}

func TestNewSidecarConfig(t *testing.T) {
	config := &Config{
		AgentAddress:            "my-agent-address",
		Cmd:                     "my-cmd",
		CertDir:                 "my-cert-dir",
		SVIDKeyFileName:         "my-key",
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
	assert.Equal(t, config.SVIDKeyFileName, sidecarConfig.SVIDKeyFileName)
	assert.Equal(t, config.IncludeFederatedDomains, sidecarConfig.IncludeFederatedDomains)

	// Ensure JWT Config was populated correctly
	require.Equal(t, len(config.JWTSVIDs), len(sidecarConfig.JWTSVIDs))
	for i := 0; i < len(config.JWTSVIDs); i++ {
		assert.Equal(t, config.JWTSVIDs[i].JWTAudience, sidecarConfig.JWTSVIDs[i].JWTAudience)
		assert.Equal(t, config.JWTSVIDs[i].JWTSVIDFilename, sidecarConfig.JWTSVIDs[i].JWTSVIDFilename)
	}

	// Ensure empty fields were not populated
	assert.Equal(t, "", sidecarConfig.SVIDFileName)
	assert.Equal(t, "", sidecarConfig.RenewSignal)
}

func TestDaemonModeFlag(t *testing.T) {
	config := &Config{
		SVIDFileName:       "cert.pem",
		SVIDKeyFileName:    "key.pem",
		SVIDBundleFileName: "bundle.pem",
	}

	daemonModeFlag := flag.Bool(daemonModeFlagName, true, "Toggle running as a daemon to rotate X.509/JWT or just fetch and exit")
	flag.Parse()

	err := flag.Set(daemonModeFlagName, "false")
	require.NoError(t, err)

	config.ParseConfigFlagOverrides(*daemonModeFlag, daemonModeFlagName)
	require.NotNil(t, config.DaemonMode)
	assert.Equal(t, false, *config.DaemonMode)
}

type shortEntry struct {
	Level   logrus.Level
	Message string
}

func getShortEntries(entries []*logrus.Entry) []shortEntry {
	result := make([]shortEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, shortEntry{
			Level:   entry.Level,
			Message: entry.Message,
		})
	}
	return result
}
