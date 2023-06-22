package sidecar

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig("../../test/fixture/config/helper.conf")

	assert.NoError(t, err)

	expectedAgentAddress := "/tmp/agent.sock"
	expectedCmd := "hot-restarter.py"
	expectedCmdArgs := "start_envoy.sh"
	expectedCertDir := "certs"
	expectedRenewSignal := "SIGHUP"
	expectedSvidFileName := "svid.pem"
	expectedKeyFileName := "svid_key.pem"
	expectedSvidBundleFileName := "svid_bundle.pem"

	assert.Equal(t, expectedAgentAddress, c.AgentAddress)
	assert.Equal(t, expectedCmd, c.Cmd)
	assert.Equal(t, expectedCmdArgs, c.CmdArgs)
	assert.Equal(t, expectedCertDir, c.CertDir)
	assert.Equal(t, expectedRenewSignal, c.RenewSignal)
	assert.Equal(t, expectedSvidFileName, c.SvidFileName)
	assert.Equal(t, expectedKeyFileName, c.SvidKeyFileName)
	assert.Equal(t, expectedSvidBundleFileName, c.SvidBundleFileName)
	assert.True(t, c.AddIntermediatesToBundle)
}

func TestValidateConfig(t *testing.T) {
	for _, tt := range []struct {
		name        string
		config      *Config
		expectError string
		expectLogs  []string
	}{
		{
			name: "no error",
			config: &Config{
				AgentAddress:       "path",
				SvidFileName:       "cert.pem",
				SvidKeyFileName:    "key.pem",
				SvidBundleFileName: "bundle.pem",
			},
		},
		{
			name: "no address",
			config: &Config{
				SvidFileName:       "cert.pem",
				SvidKeyFileName:    "key.pem",
				SvidBundleFileName: "bundle.pem",
			},
			expectError: "agentAddress is required",
		},
		{
			name: "no SVID file",
			config: &Config{
				AgentAddress:       "path",
				SvidKeyFileName:    "key.pem",
				SvidBundleFileName: "bundle.pem",
			},
			expectError: "svidFileName is required",
		},
		{
			name: "no key file",
			config: &Config{
				AgentAddress:       "path",
				SvidFileName:       "cert.pem",
				SvidBundleFileName: "bundle.pem",
			},
			expectError: "svidKeyFileName is required",
		},
		{
			name: "no bundle file",
			config: &Config{
				AgentAddress:    "path",
				SvidFileName:    "cert.pem",
				SvidKeyFileName: "key.pem",
			},
			expectError: "svidBundleFileName is required",
		},

		// Duplicated field error:
		{
			name: "Both agent_address & agentAddress in use",
			config: &Config{
				AgentAddress:           "path",
				AgentAddressDeprecated: "path",
				SvidFileName:           "cert.pem",
				SvidKeyFileName:        "key.pem",
				SvidBundleFileName:     "bundle.pem",
			},
			expectError: "use of agent_address and AgentAddress found, use only agent_address",
		},
		{
			name: "Both cmd_args & cmdArgs in use",
			config: &Config{
				AgentAddress:       "path",
				CmdArgs:            "start_envoy.sh",
				CmdArgsDeprecated:  "start_envoy.sh",
				SvidFileName:       "cert.pem",
				SvidKeyFileName:    "key.pem",
				SvidBundleFileName: "bundle.pem",
			},
			expectError: "use of cmd_args and cmdArgs found, use only cmd_args",
		},
		{
			name: "Both cert_dir & certDir in use",
			config: &Config{
				AgentAddress:       "path",
				CertDir:            "certs",
				CertDirDeprecated:  "certs",
				SvidFileName:       "cert.pem",
				SvidKeyFileName:    "key.pem",
				SvidBundleFileName: "bundle.pem",
			},
			expectError: "use of cert_dir and certDir found, use only cert_dir",
		},
		{
			name: "Both svid_file_name & svidFileName in use",
			config: &Config{
				AgentAddress:           "path",
				SvidFileName:           "cert.pem",
				SvidFileNameDeprecated: "cert.pem",
				SvidKeyFileName:        "key.pem",
				SvidBundleFileName:     "bundle.pem",
			},
			expectError: "use of svid_file_name and svidFileName found, use only svid_file_name",
		},
		{
			name: "Both svid_key_file_name & svidKeyFileName in use",
			config: &Config{
				AgentAddress:              "path",
				SvidFileName:              "cert.pem",
				SvidKeyFileName:           "key.pem",
				SvidKeyFileNameDeprecated: "key.pem",
				SvidBundleFileName:        "bundle.pem",
			},
			expectError: "use of svid_key_file_name and svidKeyFileName found, use only svid_key_file_name",
		},
		{
			name: "Both svid_bundle_file_name & svidBundleFileName in use",
			config: &Config{
				AgentAddress:                 "path",
				SvidFileName:                 "cert.pem",
				SvidKeyFileName:              "key.pem",
				SvidBundleFileName:           "bundle.pem",
				SvidBundleFileNameDeprecated: "bundle.pem",
			},
			expectError: "use of svid_bundle_file_name and svidBundleFileName found, use only svid_bundle_file_name",
		},
		{
			name: "Both renew_signal & renewSignal in use",
			config: &Config{
				AgentAddress:          "path",
				SvidFileName:          "cert.pem",
				SvidKeyFileName:       "key.pem",
				SvidBundleFileName:    "bundle.pem",
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
				SvidFileName:           "cert.pem",
				SvidKeyFileName:        "key.pem",
				SvidBundleFileName:     "bundle.pem",
			},
			expectLogs: []string{"agentAddress will be deprecated, should be used as agent_address"},
		},
		{
			name: "Using CmdArgsDeprecated",
			config: &Config{
				AgentAddress:       "path",
				CmdArgsDeprecated:  "start_envoy.sh",
				SvidFileName:       "cert.pem",
				SvidKeyFileName:    "key.pem",
				SvidBundleFileName: "bundle.pem",
			},
			expectLogs: []string{"cmdArgs will be deprecated, should be used as cmd_args"},
		},
		{
			name: "Using CertDirDeprecated",
			config: &Config{
				AgentAddress:       "path",
				CertDirDeprecated:  "certs",
				SvidFileName:       "cert.pem",
				SvidKeyFileName:    "key.pem",
				SvidBundleFileName: "bundle.pem",
			},
			expectLogs: []string{"certDir will be deprecated, should be used as cert_dir"},
		},
		{
			name: "Using SvidFileNameDeprecated",
			config: &Config{
				AgentAddress:           "path",
				SvidFileNameDeprecated: "cert.pem",
				SvidKeyFileName:        "key.pem",
				SvidBundleFileName:     "bundle.pem",
			},
			expectLogs: []string{"svidFileName will be deprecated, should be used as svid_file_name"},
		},
		{
			name: "Using SvidKeyFileNameDeprecated",
			config: &Config{
				AgentAddress:              "path",
				SvidFileName:              "cert.pem",
				SvidKeyFileNameDeprecated: "key.pem",
				SvidBundleFileName:        "bundle.pem",
			},
			expectLogs: []string{"svidKeyFileName will be deprecated, should be used as svid_key_file_name"},
		},
		{
			name: "Using SvidBundleFileNameDeprecated",
			config: &Config{
				AgentAddress:                 "path",
				SvidFileName:                 "cert.pem",
				SvidKeyFileName:              "key.pem",
				SvidBundleFileNameDeprecated: "bundle.pem",
			},
			expectLogs: []string{"svidBundleFileName will be deprecated, should be used as svid_bundle_file_name"},
		},
		{
			name: "Using RenewSignalDeprecated",
			config: &Config{
				AgentAddress:          "path",
				SvidFileName:          "cert.pem",
				SvidKeyFileName:       "key.pem",
				SvidBundleFileName:    "bundle.pem",
				RenewSignalDeprecated: "SIGHUP",
			},
			expectLogs: []string{"renewSignal will be deprecated, should be used as renew_signal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log := &fakeLogger{}
			tt.config.Log = log

			err := ValidateConfig(tt.config)

			require.Equal(t, tt.expectLogs, log.Warnings)

			if tt.expectError != "" {
				require.Error(t, err, tt.expectError)
				return
			}

			require.NoError(t, err)
		})
	}
}

type fakeLogger struct {
	logger.Logger

	Warnings []string
}

func (f *fakeLogger) Warnf(format string, args ...interface{}) {
	f.Warnings = append(f.Warnings, format)
}
