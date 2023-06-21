package sidecar

import (
	"testing"

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
			expectError: "duplicated AgentAddress",
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
			expectError: "duplicated cmdArgs",
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
			expectError: "duplicated certDir",
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
			expectError: "duplicated SvidFileName",
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
			expectError: "duplicated SvidKeyFileName",
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
			expectError: "duplicated SvidBundleFileName",
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
			expectError: "duplicated RenewSignal",
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
			expectLogs: []string{GetWarning("agentAddress", "agent_address")},
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
			expectLogs: []string{GetWarning("cmdArgs", "cmd_args")},
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
			expectLogs: []string{GetWarning("certDir", "cert_dir")},
		},
		{
			name: "Using SvidFileNameDeprecated",
			config: &Config{
				AgentAddress:           "path",
				SvidFileNameDeprecated: "cert.pem",
				SvidKeyFileName:        "key.pem",
				SvidBundleFileName:     "bundle.pem",
			},
			expectLogs: []string{GetWarning("svidFileName", "svid_file_name")},
		},
		{
			name: "Using SvidKeyFileNameDeprecated",
			config: &Config{
				AgentAddress:              "path",
				SvidFileName:              "cert.pem",
				SvidKeyFileNameDeprecated: "key.pem",
				SvidBundleFileName:        "bundle.pem",
			},
			expectLogs: []string{GetWarning("svidKeyFileName", "svid_key_file_name")},
		},
		{
			name: "Using SvidBundleFileNameDeprecated",
			config: &Config{
				AgentAddress:                 "path",
				SvidFileName:                 "cert.pem",
				SvidKeyFileName:              "key.pem",
				SvidBundleFileNameDeprecated: "bundle.pem",
			},
			expectLogs: []string{GetWarning("svidBundleFileName", "svid_bundle_file_name")},
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
			expectLogs: []string{GetWarning("renewSignal", "renew_signal")},
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
