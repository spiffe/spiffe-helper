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
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.expectError != "" {
				require.Error(t, err, tt.expectError)
				return
			}

			require.NoError(t, err)
		})
	}
}
