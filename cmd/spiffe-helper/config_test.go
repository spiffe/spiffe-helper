package main

import (
	"testing"
	"time"

	"github.com/spiffe/spiffe-helper/pkg/sidecar"
	"github.com/stretchr/testify/assert"
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
	expectedTimeOut := "10s"

	assert.Equal(t, expectedAgentAddress, c.AgentAddress)
	assert.Equal(t, expectedCmd, c.Cmd)
	assert.Equal(t, expectedCmdArgs, c.CmdArgs)
	assert.Equal(t, expectedCertDir, c.CertDir)
	assert.Equal(t, expectedRenewSignal, c.RenewSignal)
	assert.Equal(t, expectedSvidFileName, c.SvidFileName)
	assert.Equal(t, expectedKeyFileName, c.SvidKeyFileName)
	assert.Equal(t, expectedSvidBundleFileName, c.SvidBundleFileName)
	assert.Equal(t, expectedTimeOut, c.Timeout)
	assert.True(t, c.AddIntermediatesToBundle)
}

//Tests that when there is no defaultTimeout in the config, it uses
//the default defaultTimeout set in a constant in the spiffe_sidecar
func Test_getTimeout_default(t *testing.T) {
	config := &sidecar.Config{}

	expectedTimeout := defaultTimeout
	actualTimeout, err := GetTimeout(config)

	assert.NoError(t, err)
	if actualTimeout != expectedTimeout {
		t.Errorf("Expected defaultTimeout : %v, got %v", expectedTimeout, actualTimeout)
	}
}

//Tests that when there is a timeout set in the config, it's used that one
func Test_getTimeout_custom(t *testing.T) {
	config := &sidecar.Config{
		Timeout: "10s",
	}

	expectedTimeout := time.Second * 10
	actualTimeout, err := GetTimeout(config)

	assert.NoError(t, err)
	if actualTimeout != expectedTimeout {
		t.Errorf("Expected defaultTimeout : %v, got %v", expectedTimeout, actualTimeout)
	}
}

func Test_getTimeout_return_error_when_parsing_fails(t *testing.T) {
	config := &sidecar.Config{
		Timeout: "invalid",
	}

	actualTimeout, err := GetTimeout(config)

	assert.Empty(t, actualTimeout)
	assert.NotEmpty(t, err)
}
