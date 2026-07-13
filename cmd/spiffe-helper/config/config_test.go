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
	testAgentAddress   = "path"
	testCertFilename   = "cert.pem"
	testKeyFilename    = "key.pem"
	testBundleFilename = "bundle.pem"
	testPIDFilename    = "pidfile"
	testRenewSignal    = "SIGHUP"
	testCmd            = "echo"
	configAgentAddress = "MY_ADDRESS"
	envAgentAddress    = "MY_ENV_ADDRESS"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfigFile("testdata/helper.conf")

	assert.NoError(t, err)
	assert.NoError(t, c.checkForUnknownConfig())

	expectedAgentAddress := "/tmp/spire-agent/public/api.sock"
	expectedCmd := "hot-restarter.py"
	expectedCmdArgs := "start_envoy.sh"
	expectedCertDir := "certs"
	expectedRenewSignal := testRenewSignal
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

func TestParseLifecycleConfig(t *testing.T) {
	tempDir := t.TempDir()
	configFile, err := os.CreateTemp(tempDir, "spiffe-helper")
	require.NoError(t, err)

	_, err = configFile.WriteString(`
		agent_address = "/tmp/spire-agent/public/api.sock"
		cert_dir = "certs"
		svid_file_name = "svid.pem"
		svid_key_file_name = "svid_key.pem"
		svid_bundle_file_name = "svid_bundle.pem"

		start {
			cmd = "envoy"
			args = "-c envoy.yaml"
		}

		reload {
			cmd = "mysql"
			args = "-e \"ALTER INSTANCE RELOAD TLS;\""
			signal = "SIGHUP"
			pid_file_name = "mysql.pid"
		}
	`)
	require.NoError(t, err)
	require.NoError(t, configFile.Close())

	c, err := ParseConfigFile(configFile.Name())
	require.NoError(t, err)

	log, _ := test.NewNullLogger()
	require.NoError(t, c.ValidateConfig(log))

	assert.Equal(t, "envoy", c.Start.Cmd)
	assert.Equal(t, "-c envoy.yaml", c.Start.Args)
	assert.Equal(t, "mysql", c.Reload.Cmd)
	assert.Equal(t, "-e \"ALTER INSTANCE RELOAD TLS;\"", c.Reload.Args)
	assert.Equal(t, "SIGHUP", c.Reload.Signal)
	assert.Equal(t, "mysql.pid", c.Reload.PIDFilename)
}

func TestValidateConfig(t *testing.T) {
	for _, tt := range []struct {
		name        string
		config      *Config
		expectError string
		skipWindows bool
	}{
		{
			name: "valid x509 config",
			config: &Config{
				AgentAddress:       testAgentAddress,
				SVIDFilename:       testCertFilename,
				SVIDKeyFilename:    testKeyFilename,
				SVIDBundleFilename: testBundleFilename,
			},
		},
		{
			name: "valid jwt svid config",
			config: &Config{
				AgentAddress: testAgentAddress,
				JWTSVIDs: []JWTConfig{{
					JWTSVIDFilename: "jwt.token",
					JWTAudience:     "your-audience",
				}},
				JWTBundleFilename: "bundle.json",
			},
		},
		{
			name: "valid jwt bundle config",
			config: &Config{
				AgentAddress:      testAgentAddress,
				JWTBundleFilename: "bundle.json",
			},
		},
		{
			name: "no error in oneshot mode",
			config: &Config{
				DaemonMode:         &[]bool{false}[0],
				AgentAddress:       testAgentAddress,
				SVIDFilename:       testCertFilename,
				SVIDKeyFilename:    testKeyFilename,
				SVIDBundleFilename: testBundleFilename,
			},
		},
		{
			name: "no set specified",
			config: &Config{
				AgentAddress: testAgentAddress,
			},
			expectError: "at least one of the sets ('svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name'), 'jwt_svids', or 'jwt_bundle_file_name' must be fully specified",
		},
		{
			name: "missing svid config",
			config: &Config{
				AgentAddress: testAgentAddress,
				SVIDFilename: testCertFilename,
			},
			expectError: "all or none of 'svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name' must be specified",
		},
		{
			name: "missing jwt audience",
			config: &Config{
				AgentAddress: testAgentAddress,
				JWTSVIDs: []JWTConfig{{
					JWTSVIDFilename: "jwt.token",
				}},
			},
			expectError: "'jwt_audience' is required in 'jwt_svids'",
		},
		{
			name: "missing jwt path",
			config: &Config{
				AgentAddress: testAgentAddress,
				JWTSVIDs: []JWTConfig{{
					JWTAudience: "my-audience",
				}},
			},
			expectError: "'jwt_file_name' is required in 'jwt_svids'",
		},
		{
			name: "no error with pid_file_name and renew_signal",
			config: &Config{
				PIDFilename:        testPIDFilename,
				RenewSignal:        testRenewSignal,
				AgentAddress:       testAgentAddress,
				SVIDFilename:       testCertFilename,
				SVIDKeyFilename:    testKeyFilename,
				SVIDBundleFilename: testBundleFilename,
			},
			skipWindows: true,
		},
		{
			// There's no test for 'cmd' and 'renew_signal' set in
			// daemon_mode here because they just log warnings
			name: "pid_file_name set in !daemon_mode",
			config: &Config{
				DaemonMode:  &[]bool{false}[0],
				PIDFilename: testPIDFilename,
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
				PIDFilename: testPIDFilename,
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
				Cmd:                testCmd,
				RenewSignal:        testRenewSignal,
				AgentAddress:       testAgentAddress,
				SVIDFilename:       testCertFilename,
				SVIDKeyFilename:    testKeyFilename,
				SVIDBundleFilename: testBundleFilename,
			},
			skipWindows: true,
		},
		{
			name: "legacy lifecycle config normalizes to start and reload",
			config: &Config{
				Cmd:                testCmd,
				CmdArgs:            "hello",
				PIDFilename:        testPIDFilename,
				RenewSignal:        testRenewSignal,
				AgentAddress:       testAgentAddress,
				SVIDFilename:       testCertFilename,
				SVIDKeyFilename:    testKeyFilename,
				SVIDBundleFilename: testBundleFilename,
			},
			skipWindows: true,
		},
		{
			name: "cmd conflicts with start cmd",
			config: &Config{
				Cmd:         testCmd,
				Start:       StartConfig{Cmd: "envoy"},
				RenewSignal: testRenewSignal,
			},
			expectError: "cmd cannot be used with start.cmd",
			skipWindows: true,
		},
		{
			name: "renew signal conflicts with reload signal",
			config: &Config{
				RenewSignal: testRenewSignal,
				Reload:      ReloadConfig{Signal: "SIGUSR1"},
			},
			expectError: "renew_signal cannot be used with reload.signal",
			skipWindows: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipWindows && os.Getenv("GOOS") == "windows" {
				t.Skip("skipping test on windows")
			}
			log, hook := test.NewNullLogger()
			err := tt.config.ValidateConfig(log)

			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				return
			}

			require.NoError(t, err)

			if tt.name == "legacy lifecycle config normalizes to start and reload" {
				assert.Equal(t, tt.config.Cmd, tt.config.Start.Cmd)
				assert.Equal(t, tt.config.CmdArgs, tt.config.Start.Args)
				assert.Equal(t, tt.config.RenewSignal, tt.config.Reload.Signal)
				assert.Equal(t, tt.config.PIDFilename, tt.config.Reload.PIDFilename)

				entries := hook.AllEntries()
				require.Len(t, entries, 3)
				assert.Equal(t, "cmd and cmd_args are deprecated and will be removed in a future release. Use start.cmd/start.args for a managed long-running process, or reload.cmd/reload.args for a one-shot reload command.", entries[0].Message)
				assert.Equal(t, "renew_signal is deprecated and will be removed in a future release. Use reload.signal instead.", entries[1].Message)
				assert.Equal(t, "pid_file_name is deprecated and will be removed in a future release. Use reload.pid_file_name instead.", entries[2].Message)
			}
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
		{
			name: "Unknown configuration in start",
			config: `
				start {
					cmd = "envoy"
					foo = "bar"
				}
				`,
			expectError: "unknown key(s) in start: foo",
		},
		{
			name: "Unknown configuration in reload",
			config: `
				reload {
					signal = "SIGHUP"
					foo = "bar"
				}
				`,
			expectError: "unknown key(s) in reload: foo",
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
			agentAddress:         configAgentAddress,
			expectedAgentAddress: configAgentAddress,
		},
		{
			name:                    "Agent Address not set in config but SPIFFE_ENDPOINT_SOCKET is set in env",
			envSPIFFEEndpointSocket: envAgentAddress,
			expectedAgentAddress:    envAgentAddress,
		},
		{
			name:                    "Agent Address set in config and set in env",
			agentAddress:            configAgentAddress,
			envSPIFFEEndpointSocket: envAgentAddress,
			expectedAgentAddress:    configAgentAddress,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("SPIFFE_ENDPOINT_SOCKET", tt.envSPIFFEEndpointSocket)

			config := &Config{
				AgentAddress:       tt.agentAddress,
				SVIDFilename:       testCertFilename,
				SVIDKeyFilename:    testKeyFilename,
				SVIDBundleFilename: testBundleFilename,
			}

			log, _ := test.NewNullLogger()
			err := config.ValidateConfig(log)
			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.expectedAgentAddress, config.AgentAddress)
		})
	}
}

func TestNewSidecarConfig(t *testing.T) {
	config := &Config{
		AgentAddress:            "my-agent-address",
		Cmd:                     "my-cmd",
		CmdArgs:                 "my-cmd-args",
		RenewSignal:             "SIGHUP",
		PIDFilename:             "my.pid",
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
	assert.Equal(t, config.Cmd, sidecarConfig.Start.Cmd)
	assert.Equal(t, config.CmdArgs, sidecarConfig.Start.Args)
	assert.Equal(t, config.RenewSignal, sidecarConfig.Reload.Signal)
	assert.Equal(t, config.PIDFilename, sidecarConfig.Reload.PIDFilename)
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
}

func TestDaemonModeFlag(t *testing.T) {
	config := &Config{
		SVIDFilename:       testCertFilename,
		SVIDKeyFilename:    testKeyFilename,
		SVIDBundleFilename: testBundleFilename,
	}

	daemonModeFlag := flag.Bool(daemonModeFlagName, true, "Toggle running as a daemon to rotate X.509/JWT or just fetch and exit")
	flag.Parse()

	err := flag.Set(daemonModeFlagName, "false")
	require.NoError(t, err)

	config.ParseConfigFlagOverrides(*daemonModeFlag, daemonModeFlagName)
	require.NotNil(t, config.DaemonMode)
	assert.False(t, *config.DaemonMode)
}
