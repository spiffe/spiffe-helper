package main

import (
	"errors"
	"os"

	"github.com/hashicorp/hcl"
	"github.com/sirupsen/logrus"
)

const (
	defaultAgentAddress = "/tmp/spire-agent/public/api.sock"
)

// Config contains config variables when creating a SPIFFE Sidecar.
type Config struct {
	AgentAddress                 string `hcl:"agent_address"`
	AgentAddressDeprecated       string `hcl:"agentAddress"`
	Cmd                          string `hcl:"cmd"`
	CmdArgs                      string `hcl:"cmd_args"`
	CmdArgsDeprecated            string `hcl:"cmdArgs"`
	CertDir                      string `hcl:"cert_dir"`
	CertDirDeprecated            string `hcl:"certDir"`
	ExitWhenReady                bool   `hcl:"exit_when_ready"`
	SvidFileName                 string `hcl:"svid_file_name"`
	SvidFileNameDeprecated       string `hcl:"svidFileName"`
	SvidKeyFileName              string `hcl:"svid_key_file_name"`
	SvidKeyFileNameDeprecated    string `hcl:"svidKeyFileName"`
	SvidBundleFileName           string `hcl:"svid_bundle_file_name"`
	SvidBundleFileNameDeprecated string `hcl:"svidBundleFileName"`
	RenewSignal                  string `hcl:"renew_signal"`
	RenewSignalDeprecated        string `hcl:"renewSignal"`
	IncludeFederatedDomains      bool   `hcl:"include_federated_domains"`
	DaemonMode                   *bool  `hcl:"daemon_mode"`

	// JWT configuration
	JWTSvids          []JwtConfig `hcl:"jwt_svids"`
	JWTBundleFilename string      `hcl:"jwt_bundle_file_name"`

	// Merge intermediate certificates into Bundle file instead of SVID file,
	// it is useful is some scenarios like MySQL,
	// where this is the expected format for presented certificates and bundles
	AddIntermediatesToBundle           bool `hcl:"add_intermediates_to_bundle"`
	AddIntermediatesToBundleDeprecated bool `hcl:"addIntermediatesToBundle"`
}

type JwtConfig struct {
	JWTAudience     string `hcl:"jwt_audience"`
	JWTSvidFilename string `hcl:"jwt_svid_file_name"`
}

// ParseConfig parses the given HCL file into a SidecarConfig struct
func ParseConfig(file string) (*Config, error) {
	// Read HCL file
	dat, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Parse HCL
	config := new(Config)
	if err := hcl.Decode(config, string(dat)); err != nil {
		return nil, err
	}

	return config, nil
}

func ValidateConfig(c *Config, log logrus.FieldLogger) (bool, bool, bool, error) {
	if err := validateOSConfig(c); err != nil {
		return false, false, false, err
	}

	if c.AgentAddressDeprecated != "" {
		if c.AgentAddress != "" {
			return false, false, false, errors.New("use of agent_address and agentAddress found, use only agent_address")
		}
		log.Warn(getWarning("agentAddress", "agent_address"))
		c.AgentAddress = c.AgentAddressDeprecated
	}

	if c.CmdArgsDeprecated != "" {
		if c.CmdArgs != "" {
			return false, false, false, errors.New("use of cmd_args and cmdArgs found, use only cmd_args")
		}
		log.Warn(getWarning("cmdArgs", "cmd_args"))
		c.CmdArgs = c.CmdArgsDeprecated
	}

	if c.CertDirDeprecated != "" {
		if c.CertDir != "" {
			return false, false, false, errors.New("use of cert_dir and certDir found, use only cert_dir")
		}
		log.Warn(getWarning("certDir", "cert_dir"))
		c.CertDir = c.CertDirDeprecated
	}

	if c.SvidFileNameDeprecated != "" {
		if c.SvidFileName != "" {
			return false, false, false, errors.New("use of svid_file_name and svidFileName found, use only svid_file_name")
		}
		log.Warn(getWarning("svidFileName", "svid_file_name"))
		c.SvidFileName = c.SvidFileNameDeprecated
	}

	if c.SvidKeyFileNameDeprecated != "" {
		if c.SvidKeyFileName != "" {
			return false, false, false, errors.New("use of svid_key_file_name and svidKeyFileName found, use only svid_key_file_name")
		}
		log.Warn(getWarning("svidKeyFileName", "svid_key_file_name"))
		c.SvidKeyFileName = c.SvidKeyFileNameDeprecated
	}

	if c.SvidBundleFileNameDeprecated != "" {
		if c.SvidBundleFileName != "" {
			return false, false, false, errors.New("use of svid_bundle_file_name and svidBundleFileName found, use only svid_bundle_file_name")
		}
		log.Warn(getWarning("svidBundleFileName", "svid_bundle_file_name"))
		c.SvidBundleFileName = c.SvidBundleFileNameDeprecated
	}

	if c.RenewSignalDeprecated != "" {
		if c.RenewSignal != "" {
			return false, false, false, errors.New("use of renew_signal and renewSignal found, use only renew_signal")
		}
		log.Warn(getWarning("renewSignal", "renew_signal"))
		c.RenewSignal = c.RenewSignalDeprecated
	}

	for _, jwtConfig := range c.JWTSvids {
		if jwtConfig.JWTSvidFilename == "" {
			return false, false, false, errors.New("'jwt_file_name' is required in 'jwt_svids'")
		}
		if jwtConfig.JWTAudience == "" {
			return false, false, false, errors.New("'jwt_audience' is required in 'jwt_svids'")
		}
	}

	if c.AgentAddress == "" {
		c.AgentAddress = os.Getenv("SPIFFE_ENDPOINT_SOCKET")
		if c.AgentAddress == "" {
			c.AgentAddress = defaultAgentAddress
		}
		c.AgentAddress = os.Getenv("SPIRE_AGENT_ADDRESS")
		if c.AgentAddress == "" {
			c.AgentAddress = defaultAgentAddress
		}
	}

	x509Enabled, err := validateX509Config(c)
	if err != nil {
		return false, false, false, err
	}

	jwtBundleEnabled, jwtSVIDsEnabled := validateJWTConfig(c)

	if !x509Enabled && !jwtBundleEnabled && !jwtSVIDsEnabled {
		return false, false, false, errors.New("at least one of the sets ('svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name'), 'jwt_svids', or 'jwt_bundle_file_name' must be fully specified")
	}

	if c.DaemonMode == nil {
		daemonMode := true
		c.DaemonMode = &daemonMode
	}

	return x509Enabled, jwtBundleEnabled, jwtSVIDsEnabled, nil
}

func validateX509Config(c *Config) (bool, error) {
	x509EmptyCount := countEmpty(c.SvidFileName, c.SvidBundleFileName, c.SvidKeyFileName)
	if x509EmptyCount != 0 && x509EmptyCount != 3 {
		return false, errors.New("all or none of 'svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name' must be specified")
	}

	return x509EmptyCount == 0, nil
}

func validateJWTConfig(c *Config) (bool, bool) {
	jwtBundleEmptyCount := countEmpty(c.SvidBundleFileName)

	return jwtBundleEmptyCount == 0, len(c.JWTSvids) > 0
}

func getWarning(s1 string, s2 string) string {
	return s1 + " will be deprecated, should be used as " + s2
}

func countEmpty(configs ...string) int {
	cnt := 0
	for _, config := range configs {
		if config == "" {
			cnt++
		}
	}
	return cnt
}
