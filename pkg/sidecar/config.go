package sidecar

import (
	"errors"
	"os"

	"github.com/hashicorp/hcl"
	"github.com/sirupsen/logrus"
)

// Config contains config variables when creating a SPIFFE Sidecar.
type Config struct {
	AgentAddress           string `hcl:"agent_address"`
	AgentAddressDeprecated string `hcl:"agentAddress"`
	Cmd                    string `hcl:"cmd"`
	CmdArgs                string `hcl:"cmd_args"`
	CmdArgsDeprecated      string `hcl:"cmdArgs"`
	CertDir                string `hcl:"cert_dir"`
	CertDirDeprecated      string `hcl:"certDir"`
	ExitWhenReady          bool   `hcl:"exit_when_ready"`
	// Merge intermediate certificates into Bundle file instead of SVID file,
	// it is useful is some scenarios like MySQL,
	// where this is the expected format for presented certificates and bundles
	AddIntermediatesToBundle           bool   `hcl:"add_intermediates_to_bundle"`
	AddIntermediatesToBundleDeprecated bool   `hcl:"addIntermediatesToBundle"`
	SvidFileName                       string `hcl:"svid_file_name"`
	SvidFileNameDeprecated             string `hcl:"svidFileName"`
	SvidKeyFileName                    string `hcl:"svid_key_file_name"`
	SvidKeyFileNameDeprecated          string `hcl:"svidKeyFileName"`
	SvidBundleFileName                 string `hcl:"svid_bundle_file_name"`
	SvidBundleFileNameDeprecated       string `hcl:"svidBundleFileName"`
	RenewSignal                        string `hcl:"renew_signal"`
	RenewSignalDeprecated              string `hcl:"renewSignal"`
	IncludeFederatedDomains            bool   `hcl:"include_federated_domains"`

	// JWT configuration
	JWTAudience       string `hcl:"jwt_audience"`
	JWTSvidFilename   string `hcl:"jwt_svid_file_name"`
	JWTBundleFilename string `hcl:"jwt_bundle_file_name"`

	// TODO: is there a reason for this to be exposed? and inside of config?
	ReloadExternalProcess func() error
	// TODO: is there a reason for this to be exposed? and inside of config?
	Log logrus.FieldLogger
}

// ParseConfig parses the given HCL file into a SidecarConfig struct
func ParseConfig(file string) (*Config, error) {
	sidecarConfig := new(Config)

	// Read HCL file
	dat, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Parse HCL
	if err := hcl.Decode(sidecarConfig, string(dat)); err != nil {
		return nil, err
	}

	return sidecarConfig, nil
}

func ValidateConfig(c *Config) error {
	if err := validateOSConfig(c); err != nil {
		return err
	}
	if c.AgentAddressDeprecated != "" {
		if c.AgentAddress != "" {
			return errors.New("use of agent_address and agentAddress found, use only agent_address")
		}
		c.Log.Warn(getWarning("agentAddress", "agent_address"))
		c.AgentAddress = c.AgentAddressDeprecated
	}

	if c.CmdArgsDeprecated != "" {
		if c.CmdArgs != "" {
			return errors.New("use of cmd_args and cmdArgs found, use only cmd_args")
		}
		c.Log.Warn(getWarning("cmdArgs", "cmd_args"))
		c.CmdArgs = c.CmdArgsDeprecated
	}

	if c.CertDirDeprecated != "" {
		if c.CertDir != "" {
			return errors.New("use of cert_dir and certDir found, use only cert_dir")
		}
		c.Log.Warn(getWarning("certDir", "cert_dir"))
		c.CertDir = c.CertDirDeprecated
	}

	if c.SvidFileNameDeprecated != "" {
		if c.SvidFileName != "" {
			return errors.New("use of svid_file_name and svidFileName found, use only svid_file_name")
		}
		c.Log.Warn(getWarning("svidFileName", "svid_file_name"))
		c.SvidFileName = c.SvidFileNameDeprecated
	}

	if c.SvidKeyFileNameDeprecated != "" {
		if c.SvidKeyFileName != "" {
			return errors.New("use of svid_key_file_name and svidKeyFileName found, use only svid_key_file_name")
		}
		c.Log.Warn(getWarning("svidKeyFileName", "svid_key_file_name"))
		c.SvidKeyFileName = c.SvidKeyFileNameDeprecated
	}

	if c.SvidBundleFileNameDeprecated != "" {
		if c.SvidBundleFileName != "" {
			return errors.New("use of svid_bundle_file_name and svidBundleFileName found, use only svid_bundle_file_name")
		}
		c.Log.Warn(getWarning("svidBundleFileName", "svid_bundle_file_name"))
		c.SvidBundleFileName = c.SvidBundleFileNameDeprecated
	}

	if c.RenewSignalDeprecated != "" {
		if c.RenewSignal != "" {
			return errors.New("use of renew_signal and renewSignal found, use only renew_signal")
		}
		c.Log.Warn(getWarning("renewSignal", "renew_signal"))
		c.RenewSignal = c.RenewSignalDeprecated
	}

	x509EmptyCount := countEmpty(c.SvidFileName, c.SvidBundleFileName, c.SvidKeyFileName)
	jwtSVIDEmptyCount := countEmpty(c.JWTSvidFilename, c.JWTAudience)
	jwtBundleEmptyCount := countEmpty(c.SvidBundleFileName)
	if x509EmptyCount == 3 && jwtSVIDEmptyCount == 2 && jwtBundleEmptyCount == 1 {
		return errors.New("at least one of the sets ('svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name'), ('jwt_file_name', 'jwt_audience'), or ('jwt_bundle_file_name') must be fully specified")
	}

	if x509EmptyCount != 0 && x509EmptyCount != 3 {
		return errors.New("all or none of 'svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name' must be specified")
	}

	if jwtSVIDEmptyCount != 0 && jwtSVIDEmptyCount != 2 {
		return errors.New("all or none of 'jwt_file_name', 'jwt_audience' must be specified")
	}

	return nil
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
