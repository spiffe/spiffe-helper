package sidecar

import (
	"errors"
	"os"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/logger"
)

// Config contains config variables when creating a SPIFFE Sidecar.
type Config struct {
	AgentAddress string `hcl:"agentAddress"`
	Cmd          string `hcl:"cmd"`
	CmdArgs      string `hcl:"cmdArgs"`
	CertDir      string `hcl:"certDir"`
	// Merge intermediate certificates into Bundle file instead of SVID file,
	// it is useful is some scenarios like MySQL,
	// where this is the expected format for presented certificates and bundles
	AddIntermediatesToBundle bool   `hcl:"addIntermediatesToBundle"`
	SvidFileName             string `hcl:"svidFileName"`
	SvidKeyFileName          string `hcl:"svidKeyFileName"`
	SvidBundleFileName       string `hcl:"svidBundleFileName"`
	RenewSignal              string `hcl:"renewSignal"`
	// TODO: is there a reason for this to be exposed? and inside of config?
	ReloadExternalProcess func() error
	// TODO: is there a reason for this to be exposed? and inside of config?
	Log logger.Logger
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
	switch {
	case c.AgentAddress == "":
		return errors.New("agentAddress is required")
	case c.SvidFileName == "":
		return errors.New("svidFileName is required")
	case c.SvidKeyFileName == "":
		return errors.New("svidKeyFileName is required")
	case c.SvidBundleFileName == "":
		return errors.New("svidBundleFileName is required")
	default:
		return nil
	}
}
