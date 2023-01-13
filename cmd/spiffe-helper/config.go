package main

import (
	"errors"
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

// ParseConfig parses the given HCL file into a SidecarConfig struct
func ParseConfig(file string) (*sidecar.Config, error) {
	sidecarConfig := new(sidecar.Config)

	// Read HCL file
	dat, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Parse HCL
	if err := hcl.Decode(sidecarConfig, string(dat)); err != nil {
		return nil, err
	}

	return sidecarConfig, nil
}

func ValidateConfig(c *sidecar.Config) error {
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
