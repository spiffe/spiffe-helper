package main

import (
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

// ParseConfig parses the given HCL file into a SidecarConfig struct
func ParseConfig(file string) (Config *sidecar.Config, err error) {
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
