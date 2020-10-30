package main

import (
	"io/ioutil"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)
const (
	// default timeout Duration for the workloadAPI client when the defaultTimeout
	// is not configured in the .conf file
	defaultTimeout = 5 * time.Second
)

// ParseConfig parses the given HCL file into a SidecarConfig struct
func ParseConfig(file string) (config *sidecar.Config, err error) {
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

// GetTimeout parses a time.Duration from the the Config,
// if there's an error during parsing, maybe because
// it's not well defined or not defined at all in the
// config, returns the defaultTimeout constant
func GetTimeout(config *sidecar.Config) (time.Duration, error) {
	if config.Timeout == "" {
		return defaultTimeout, nil
	}

	t, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return 0, err
	}
	return t, nil
}
