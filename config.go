package main

import (
	"io/ioutil"

	"github.com/hashicorp/hcl"
)

// SidecarConfig is HCL config data
type SidecarConfig struct {
	AgentAddress       string `hcl:"agentAddress"`
	Cmd                string `hcl:"cmd"`
	CmdArgs            string `hcl:"cmdArgs"`
	CertDir            string `hcl:"certDir"`
	SvidFileName       string `hcl:"svidFileName"`
	SvidKeyFileName    string `hcl:"svidKeyFileName"`
	SvidBundleFileName string `hcl:"svidBundleFileName"`
	RenewSignal        string `hcl:"renewSignal"`
	Timeout            string `hcl:"timeout"`
}

// ParseConfig parses the given HCL file into a SidecarConfig struct
func ParseConfig(file string) (sidecarConfig *SidecarConfig, err error) {
	sidecarConfig = &SidecarConfig{}

	// Read HCL file
	dat, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	hclText := string(dat)

	// Parse HCL
	hclParseTree, err := hcl.Parse(hclText)
	if err != nil {
		return nil, err
	}

	if err := hcl.DecodeObject(&sidecarConfig, hclParseTree); err != nil {
		return nil, err
	}

	return sidecarConfig, nil
}
