package sidecar

import (
	"github.com/sirupsen/logrus"
)

// Config contains config variables when creating a SPIFFE Sidecar.
type Config struct {
	AgentAddress       string
	Cmd                string
	CmdArgs            string
	CertDir            string
	SvidFileName       string
	SvidKeyFileName    string
	SvidBundleFileName string
	Log                logrus.FieldLogger
	RenewSignal        string
	IncludeFederatedDomains            bool   `hcl:"include_federated_domains"`

	// Merge intermediate certificates into Bundle file instead of SVID file,
	// it is useful is some scenarios like MySQL,
	// where this is the expected format for presented certificates and bundles
	AddIntermediatesToBundle bool

	// JWT configuration
	JwtSvids          []JwtConfig
	JWTBundleFilename string

	// TODO: is there a reason for this to be exposed? and inside of config?
	ReloadExternalProcess func() error
}

type JwtConfig struct {
	JWTAudience     string
	JWTSvidFilename string
}
