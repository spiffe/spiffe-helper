package sidecar

import (
	"github.com/sirupsen/logrus"
)

// Config contains config variables when creating a SPIFFE Sidecar.
type Config struct {
	AgentAddress            string
	Cmd                     string
	CmdArgs                 string
	CertDir                 string
	SVIDFileName            string
	SVIDKeyFileName         string
	SVIDBundleFileName      string
	Log                     logrus.FieldLogger
	RenewSignal             string
	IncludeFederatedDomains bool
	X509Enabled             bool
	JWTBundleEnabled        bool
	JWTSVIDsEnabled         bool

	// Merge intermediate certificates into Bundle file instead of SVID file,
	// it is useful is some scenarios like MySQL,
	// where this is the expected format for presented certificates and bundles
	AddIntermediatesToBundle bool

	// JWT configuration
	JWTSVIDs          []JWTConfig
	JWTBundleFilename string

	// TODO: is there a reason for this to be exposed? and inside of config?
	ReloadExternalProcess func() error
}

type JWTConfig struct {
	JWTAudience     string
	JWTSVIDFilename string
}
