package sidecar

import (
	"github.com/sirupsen/logrus"
)

type Config struct {
	// If true, merge intermediate certificates into Bundle file instead of SVID file.
	// This is the exptected format for MySQL and some other applications.
	AddIntermediatesToBundle bool

	// The address of the Agent Workload API.
	AgentAddress string

	// The path to the process to launch.
	Cmd string

	// The arguments of the process to launch.
	CmdArgs string

	// The directory name to store the x509s and/or JWTs.
	CertDir string

	// If true, fetche x509 certificate and then exit(0).
	ExitWhenReady bool

	// If true, includes trust domains from federated servers in the CA bundle.
	IncludeFederatedDomains bool

	// An array with the audience and file name to store the JWT SVIDs. File is Base64-encoded string).
	JwtSvids []JwtConfig

	// File name to be used to store JWT Bundle in JSON format.
	JWTBundleFilename string

	// The logger to use
	Log logrus.FieldLogger

	// The signal that the process to be launched expects to reload the certificates. Not supported on Windows.
	RenewSignal string

	// File name to be used to store the X.509 SVID public certificate in PEM format.
	SvidFileName string

	// File name to be used to store the X.509 SVID private key and public certificate in PEM format.
	SvidKeyFileName string

	// File name to be used to store the X.509 SVID Bundle in PEM format.
	SvidBundleFileName string

	// TODO: is there a reason for this to be exposed? and inside of config?
	ReloadExternalProcess func() error
}

type JwtConfig struct {
	// The audience for the JWT SVID to fetch
	JWTAudience string

	// The filename to save the JWT SVID to
	JWTSvidFilename string
}
