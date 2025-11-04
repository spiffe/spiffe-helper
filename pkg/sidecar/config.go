package sidecar

import (
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/pkg/disk"
)

type Config struct {
	// The address of the Agent Workload API.
	AgentAddress string

	// The path to the process to launch.
	Cmd string

	// The arguments of the process to launch.
	CmdArgs string

	// Signal external process via PID file
	PIDFileName string

	// The logger to use
	Log logrus.FieldLogger

	// The signal that the process to be launched expects to reload the certificates. Not supported on Windows.
	RenewSignal string

	// X.509 SVID related disk writer
	X509Disk *disk.X509

	// JWT SVID related disk writer
	JWTDisk *disk.JWT

	// JWT SVIDs to fetch and write to disk
	JWTSVIDs []JWTConfig

	// TODO: is there a reason for this to be exposed? and inside of config?
	ReloadExternalProcess func() error
}

type JWTConfig struct {
	// The audience for the JWT SVID to fetch
	JWTAudience string

	// The extra audiences for the JWT SVID to fetch
	JWTExtraAudiences []string

	// The filename to save the JWT SVID to
	JWTSVIDFileName string
}
