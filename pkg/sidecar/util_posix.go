//go:build !windows
// +build !windows

package sidecar

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/sys/unix"
)

func (s *Sidecar) getWorkloadAPIAdress() workloadapi.ClientOption {
	return workloadapi.WithAddr("unix://" + s.config.AgentAddress)
}

func (s *Sidecar) SignalProcess() error {
	// Signal to reload certs
	if s.config.RenewSignal == "" {
		// no signal provided
		return nil
	}
	sig := unix.SignalNum(s.config.RenewSignal)
	if sig == 0 {
		return fmt.Errorf("error getting signal: %v", s.config.RenewSignal)
	}

	err := s.process.Signal(sig)
	if err != nil {
		return fmt.Errorf("error signaling process with signal: %v\n%w", sig, err)
	}

	return nil
}

func validateOSConfig(c *Config) error {
	return nil
}
