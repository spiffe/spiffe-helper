//go:build windows
// +build windows

package sidecar

import (
	"errors"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func (s *Sidecar) getWorkloadAPIAdress() workloadapi.ClientOption {
	return workloadapi.WithNamedPipeName(s.config.AgentAddress)
}

func (s *Sidecar) SignalProcess() error {
	// Signal to reload certs
	// TODO: it is not possible to get signal by name on windows,
	// we must provide int here
	return errors.New("sending signal is not supported on windows")
}

func validateOSConfig(c *Config) error {
	if c.RenewSignal != "" {
		return errors.New("sending signals is not supported on windows")
	}
	return nil
}
