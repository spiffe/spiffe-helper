//go:build windows
// +build windows

package sidecar

import (
	"context"
	"errors"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// RunDaemon starts the main loop
// Starts the workload API client to listen for new SVID updates
// When a new SVID is received on the updateChan, the SVID certificates
// are stored in disk and a restart signal is sent to the proxy's process
func (s *Sidecar) RunDaemon(ctx context.Context) error {
	err := workloadapi.WatchX509Context(ctx, &x509Watcher{sidecar: s}, workloadapi.WithNamedPipeName(s.config.AgentAddress))
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
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
