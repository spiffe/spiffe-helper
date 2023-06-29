//go:build !windows
// +build !windows

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/sys/unix"
)

// RunDaemon starts the main loop
// Starts the workload API client to listen for new SVID updates
// When a new SVID is received on the updateChan, the SVID certificates
// are stored in disk and a restart signal is sent to the proxy's process
func (s *Sidecar) RunDaemon(ctx context.Context) error {
	err := workloadapi.WatchX509Context(ctx, &x509Watcher{sidecar: s}, workloadapi.WithAddr("unix://"+s.config.AgentAddress))
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
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
