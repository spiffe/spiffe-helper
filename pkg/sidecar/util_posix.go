//go:build !windows
// +build !windows

package sidecar

import (
	"context"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/sys/unix"
)

// RunDaemon starts the main loop
// Starts the workload API client to listen for new SVID updates
// When a new SVID is received on the updateChan, the SVID certificates
// are stored in disk and a restart signal is sent to the proxy's process
func (s *Sidecar) RunDaemon(ctx context.Context) error {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		wg.Wait()
	}()

	tasks := 0
	if s.config.SvidFileName != "" && s.config.SvidKeyFileName != "" && s.config.SvidBundleFileName != "" {
		tasks++
	}
	if s.config.JSONFilename != "" {
		tasks++
	}
	if s.config.JSONFilename != "" && s.config.JwtAudience != "" {
		tasks++
	}
	wg.Add(tasks)

	errch := make(chan error, tasks)
	if s.config.SvidFileName != "" && s.config.SvidKeyFileName != "" && s.config.SvidBundleFileName != "" {
		go func() {
			defer wg.Done()
			errch <- workloadapi.WatchX509Context(ctx, &x509Watcher{sidecar: s}, workloadapi.WithAddr("unix://"+s.config.AgentAddress))
		}()
	}
	if s.config.JSONFilename != "" {
		go func() {
			defer wg.Done()
			errch <- workloadapi.WatchJWTBundles(ctx, &JWTBundlesWatcher{sidecar: s}, workloadapi.WithAddr("unix://"+s.config.AgentAddress))
		}()
	}
	if s.config.JSONFilename != "" && s.config.JwtAudience != "" {
		go func() {
			defer wg.Done()
			s.updateJWTSVID(ctx, workloadapi.WithAddr("unix://"+s.config.AgentAddress))
			errch <- nil
		}()
	}

	for complete := 0; complete < tasks; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errch:
			if err != nil {
				return err
			}
			complete++
		}
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
