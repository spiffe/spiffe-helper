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
			errch <- workloadapi.WatchX509Context(ctx, &x509Watcher{sidecar: s}, workloadapi.WithNamedPipeName(s.config.AgentAddress))
		}()
	}
	if s.config.JSONFilename != "" {
		go func() {
			defer wg.Done()
			errch <- workloadapi.WatchJWTBundles(ctx, &JWTBundlesWatcher{sidecar: s}, workloadapi.WithNamedPipeName(s.config.AgentAddress))
		}()
	}
	if s.config.JSONFilename != "" && s.config.JwtAudience != "" {
		go func() {
			defer wg.Done()
			s.updateJWTSVID(ctx, workloadapi.WithNamedPipeName(s.config.AgentAddress))
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
