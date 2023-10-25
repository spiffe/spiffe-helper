//go:build windows
// +build windows

package sidecar

import (
	"context"
	"errors"
	"sync"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RunDaemon starts the main loop
// Starts the workload API client to listen for new SVID updates
// When a new SVID is received on the updateChan, the SVID certificates
// are stored in disk and a restart signal is sent to the proxy's process
func (s *Sidecar) RunDaemon(ctx context.Context) error {
	var wg sync.WaitGroup

	if s.config.SvidFileName != "" && s.config.SvidKeyFileName != "" && s.config.SvidBundleFileName != "" {
		wg.add(1)
		go func() {
			defer wg.Done()
			err := workloadapi.WatchX509Context(ctx, &x509Watcher{sidecar: s}, workloadapi.WithNamedPipeName(s.config.AgentAddress))
			if err != nil && status.Code(err) != codes.Canceled {
				s.config.Log.Fatalf("Error watching X.509 context: %w", err)
			}
		}()
	}

	if s.config.JWKFilename != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := workloadapi.WatchJWTBundles(ctx, &JWTBundlesWatcher{sidecar: s}, workloadapi.WithNamedPipeName(s.config.AgentAddress))
			if err != nil && status.Code(err) != codes.Canceled {
				s.config.Log.Fatalf("Error watching JWT bundles updates: %w", err)
			}
		}()
	}

	if s.config.JWTFilename != "" && s.config.JwtAudience != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.updateJWTSVID(ctx, workloadapi.WithNamedPipeName(s.config.AgentAddress))
			errch <- nil
		}()
	}

	wg.Wait()

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
