package sidecar

import (
	"context"
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := workloadapi.WatchX509Context(ctx, &x509Watcher{sidecar: s}, s.getWorkloadAPIAdress())
			if err != nil && status.Code(err) != codes.Canceled {
				s.config.Log.Errorf("Error watching X.509 context: %v", err)
			}
		}()
	}

	if s.config.JWTBundleFilename != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := workloadapi.WatchJWTBundles(ctx, &JWTBundlesWatcher{sidecar: s}, s.getWorkloadAPIAdress())
			if err != nil && status.Code(err) != codes.Canceled {
				s.config.Log.Errorf("Error watching JWT bundle updates: %v", err)
			}
		}()
	}

	if s.config.JWTSvidFilename != "" && s.config.JWTAudience != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.updateJWTSVID(ctx, s.getWorkloadAPIAdress())
		}()
	}

	wg.Wait()

	return nil
}
