package sidecar

/*
 * This file contains helpers for starting sidecars for testing,
 * mocking the workload API server responses, and creating test
 * X.509 SVIDs.
 */

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io/fs"
	"os"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/pkg/disk"
	"github.com/spiffe/spiffe-helper/test/spiffetest"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/retry"
)

const (
	exampleSpiffeID = "spiffe://example.test/workload"
)

// sidecarTest is a helper struct to create a sidecar instance for testing.
// Each should be used for one sidecar instance only, then disposed.
type sidecarTest struct {
	rootCA  *spiffetest.CA
	sidecar *Sidecar
	watcher *x509Watcher
	certDir string

	// Channel for receiving process exit states
	cmdExitChan chan os.ProcessState

	// Channel for receiving certificate updates
	certReadyChan chan *workloadapi.X509Context

	// Channel for receiving PID file signalling results
	pidFileSignalledChan chan pidFileSignalledResult
}

// pidFileSignalledResult is used to send the outcome whenever an attempt is made
// to signal pid_file_name. Mainly for test purposes.
type pidFileSignalledResult struct {
	pid int
	err error
}

// newSidecarTest creates a new sidecar test instance with optional configuration.
// It creates a new SPIFFE CA, a sidecar instance, and sets up channels to observe
// internal state transitions. The sidecar is configured to watch for X.509 context
// updates and will call the certReady hook when it receives a new SVID
// response.
//
// Usage:
//   - newSidecarTest(t) - uses default configuration
//   - newSidecarTest(t, withConfig(customConfig)) - uses custom configuration
func newSidecarTest(t *testing.T, opts ...option) *sidecarTest {
	t.Helper()

	// Create default config with temp directory
	certDir := t.TempDir()
	config := defaultTestConfig(certDir)
	log, _ := test.NewNullLogger()
	config.Log = log

	// Apply any custom options
	for _, opt := range opts {
		opt(config)
	}

	s := &sidecarTest{
		rootCA:  spiffetest.NewCA(t),
		sidecar: New(config),
		certDir: certDir,

		// Observers for internal state transitions
		cmdExitChan:          make(chan os.ProcessState, 2),
		pidFileSignalledChan: make(chan pidFileSignalledResult, 2),
		certReadyChan:        make(chan *workloadapi.X509Context, 2),
	}

	s.sidecar.hooks = hooks{
		certReady: func(svids *workloadapi.X509Context) {
			select {
			case s.certReadyChan <- svids:
			default:
			}
		},
		cmdExit: func(state os.ProcessState) {
			s.cmdExitChan <- state
		},
		pidFileSignalled: func(pid int, err error) {
			s.pidFileSignalledChan <- pidFileSignalledResult{
				pid: pid,
				err: err,
			}
		},
	}
	s.watcher = &x509Watcher{s.sidecar}

	return s
}

// Clean up the sidecar instance. Its channels will orphaned for the GC to
// clean up. This should be called after the test is done with the sidecar.
// Any pending signals must have been delivered, and any running processes
// must have exited.
func (s *sidecarTest) Close(t *testing.T) {
	t.Helper()

	err := retry.OnError(retry.DefaultRetry, func(err error) bool {
		return err != nil
	}, func() (err error) {
		s.sidecar.mu.Lock()
		running := s.sidecar.processRunning
		p := s.sidecar.process
		s.sidecar.mu.Unlock()

		if running {
			return fmt.Errorf("sidecar process %d still running at end of test", p.Pid)
		}
		return nil
	})

	require.NoError(t, err)
}

// Trigger a certificate update on the sidecar instance to the passed new SVID.
// The golang context passed should have a timeout set to avoid hanging tests.
func (s *sidecarTest) MockUpdateX509Certificate(ctx context.Context, t *testing.T, svid testX509SVID) {
	t.Helper()

	// Send the new SVID to the sidecar
	s.watcher.OnX509ContextUpdate(svid.x509Context())
	// and wait for the sidecar to process it
	for {
		select {
		case x509Context := <-s.certReadyChan:
			// We must get the same context back as what we sent.
			// We don't expect to be testing chains of multiple
			// server responses here and the channel only has a 1
			// entry buffer anyway.
			require.Equal(t, svid.x509Context(), x509Context)
			return
		case <-ctx.Done():
			// In case of timeout, fail the test
			require.NoError(t, ctx.Err())
			return
		}
	}
}

// defaultTestConfig provides default configuration values for tests
func defaultTestConfig(certDir string) *Config {
	return &Config{
		Cmd: "echo",
		X509Disk: disk.NewX509(disk.X509Config{
			Dir:                certDir,
			SVIDFileName:       "svid.pem",
			SVIDKeyFileName:    "svid_key.pem",
			SVIDBundleFileName: "svid_bundle.pem",
			CertFileMode:       fs.FileMode(0644),
			KeyFileMode:        fs.FileMode(0600),
		}),
		JWTDisk: disk.NewJWT(disk.JWTConfig{
			Dir:            certDir,
			BundleFileMode: fs.FileMode(0600),
			SVIDFileMode:   fs.FileMode(0600),
		}),
	}
}

// option is a functional option for configuring newSidecarTest
type option func(*Config)

// withConfig returns an Option that sets the config to the provided value
func withConfig(cfg *Config) option {
	return func(config *Config) {
		*config = *cfg
	}
}

// One X.509 SVID with its chain and private key, as will be generated for the CA
// and sent via the fake workload API server to the x.509 watcher. May not necessarily
// have the same root CA as the sidecarTest instance, since we might be testing
// incorrect responses.
type testX509SVID struct {
	rootCA    *spiffetest.CA
	spiffeID  spiffeid.ID
	svidChain []*x509.Certificate
	svidKey   crypto.PrivateKey
	svid      []*x509svid.SVID
}

// Create a single svid without intermediate, as if the workload api server
// issued a cert from the specified root CA.
func newTestX509SVID(t *testing.T, rootCA *spiffetest.CA) testX509SVID {
	t.Helper()

	spiffeID, err := spiffeid.FromString(exampleSpiffeID)
	require.NoError(t, err)
	svidChain, svidKey := rootCA.CreateX509SVID(spiffeID.String())
	require.Len(t, svidChain, 1)
	svid := []*x509svid.SVID{
		{
			ID:           spiffeID,
			Certificates: svidChain,
			PrivateKey:   svidKey,
		},
	}
	return testX509SVID{
		rootCA:    rootCA,
		spiffeID:  spiffeID,
		svidChain: svidChain,
		svidKey:   svidKey,
		svid:      svid,
	}
}

// Return the root CA bundle for x509 SVID test instance.
func (svid testX509SVID) bundle() []*x509.Certificate {
	return svid.rootCA.Roots()
}

// Return the x.509 context that should be received by any x.509 watcher
// after this SVID is passed to MockUpdateX509Certificate to simulate
// the workload API server sending a response.
func (svid testX509SVID) x509Context() *workloadapi.X509Context {
	return &workloadapi.X509Context{
		Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(svid.spiffeID.TrustDomain(), svid.bundle())),
		SVIDs:   svid.svid,
	}
}
