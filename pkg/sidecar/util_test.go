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
	"os"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/test/spiffetest"
	"github.com/stretchr/testify/require"
)

const (
	exampleSpiffeID = "spiffe://example.test/workload"
)

// sidecarTest is a helper struct to create a sidecar instance for testing.
// Each should be used for one sidecar instance only, then disposed.
type sidecarTest struct {
	rootCA  *spiffetest.CA
	config  *Config
	sidecar *Sidecar
	watcher *x509Watcher
}

// Create a new sidecar test instance. It needs to be configured
// with NewConfig() and NewSidecar() before use. Then pass a
// sidecarTestX509SVID instance from newTestX509SVID to
// MockUpdateX509Certificate to simulate the workload API server sending a
// response.
func newSidecarTest(t *testing.T) *sidecarTest {
	return &sidecarTest{
		rootCA: spiffetest.NewCA(t),
	}
}

// This only supports x509 for now, should be updated to support
// JWT too like RunDaemon. Probably helpers to inject configs for each
// of x509, jwt, etc, since we can support combos of them. Then the
// NewSidecar can check what is enabled.
func (s *sidecarTest) NewConfig(t *testing.T) {
	if s.config != nil {
		panic("reuse of sidecarTest instance, config already exists")
	}
	tmpdir := t.TempDir()
	log, _ := test.NewNullLogger()
	s.config = &Config{
		Cmd:                "echo",
		CertDir:            tmpdir,
		SVIDFileName:       "svid.pem",
		SVIDKeyFileName:    "svid_key.pem",
		SVIDBundleFileName: "svid_bundle.pem",
		Log:                log,
		CertFileMode:       os.FileMode(0644),
		KeyFileMode:        os.FileMode(0600),
		JWTBundleFileMode:  os.FileMode(0600),
		JWTSVIDFileMode:    os.FileMode(0600),
	}
}

// Create a new sidecar instance for testing.
func (s *sidecarTest) NewSidecar(_ *testing.T) {
	if s.config == nil {
		panic("cannot create test sidecar without a config")
	}
	if s.sidecar != nil {
		panic("reuse of sidecarTest instance, sidecar already exists")
	}
	s.sidecar = &Sidecar{
		config:        s.config,
		certReadyChan: make(chan *workloadapi.X509Context, 2),
		health: Health{
			FileWriteStatuses: FileWriteStatuses{
				X509WriteStatus: writeStatusUnwritten,
				JWTWriteStatus:  make(map[string]string),
			},
		},
		// Observers for internal state	transitions
		cmdExitChan:          make(chan os.ProcessState, 2),
		pidFileSignalledChan: make(chan pidFileSignalledResult, 2),
	}
	s.watcher = &x509Watcher{s.sidecar}
}

func (s *sidecarTest) Config() *Config {
	if s.config == nil {
		panic("sidecarTest instance has no config")
	}
	return s.config
}

func (s *sidecarTest) Sidecar() *Sidecar {
	if s.sidecar == nil {
		panic("sidecarTest instance has no sidecar")
	}
	return s.sidecar
}

func (s *sidecarTest) Watcher() *x509Watcher {
	if s.watcher == nil {
		panic("sidecarTest instance has no watcher")
	}
	return s.watcher
}

// Clean up the sidecar instance. Its channels will orphaned for the GC to
// clean up. This should be called after the test is done with the sidecar.
// Any pending signals must have been delivered, and any running processes
// must have exited.
func (s *sidecarTest) Close(t *testing.T) {
	s.sidecar.mu.Lock()
	running := s.sidecar.processRunning
	p := s.sidecar.process
	defer s.sidecar.mu.Unlock()

	if running {
		t.Logf("WARNING: sidecar process %d still running at end of test (%#v)", p.Pid, p)
	}
}

// Trigger a certificate update on the sidecar instance to the passed new SVID.
// The golang context passed should have a timeout set to avoid hanging tests.
func (s *sidecarTest) MockUpdateX509Certificate(ctx context.Context, t *testing.T, svid testX509SVID) {
	// Send the new SVID to the sidecar
	s.watcher.OnX509ContextUpdate(svid.x509Context())
	// and wait for the sidecar to process it
	for {
		select {
		case x509Context := <-s.sidecar.CertReadyChan():
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
