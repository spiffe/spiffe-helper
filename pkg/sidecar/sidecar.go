package sidecar

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/pkg/disk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Sidecar is the component that consumes the Workload API and renews certs
// implements the interface Sidecar
type Sidecar struct {
	config         *Config
	client         *workloadapi.Client
	jwtSource      *workloadapi.JWTSource
	processRunning int32
	process        *os.Process
	certReadyChan  chan struct{}
}

// New creates a new SPIFFE sidecar
func New(config *Config) *Sidecar {
	return &Sidecar{
		config:        config,
		certReadyChan: make(chan struct{}, 1),
	}
}

// RunDaemon starts the main loop
// Starts the workload API client to listen for new SVID updates
// When a new SVID is received on the updateChan, the SVID certificates
// are stored in disk and a restart signal is sent to the proxy's process
func (s *Sidecar) RunDaemon(ctx context.Context) error {
	var wg sync.WaitGroup

	if err := s.setupClients(ctx); err != nil {
		return err
	}
	if s.client != nil {
		defer s.client.Close()
	}
	if s.jwtSource != nil {
		defer s.jwtSource.Close()
	}

	if s.x509Enabled() {
		s.config.Log.Info("Watching for X509 Context")
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.client.WatchX509Context(ctx, &x509Watcher{sidecar: s})
			if err != nil && status.Code(err) != codes.Canceled {
				s.config.Log.Fatalf("Error watching X.509 context: %v", err)
			}
		}()
	}

	if s.jwtBundleEnabled() {
		s.config.Log.Info("Watching for JWT Bundles")
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.client.WatchJWTBundles(ctx, &JWTBundlesWatcher{sidecar: s})
			if err != nil && status.Code(err) != codes.Canceled {
				s.config.Log.Fatalf("Error watching JWT bundle updates: %v", err)
			}
		}()
	}

	if s.jwtSVIDsEnabled() {
		for _, jwtConfig := range s.config.JWTSVIDs {
			jwtConfig := jwtConfig
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.updateJWTSVID(ctx, jwtConfig.JWTAudience, jwtConfig.JWTSVIDFilename)
			}()
		}
	}

	wg.Wait()

	return nil
}

func (s *Sidecar) Run(ctx context.Context) error {
	if err := s.setupClients(ctx); err != nil {
		return err
	}
	if s.client != nil {
		defer s.client.Close()
	}
	if s.jwtSource != nil {
		defer s.jwtSource.Close()
	}

	if s.x509Enabled() {
		s.config.Log.Debug("Fetching x509 certificates")
		if err := s.fetchAndWriteX509Context(ctx); err != nil {
			s.config.Log.WithError(err).Error("Error fetching x509 certificates")
			return err
		}
		s.config.Log.Info("Successfully fetched x509 certificates")
	}

	if s.jwtBundleEnabled() {
		s.config.Log.Debug("Fetching JWT Bundle")
		if err := s.fetchAndWriteJWTBundle(ctx); err != nil {
			s.config.Log.WithError(err).Error("Error fetching JWT bundle")
			return err
		}
		s.config.Log.Info("Successfully fetched JWT bundle")
	}

	if s.jwtSVIDsEnabled() {
		s.config.Log.Debug("Fetching JWT SVIDs")
		if err := s.fetchAndWriteJWTSVIDs(ctx); err != nil {
			s.config.Log.WithError(err).Error("Error fetching JWT SVIDs")
			return err
		}
		s.config.Log.Info("Successfully fetched JWT SVIDs")
	}

	return nil
}

// CertReadyChan returns a channel to know when the certificates are ready
func (s *Sidecar) CertReadyChan() <-chan struct{} {
	return s.certReadyChan
}

func (s *Sidecar) setupClients(ctx context.Context) error {
	if s.x509Enabled() || s.jwtBundleEnabled() {
		client, err := workloadapi.New(ctx, s.getWorkloadAPIAdress())
		if err != nil {
			return err
		}
		s.client = client
	}

	if s.jwtSVIDsEnabled() {
		jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(s.getWorkloadAPIAdress()))
		if err != nil {
			return err
		}
		s.jwtSource = jwtSource
	}

	return nil
}

// updateCertificates Updates the certificates stored in disk and signal the Process to restart
func (s *Sidecar) updateCertificates(svidResponse *workloadapi.X509Context) {
	s.config.Log.Debug("Updating X.509 certificates")
	if err := disk.WriteX509Context(svidResponse, s.config.AddIntermediatesToBundle, s.config.IncludeFederatedDomains, s.config.CertDir, s.config.SVIDFileName, s.config.SVIDKeyFileName, s.config.SVIDBundleFileName, s.config.CertFileMode, s.config.KeyFileMode); err != nil {
		s.config.Log.WithError(err).Error("Unable to dump bundle")
		return
	}
	s.config.Log.Info("X.509 certificates updated")

	if s.config.Cmd != "" {
		if err := s.signalProcess(); err != nil {
			s.config.Log.WithError(err).Error("Unable to signal process")
		}
	}

	select {
	case s.certReadyChan <- struct{}{}:
	default:
	}
}

// signalProcess sends the configured Renew signal to the process running the proxy
// to reload itself so that the proxy uses the new SVID
func (s *Sidecar) signalProcess() (err error) {
	// TODO: is ReloadExternalProcess still used?
	switch s.config.ReloadExternalProcess {
	case nil:
		if atomic.LoadInt32(&s.processRunning) == 0 {
			cmdArgs, err := getCmdArgs(s.config.CmdArgs)
			if err != nil {
				return fmt.Errorf("error parsing cmd arguments: %w", err)
			}

			cmd := exec.Command(s.config.Cmd, cmdArgs...) // #nosec
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Start()
			if err != nil {
				return fmt.Errorf("error executing process: %v\n%w", s.config.Cmd, err)
			}
			s.process = cmd.Process
			go s.checkProcessExit()
		} else {
			if err := s.SignalProcess(); err != nil {
				return err
			}
		}

	default:
		if err = s.config.ReloadExternalProcess(); err != nil {
			return fmt.Errorf("error reloading external process: %w", err)
		}
	}

	return nil
}

func (s *Sidecar) checkProcessExit() {
	atomic.StoreInt32(&s.processRunning, 1)
	_, err := s.process.Wait()
	if err != nil {
		s.config.Log.Errorf("error waiting for process exit: %v", err)
	}

	atomic.StoreInt32(&s.processRunning, 0)
}

func (s *Sidecar) fetchJWTSVIDs(ctx context.Context, jwtAudience string) (*jwtsvid.SVID, error) {
	jwtSVID, err := s.jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: jwtAudience})
	if err != nil {
		s.config.Log.Errorf("Unable to fetch JWT SVID: %v", err)
		return nil, err
	}

	_, err = jwtsvid.ParseAndValidate(jwtSVID.Marshal(), s.jwtSource, []string{jwtAudience})
	if err != nil {
		s.config.Log.Errorf("Unable to parse or validate token: %v", err)
		return nil, err
	}

	return jwtSVID, nil
}

func createRetryIntervalFunc() func() time.Duration {
	const (
		initialBackoff = 1 * time.Second
		maxBackoff     = 60 * time.Second
		multiplier     = 2
	)
	backoffInterval := initialBackoff
	return func() time.Duration {
		currentBackoff := backoffInterval
		// Update backoffInterval for next call, capped at maxBackoff
		backoffInterval *= multiplier
		if backoffInterval > maxBackoff {
			backoffInterval = maxBackoff
		}
		return currentBackoff
	}
}

func getRefreshInterval(svid *jwtsvid.SVID) time.Duration {
	return time.Until(svid.Expiry)/2 + time.Second
}

func (s *Sidecar) performJWTSVIDUpdate(ctx context.Context, jwtAudience string, jwtSVIDFilename string) (*jwtsvid.SVID, error) {
	s.config.Log.Debug("Updating JWT SVID")

	jwtSVID, err := s.fetchJWTSVIDs(ctx, jwtAudience)
	if err != nil {
		s.config.Log.Errorf("Unable to update JWT SVID: %v", err)
		return nil, err
	}

	if err = disk.WriteJWTSVID(jwtSVID, s.config.CertDir, jwtSVIDFilename, s.config.JWTSVIDFileMode); err != nil {
		s.config.Log.Errorf("Unable to update JWT SVID: %v", err)
		return nil, err
	}

	s.config.Log.Info("JWT SVID updated")
	return jwtSVID, nil
}

func (s *Sidecar) updateJWTSVID(ctx context.Context, jwtAudience string, jwtSVIDFilename string) {
	retryInterval := createRetryIntervalFunc()
	var initialInterval time.Duration
	jwtSVID, err := s.performJWTSVIDUpdate(ctx, jwtAudience, jwtSVIDFilename)
	if err != nil {
		// If the first update fails, use the retry interval
		initialInterval = retryInterval()
	} else {
		// If the update succeeds, use the refresh interval
		initialInterval = getRefreshInterval(jwtSVID)
	}
	ticker := time.NewTicker(initialInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			jwtSVID, err = s.performJWTSVIDUpdate(ctx, jwtAudience, jwtSVIDFilename)
			if err == nil {
				retryInterval = createRetryIntervalFunc()
				ticker.Reset(getRefreshInterval(jwtSVID))
			} else {
				ticker.Reset(retryInterval())
			}
		}
	}
}

func (s *Sidecar) x509Enabled() bool {
	return s.config.SVIDFileName != "" && s.config.SVIDKeyFileName != "" && s.config.SVIDBundleFileName != ""
}

func (s *Sidecar) jwtBundleEnabled() bool {
	return s.config.JWTBundleFilename != ""
}

func (s *Sidecar) jwtSVIDsEnabled() bool {
	return len(s.config.JWTSVIDs) > 0
}

// x509Watcher is a sample implementation of the workload.X509SVIDWatcher interface
type x509Watcher struct {
	sidecar *Sidecar
}

// OnX509ContextUpdate is run every time an SVID is updated
func (w x509Watcher) OnX509ContextUpdate(svids *workloadapi.X509Context) {
	for _, svid := range svids.SVIDs {
		w.sidecar.config.Log.WithField("spiffe_id", svid.ID).Info("Received update")
	}

	w.sidecar.updateCertificates(svids)
}

// OnX509ContextWatchError is run when the client runs into an error
func (w x509Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		w.sidecar.config.Log.Errorf("Error while watching x509 context: %v", err)
	}
}

// getCmdArgs receives the command line arguments as a string
// and split it at spaces, except when the space is inside quotation marks
func getCmdArgs(args string) ([]string, error) {
	if args == "" {
		return []string{}, nil
	}

	r := csv.NewReader(strings.NewReader(args))
	r.Comma = ' ' // space
	cmdArgs, err := r.Read()
	if err != nil {
		return nil, err
	}

	return cmdArgs, nil
}

// JWTBundleWatcher is an implementation of workload.JWTBundleWatcher interface
type JWTBundlesWatcher struct {
	sidecar *Sidecar
}

// OnJWTBundlesUpdate is ran every time a bundle is updated
func (w JWTBundlesWatcher) OnJWTBundlesUpdate(jwkSet *jwtbundle.Set) {
	w.sidecar.config.Log.Debug("Updating JWT bundle")
	if err := disk.WriteJWTBundleSet(jwkSet, w.sidecar.config.CertDir, w.sidecar.config.JWTBundleFilename, w.sidecar.config.JWTBundleFileMode); err != nil {
		w.sidecar.config.Log.Errorf("Error writing JWT Bundle to disk: %v", err)
		return
	}

	w.sidecar.config.Log.Info("JWT bundle updated")
}

// OnJWTBundlesWatchError is ran when the client runs into an error
func (w JWTBundlesWatcher) OnJWTBundlesWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		w.sidecar.config.Log.Errorf("Error while watching JWT bundles: %v", err)
	}
}
