package sidecar

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	pb "github.com/spiffe/spiffe-helper/pkg/notifier"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	certsFileMode       = os.FileMode(0644)
	keyFileMode         = os.FileMode(0600)
	defaultAgentAddress = "/tmp/spire-agent/public/api.sock"
)

// Sidecar is the component that consumes the Workload API and renews certs
// implements the interface Sidecar
type Sidecar struct {
	config         *Config
	jwtSource      *workloadapi.JWTSource
	processRunning int32
	process        *os.Process
	certReadyChan  chan struct{}
	plugins        map[string]*pb.NotifierServer
	ctx            context.Context
}

// New creates a new SPIFFE sidecar
func New(ctx context.Context, configPath string, log logrus.FieldLogger) (*Sidecar, error) {
	config, err := ParseConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %w", configPath, err)
	}

	if log == nil {
		log = logrus.New()
	}
	config.Log = log

	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if config.AgentAddress == "" {
		config.AgentAddress = os.Getenv("SPIRE_AGENT_ADDRESS")
		if config.AgentAddress == "" {
			config.AgentAddress = defaultAgentAddress
		}
	}

	config.Log.WithField("agent_address", config.AgentAddress).Info("Connecting to agent")
	if config.Cmd == "" {
		config.Log.Warn("No cmd defined to execute.")
	}

	sidecar := &Sidecar{
		ctx:           ctx,
		config:        config,
		certReadyChan: make(chan struct{}, 1),
		plugins:       make(map[string]*pb.NotifierServer),
	}
	sidecar.loadPlugins()

	return sidecar, nil
}

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
				s.config.Log.Fatalf("Error watching X.509 context: %v", err)
			}
		}()
	}

	if s.config.JWTBundleFilename != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := workloadapi.WatchJWTBundles(ctx, &JWTBundlesWatcher{sidecar: s}, s.getWorkloadAPIAdress())
			if err != nil && status.Code(err) != codes.Canceled {
				s.config.Log.Fatalf("Error watching JWT bundle updates: %v", err)
			}
		}()
	}

	if s.config.JWTSvidFilename != "" && s.config.JWTAudience != "" {
		jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(s.getWorkloadAPIAdress()))
		if err != nil {
			s.config.Log.Fatalf("Error watching JWT svid updates: %v", err)
		}
		s.jwtSource = jwtSource
		defer s.jwtSource.Close()

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.updateJWTSVID(ctx)
		}()
	}

	wg.Wait()

	return nil
}

// CertReadyChan returns a channel to know when the certificates are ready
func (s *Sidecar) CertReadyChan() <-chan struct{} {
	return s.certReadyChan
}

// updateCertificates Updates the certificates stored in disk and signal the Process to restart
func (s *Sidecar) updateCertificates(svidResponse *workloadapi.X509Context) {
	s.config.Log.Debug("Updating X.509 certificates")
	err := s.dumpBundles(svidResponse)
	if err != nil {
		s.config.Log.WithError(err).Error("Unable to dump bundle")
		return
	}
	s.config.Log.Info("X.509 certificates updated")
	s.notifyX509Update()

	if s.config.Cmd != "" {
		if err := s.signalProcess(); err != nil {
			s.config.Log.WithError(err).Error("Unable to signal process")
		}
	}

	if s.config.ExitWhenReady {
		os.Exit(0)
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

func (s *Sidecar) loadPlugins() {
	for pluginName, pluginConfig := range s.config.Plugins {
		pluginPath := pluginConfig["path"]
		if pluginPath == "" {
			s.config.Log.Warnf("Please provide a path for plugin %s", pluginName)
			continue
		}

		checksum := pluginConfig["checksum"]
		if checksum == "" {
			s.config.Log.Warnf("Please provide a checksum for plugin %s", pluginName)
			continue
		}

		if _, typeIsPresent := pluginConfig["type"]; typeIsPresent {
			s.config.Log.Warnf("Please update the configuration for plugin %s, type is a reserved configuration name", pluginName)
			continue
		}

		secureConfig, err := pb.GetSecureConfig(checksum)
		if err != nil {
			s.config.Log.Warnf("Error while trying to create secure config for plugin %s", pluginName)
			continue
		}

		request := &pb.LoadConfigsRequest{}
		request.Configs = pluginConfig
		request.Configs["cert_dir"] = s.config.CertDir
		request.Configs["add_intermediates_to_bundle"] = strconv.FormatBool(s.config.AddIntermediatesToBundle)
		request.Configs["svid_file_name"] = s.config.SvidFileName
		request.Configs["svid_key_file_name"] = s.config.SvidKeyFileName
		request.Configs["svid_bundle_file_name"] = s.config.SvidBundleFileName
		request.Configs["jwt_audience"] = s.config.JWTAudience
		request.Configs["jwt_svid_file_name"] = s.config.JWTSvidFilename
		request.Configs["jwt_bundle_file_name"] = s.config.JWTBundleFilename

		client := plugin.NewClient(&plugin.ClientConfig{
			HandshakeConfig:  pb.GetHandshakeConfig(),
			Plugins:          pb.GetPluginMap(),
			Cmd:              exec.Command(pluginPath),
			AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
			SecureConfig:     secureConfig,
		})

		RPCClient, err := client.Client()
		if err != nil {
			s.config.Log.Warn(err)
			continue
		}

		raw, err := RPCClient.Dispense("plugin")
		if err != nil {
			s.config.Log.Warn(err)
			continue
		}

		notifier := raw.(pb.NotifierServer)
		response, err := notifier.LoadConfigs(s.ctx, request)
		if err != nil {
			s.config.Log.Warnf("Failed to load configs into plugin %s", pluginName)
			continue
		}

		s.plugins[pluginName] = &notifier

		s.config.Log.Infof("Plugin %s loaded %s", pluginName, response)
	}
}

func (s *Sidecar) checkProcessExit() {
	atomic.StoreInt32(&s.processRunning, 1)
	_, err := s.process.Wait()
	if err != nil {
		s.config.Log.Errorf("error waiting for process exit: %v", err)
	}

	atomic.StoreInt32(&s.processRunning, 0)
}

func (s *Sidecar) notifyX509Update() {
	for pluginName := range s.plugins {
		plugin := *s.plugins[pluginName]
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()
		_, err := plugin.UpdateX509SVID(ctx, &pb.UpdateX509SVIDRequest{})
		if err != nil {
			s.config.Log.Warnf("Failed to update x509 svid to plugin %s", pluginName)
			continue
		}
	}
}

func (s *Sidecar) notifyJWTSVIDUpdate() {
	for pluginName := range s.plugins {
		plugin := *s.plugins[pluginName]
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()
		_, err := plugin.UpdateJWTSVID(ctx, &pb.UpdateJWTSVIDRequest{})
		if err != nil {
			s.config.Log.Warnf("Failed to update jwt svid to plugin %s", pluginName)
			continue
		}
	}
}

func (s *Sidecar) notifyJWTBundleUpdate() {
	for pluginName := range s.plugins {
		plugin := *s.plugins[pluginName]
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()
		_, err := plugin.UpdateJWTBundle(ctx, &pb.UpdateJWTBundleRequest{})
		if err != nil {
			s.config.Log.Warnf("Failed to update jwt bundle to plugin %s", pluginName)
			continue
		}
	}
}

// dumpBundles takes a X509SVIDResponse, representing a svid message from
// the Workload API, and calls writeCerts and writeKey to write to disk
// the svid, key and bundle of certificates.
// It is possible to change output setting `addIntermediatesToBundle` as true.
func (s *Sidecar) dumpBundles(svidResponse *workloadapi.X509Context) error {
	// There may be more than one certificate, but we are interested in the first one only
	svid := svidResponse.DefaultSVID()

	svidFile := path.Join(s.config.CertDir, s.config.SvidFileName)
	svidKeyFile := path.Join(s.config.CertDir, s.config.SvidKeyFileName)
	svidBundleFile := path.Join(s.config.CertDir, s.config.SvidBundleFileName)

	certs := svid.Certificates
	bundleSet, found := svidResponse.Bundles.Get(svid.ID.TrustDomain())
	if !found {
		return fmt.Errorf("no bundles found for %s trust domain", svid.ID.TrustDomain().String())
	}
	bundles := bundleSet.X509Authorities()
	privateKey, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	if err != nil {
		return err
	}

	// Add intermediates into bundles, and remove them from certs
	if s.config.AddIntermediatesToBundle {
		bundles = append(bundles, certs[1:]...)
		certs = []*x509.Certificate{certs[0]}
	}

	if err := writeCerts(svidFile, certs); err != nil {
		return err
	}

	if err := writeKey(svidKeyFile, privateKey); err != nil {
		return err
	}

	if err := writeCerts(svidBundleFile, bundles); err != nil {
		return err
	}

	return nil
}

func (s *Sidecar) writeJSON(fileName string, certs map[string]interface{}) error {
	file, err := json.Marshal(certs)
	if err != nil {
		return err
	}

	jsonPath := path.Join(s.config.CertDir, fileName)
	if err = os.WriteFile(jsonPath, file, os.ModePerm); err != nil {
		return err
	}

	return nil
}

func (s *Sidecar) updateJWTBundle(jwkSet *jwtbundle.Set) {
	s.config.Log.Debug("Updating JWT bundle")

	bundles := make(map[string]interface{})
	for _, bundle := range jwkSet.Bundles() {
		bytes, err := bundle.Marshal()
		if err != nil {
			s.config.Log.Errorf("Unable to marshal JWT bundle: %v", err)
			continue
		}
		bundles[bundle.TrustDomain().Name()] = base64.StdEncoding.EncodeToString(bytes)
	}

	if err := s.writeJSON(s.config.JWTBundleFilename, bundles); err != nil {
		s.config.Log.Errorf("Unable to write JSON file: %v", err)
	} else {
		s.config.Log.Info("JWT bundle updated")
		s.notifyJWTBundleUpdate()
	}
}

func (s *Sidecar) fetchJWTSVID(ctx context.Context) (*jwtsvid.SVID, error) {
	jwtSVID, err := s.jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: s.config.JWTAudience})
	if err != nil {
		s.config.Log.Errorf("Unable to fetch JWT SVID: %v", err)
		return nil, err
	}

	_, err = jwtsvid.ParseAndValidate(jwtSVID.Marshal(), s.jwtSource, []string{s.config.JWTAudience})
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

func (s *Sidecar) performJWTSVIDUpdate(ctx context.Context) (*jwtsvid.SVID, error) {
	s.config.Log.Debug("Updating JWT SVID")

	jwtSVID, err := s.fetchJWTSVID(ctx)
	if err != nil {
		s.config.Log.Errorf("Unable to update JWT SVID: %v", err)
		return nil, err
	}

	filePath := path.Join(s.config.CertDir, s.config.JWTSvidFilename)
	if err = os.WriteFile(filePath, []byte(jwtSVID.Marshal()), os.ModePerm); err != nil {
		s.config.Log.Errorf("Unable to update JWT SVID: %v", err)
		return nil, err
	}

	s.config.Log.Info("JWT SVID updated")
	s.notifyJWTSVIDUpdate()

	return jwtSVID, nil
}

func (s *Sidecar) updateJWTSVID(ctx context.Context) {
	retryInterval := createRetryIntervalFunc()
	var initialInterval time.Duration
	jwtSVID, err := s.performJWTSVIDUpdate(ctx)
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
			jwtSVID, err = s.performJWTSVIDUpdate(ctx)
			if err == nil {
				retryInterval = createRetryIntervalFunc()
				ticker.Reset(getRefreshInterval(jwtSVID))
			} else {
				ticker.Reset(retryInterval())
			}
		}
	}
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

// writeCerts takes an array of certificates,
// and encodes them as PEM blocks, writing them to file
func writeCerts(file string, certs []*x509.Certificate) error {
	var pemData []byte
	for _, cert := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return os.WriteFile(file, pemData, certsFileMode)
}

// writeKey takes a private key as a slice of bytes,
// formats as PEM, and writes it to file
func writeKey(file string, data []byte) error {
	b := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	}

	return os.WriteFile(file, pem.EncodeToMemory(b), keyFileMode)
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
	w.sidecar.updateJWTBundle(jwkSet)
}

// OnJWTBundlesWatchError is ran when the client runs into an error
func (w JWTBundlesWatcher) OnJWTBundlesWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		w.sidecar.config.Log.Errorf("Error while watching JWT bundles: %v", err)
	}
}
