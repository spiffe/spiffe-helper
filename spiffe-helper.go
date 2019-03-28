package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/apex/log"
	"github.com/pkg/errors"
	"github.com/spiffe/spire/api/workload"
	proto "github.com/spiffe/spire/proto/api/workload"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// sidecar is the component that consumes the Workload API and renews certs
// implements the interface Sidecar
type sidecar struct {
	config            *SidecarConfig
	processRunning    int32
	process           *os.Process
	workloadAPIClient workload.X509Client
}

const (
	// default timeout Duration for the workloadAPI client when the defaultTimeout
	// is not configured in the .conf file
	defaultTimeout = time.Duration(5 * time.Second)

	certsFileMode = os.FileMode(0644)
	keyFileMode   = os.FileMode(0600)
)

// NewSidecar creates a new sidecar
func NewSidecar(config *SidecarConfig) (*sidecar, error) {
	timeout, err := getTimeout(config)
	if err != nil {
		return nil, err
	}

	return &sidecar{
		config:            config,
		workloadAPIClient: newWorkloadAPIClient(config.AgentAddress, timeout),
	}, nil
}

// RunDaemon starts the main loop
// Starts the workload API client to listen for new SVID updates
// When a new SVID is received on the updateChan, the SVID certificates
// are stored in disk and a restart signal is sent to the proxy's process
func (s *sidecar) RunDaemon(ctx context.Context) error {
	// Create channel for interrupt signal
	interrupt := make(chan os.Signal, 1)
	errorChan := make(chan error, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	updateChan := s.workloadAPIClient.UpdateChan()

	//start the workloadAPIClient
	go func() {
		err := s.workloadAPIClient.Start()
		if err != nil {
			log.Error(err.Error())
			errorChan <- err
		}
	}()
	defer s.workloadAPIClient.Stop()

	for {
		select {
		case svidResponse := <-updateChan:
			updateCertificates(s, svidResponse)
		case <-interrupt:
			return nil
		case err := <-errorChan:
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

// Updates the certificates stored in disk and signal the Process to restart
func updateCertificates(s *sidecar, svidResponse *proto.X509SVIDResponse) {
	err := s.dumpBundles(svidResponse)
	if err != nil {
		log.Error(err.Error())
		return
	}
	err = s.signalProcess()
	if err != nil {
		log.Error(err.Error())
	}
}

//newWorkloadAPIClient creates a workload.X509Client
func newWorkloadAPIClient(agentAddress string, timeout time.Duration) workload.X509Client {
	addr := &net.UnixAddr{
		Net:  "unix",
		Name: agentAddress,
	}
	config := &workload.X509ClientConfig{
		Addr:    addr,
		Timeout: timeout,
	}
	return workload.NewX509Client(config)
}

//signalProcess sends the configured Renew signal to the process running the proxy
//to reload itself so that the proxy uses the new SVID
func (s *sidecar) signalProcess() (err error) {
	if atomic.LoadInt32(&s.processRunning) == 0 {
		cmd := exec.Command(s.config.Cmd, strings.Split(s.config.CmdArgs, " ")...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("error executing process: %v\n%v", s.config.Cmd, err)
		}
		s.process = cmd.Process
		go s.checkProcessExit()
	} else {
		// Signal to reload certs
		sig, err := getSignal(s.config.RenewSignal)
		if err != nil {
			return fmt.Errorf("error getting signal: %v\n%v", s.config.RenewSignal, err)
		}

		err = s.process.Signal(sig)
		if err != nil {
			return fmt.Errorf("error signaling process with signal: %v\n%v", sig, err)
		}
	}

	return nil
}

func (s *sidecar) checkProcessExit() {
	atomic.StoreInt32(&s.processRunning, 1)
	s.process.Wait()
	atomic.StoreInt32(&s.processRunning, 0)
}

//dumpBundles takes a X509SVIDResponse, representing a svid message from
//the Workload API, and calls writeCerts and writeKey to write to disk
//the svid, key and bundle of certificates
func (s *sidecar) dumpBundles(svidResponse *proto.X509SVIDResponse) error {

	// There may be more than one certificate, but we are interested in the first one only
	svid := svidResponse.Svids[0]

	svidFile := path.Join(s.config.CertDir, s.config.SvidFileName)
	svidKeyFile := path.Join(s.config.CertDir, s.config.SvidKeyFileName)
	svidBundleFile := path.Join(s.config.CertDir, s.config.SvidBundleFileName)

	err := s.writeCerts(svidFile, svid.X509Svid)
	if err != nil {
		return err
	}

	err = s.writeKey(svidKeyFile, svid.X509SvidKey)
	if err != nil {
		return err
	}

	err = s.writeCerts(svidBundleFile, svid.Bundle)
	if err != nil {
		return err
	}

	return nil
}

// writeCerts takes a slice of bytes, which may contain multiple certificates,
// and encodes them as PEM blocks, writing them to file
func (s *sidecar) writeCerts(file string, data []byte) error {
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return err
	}

	pemData := []byte{}
	for _, cert := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return ioutil.WriteFile(file, pemData, certsFileMode)
}

// writeKey takes a private key as a slice of bytes,
// formats as PEM, and writes it to file
func (s *sidecar) writeKey(file string, data []byte) error {
	b := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	}

	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, keyFileMode)
	if err != nil {
		return err
	}

	_, err = f.Write(pem.EncodeToMemory(b))
	if err != nil {
		err1 := f.Close()
		if err1 != nil {
			return errors.Wrap(err1, err.Error())
		}
		return err
	}

	err = f.Close()
	return err
}

// parses a time.Duration from the the SidecarConfig,
// if there's an error during parsing, maybe because
// it's not well defined or not defined at all in the
// config, returns the defaultTimeout constant
func getTimeout(config *SidecarConfig) (time.Duration, error) {
	if config.Timeout == "" {
		return defaultTimeout, nil
	}

	t, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return 0, err
	}
	return t, nil
}

func getSignal(s string) (sig syscall.Signal, err error) {
	switch s {
	case "SIGABRT":
		sig = syscall.SIGABRT
	case "SIGALRM":
		sig = syscall.SIGALRM
	case "SIGBUS":
		sig = syscall.SIGBUS
	case "SIGCHLD":
		sig = syscall.SIGCHLD
	case "SIGCONT":
		sig = syscall.SIGCONT
	case "SIGFPE":
		sig = syscall.SIGFPE
	case "SIGHUP":
		sig = syscall.SIGHUP
	case "SIGILL":
		sig = syscall.SIGILL
	case "SIGIO":
		sig = syscall.SIGIO
	case "SIGIOT":
		sig = syscall.SIGIOT
	case "SIGKILL":
		sig = syscall.SIGKILL
	case "SIGPIPE":
		sig = syscall.SIGPIPE
	case "SIGPROF":
		sig = syscall.SIGPROF
	case "SIGQUIT":
		sig = syscall.SIGQUIT
	case "SIGSEGV":
		sig = syscall.SIGSEGV
	case "SIGSTOP":
		sig = syscall.SIGSTOP
	case "SIGSYS":
		sig = syscall.SIGSYS
	case "SIGTERM":
		sig = syscall.SIGTERM
	case "SIGTRAP":
		sig = syscall.SIGTRAP
	case "SIGTSTP":
		sig = syscall.SIGTSTP
	case "SIGTTIN":
		sig = syscall.SIGTTIN
	case "SIGTTOU":
		sig = syscall.SIGTTOU
	case "SIGURG":
		sig = syscall.SIGURG
	case "SIGUSR1":
		sig = syscall.SIGUSR1
	case "SIGUSR2":
		sig = syscall.SIGUSR2
	case "SIGVTALRM":
		sig = syscall.SIGVTALRM
	case "SIGWINCH":
		sig = syscall.SIGWINCH
	case "SIGXCPU":
		sig = syscall.SIGXCPU
	case "SIGXFSZ":
		sig = syscall.SIGXFSZ
	default:
		err = fmt.Errorf("unrecognized signal: %v", s)
	}

	return sig, err
}
