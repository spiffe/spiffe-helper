package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/spire/proto/api/workload"
)

// Sidecar is the component that consumes Workload API and renews certs
type Sidecar struct {
	config                *SidecarConfig
	workloadClient        workload.WorkloadClient
	workloadClientContext context.Context
	processRunning        bool
	process               *os.Process
}

// NewSidecar creates a new sidecar
func NewSidecar(workloadClientContext context.Context, config *SidecarConfig, workloadClient workload.WorkloadClient) *Sidecar {
	return &Sidecar{
		workloadClientContext: workloadClientContext,
		config:                config,
		workloadClient:        workloadClient,
	}
}

// RunDaemon starts the main loop
func (s *Sidecar) RunDaemon() error {
	// Create channel for interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Main loop
	for {
		// Fetch and dump certificates
		ttl, err := s.dumpBundles()
		if err != nil {
			return err
		}
		err = s.signalProcess()
		if err != nil {
			return err
		}

		// Create timer for TTL/2
		timer := time.NewTimer(time.Second * time.Duration(ttl/2))

		// Wait for either timer or interrupt signal
		log("Will wait for TTL/2 (%d seconds)\n", ttl/2)
		select {
		case <-timer.C:
			log("Time is up! Will renew cert.\n")
			// Continue
		case <-interrupt:
			log("Interrupted! Will exit.\n")
			return nil
		}
	}
}

func (s *Sidecar) signalProcess() (err error) {
	if !s.processRunning {
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

func (s *Sidecar) checkProcessExit() {
	s.processRunning = true
	s.process.Wait()
	s.processRunning = false
}

func (s *Sidecar) dumpBundles() (ttl int32, err error) {
	bundles, err := s.workloadClient.FetchAllBundles(s.workloadClientContext, &workload.Empty{})
	if err != nil {
		return ttl, err
	}

	if len(bundles.Bundles) == 0 {
		return ttl, errors.New("fetched zero bundles")
	}

	ttl = bundles.Ttl
	log("TTL is: %v seconds\n", ttl)
	log("Bundles found: %d\n", len(bundles.Bundles))

	if len(bundles.Bundles) > 1 {
		log("Only certificates from the first bundle will be written")
	}

	// There may be more than one bundle, but we are interested in the first one only
	bundle := bundles.Bundles[0]

	svidKeyFile := path.Join(s.config.CertDir, s.config.SvidKeyFileName)
	svidFile := path.Join(s.config.CertDir, s.config.SvidFileName)
	svidBundleFile := path.Join(s.config.CertDir, s.config.SvidBundleFileName)

	svidPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: bundle.SvidPrivateKey})

	svid := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bundle.Svid})

	log("Writing: %v\n", svidKeyFile)
	err = ioutil.WriteFile(svidKeyFile, append(svidPrivateKey, svid...), os.ModePerm)
	if err != nil {
		return ttl, fmt.Errorf("error writing file: %v\n%v", svidKeyFile, err)
	}

	log("Writing: %v\n", svidFile)
	err = ioutil.WriteFile(svidFile, svid, os.ModePerm)
	if err != nil {
		return ttl, fmt.Errorf("error writing file: %v\n%v", svidFile, err)
	}

	svidBundle := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bundle.SvidBundle,
		})

	log("Writing: %v\n", svidBundleFile)
	err = ioutil.WriteFile(svidBundleFile, svidBundle, os.ModePerm)
	if err != nil {
		return ttl, fmt.Errorf("error writing file: %v\n%v", svidBundleFile, err)
	}

	return ttl, nil
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

func log(format string, a ...interface{}) {
	fmt.Print(time.Now().Format(time.Stamp), ": ")
	fmt.Printf(format, a...)
}
