package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	workload "github.com/spiffe/sidecar/wlapi"
	//workload "github.com/spiffe/spire/pkg/api/workload"
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
		pk, crt, ttl, err := s.dumpBundles()
		if err != nil {
			return err
		}
		err = s.signalProcess(pk, crt)
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

func (s *Sidecar) signalProcess(pk, crt string) (err error) {
	// TODO: generalize this for any process, not just Ghostunnel
	if !s.processRunning {
		// Start Ghostunnel
		args := fmt.Sprintf("%s --keystore %s --cacert %s", s.config.GhostunnelArgs, pk, crt)
		cmd := exec.Command(s.config.GhostunnelCmd, strings.Split(args, " ")...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			return
		}
		s.process = cmd.Process
		go s.checkProcessExit()
	} else {
		// Signal Ghostunnel to reload certs
		err = s.process.Signal(syscall.SIGUSR1)
		if err != nil {
			return
		}
	}

	return
}

func (s *Sidecar) checkProcessExit() {
	s.processRunning = true
	s.process.Wait()
	s.processRunning = false
}

func convertToPem(format string, in []byte) (out []byte, err error) {
	// TODO: Use Golang library to make this conversion
	fin, err := ioutil.TempFile("", "")
	if err != nil {
		return
	}
	defer os.Remove(fin.Name())
	fin.Write(in)
	fin.Close()

	fout, err := ioutil.TempFile("", "")
	if err != nil {
		return
	}
	defer os.Remove(fout.Name())
	fin.Close()

	cmd := exec.Command("openssl", format, "-inform", "der", "-in", fin.Name(), "-out", fout.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return
	}
	cmd.Wait()
	out, err = ioutil.ReadFile(fout.Name())
	return
}

func (s *Sidecar) dumpBundles() (pk, crt string, ttl int32, err error) {
	bundles, err := s.workloadClient.FetchAllBundles(s.workloadClientContext, &workload.Empty{})
	if err != nil {
		return
	}

	if len(bundles.Bundles) == 0 {
		err = errors.New("Fetched zero bundles")
		return
	}

	ttl = bundles.Ttl

	log("Writing %d bundles!\n", len(bundles.Bundles))
	for index, bundle := range bundles.Bundles {
		pkFilename := fmt.Sprintf("%s/%d.key", s.config.CertDir, index)
		certFilename := fmt.Sprintf("%s/%d.cert", s.config.CertDir, index)
		if index == 0 {
			pk = pkFilename
			crt = certFilename
		}

		log("Writing keystore #%d...\n", index+1)
		var svidPrivateKey, svid, svidBundle []byte
		svidPrivateKey, err = convertToPem("ec", bundle.SvidPrivateKey)
		if err != nil {
			return
		}
		svid, err = convertToPem("x509", bundle.Svid)
		if err != nil {
			return
		}
		keystore := append(svidPrivateKey, svid...)
		err = ioutil.WriteFile(pkFilename, keystore, os.ModePerm)
		if err != nil {
			return
		}

		log("Writing CA certs #%d...\n", index+1)
		svidBundle, err = convertToPem("x509", bundle.SvidBundle)
		if err != nil {
			return
		}
		err = ioutil.WriteFile(certFilename, svidBundle, os.ModePerm)
		if err != nil {
			return
		}
	}
	return
}

func log(format string, a ...interface{}) {
	fmt.Print(time.Now().Format(time.Stamp), ": ")
	fmt.Printf(format, a...)
}
