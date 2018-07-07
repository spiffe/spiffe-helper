package main

import (
	"crypto/x509"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/test/util"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"
)

//Creates a Sidecar with a Mocked WorkloadAPIClient and tests that
//running the Sidecar Daemon, when a SVID Response is sent to the
//UpdateChan on the WorkloadAPI client, the PEM files are stored on disk
func TestSidecar_RunDaemon(t *testing.T) {

	tmpdir, err := ioutil.TempDir("", "test-certs")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpdir)

	config := &SidecarConfig{
		Cmd:                "echo",
		CertDir:            tmpdir,
		SvidFileName:       "svid.pem",
		SvidKeyFileName:    "svid_key.pem",
		SvidBundleFileName: "svid_bundle.pem",
	}

	updateMockChan := make(chan *workload.X509SVIDResponse, 1)
	workloadClient := MockWorkloadClient{
		mockChan: updateMockChan,
	}

	sidecar := sidecar{
		config:            config,
		workloadAPIClient: workloadClient,
	}

	go func() {
		err = sidecar.RunDaemon()
		if err != nil {
			panic(err)
		}
	}()

	x509SvidTestResponse := x509SvidResponse(t)

	//send a X509SVIDResponse to Updates channel
	updateMockChan <- x509SvidTestResponse

	//sleep this routine so the dumpBundles on the Sidecar is run
	time.Sleep(1 * time.Millisecond)

	//The expected files
	svidFile := path.Join(tmpdir, config.SvidFileName)
	svidKeyFile := path.Join(tmpdir, config.SvidKeyFileName)
	svidBundleFile := path.Join(tmpdir, config.SvidBundleFileName)

	if _, err := os.Stat(svidFile); os.IsNotExist(err) {
		t.Errorf("svid file was not created: %v", err)
	}

	if _, err := os.Stat(svidKeyFile); os.IsNotExist(err) {
		t.Errorf("svid key file was not created: %v", err)
	}

	if _, err := os.Stat(svidBundleFile); os.IsNotExist(err) {
		t.Errorf("svid bundle file was not created: %v", err)
	}
}

//Tests that when there is no timeout in the config, it uses
//the default timeout set in a constant in the spiffe_helper
func Test_getTimeout_default(t *testing.T) {
	config := &SidecarConfig{}

	expectedTimeout := timeout
	actualTimeout := getTimeout(config)

	if actualTimeout != expectedTimeout {
		t.Errorf("Expected timeout : %v, got %v", expectedTimeout, actualTimeout)
	}
}

//Tests that when there
func Test_getTimeout_custom(t *testing.T) {
	config := &SidecarConfig{
		Timeout: "10s",
	}

	expectedTimeout, _ := time.ParseDuration(config.Timeout)
	actualTimeout := getTimeout(config)

	if actualTimeout != expectedTimeout {
		t.Errorf("Expected timeout : %v, got %v", expectedTimeout, actualTimeout)
	}
}

type MockWorkloadClient struct {
	mockChan chan *workload.X509SVIDResponse
}

func (m MockWorkloadClient) Start() error {
	return nil
}

func (m MockWorkloadClient) Stop() {}

func (m MockWorkloadClient) UpdateChan() <-chan *workload.X509SVIDResponse {
	return m.mockChan
}

// creates a X509SVIDResponse reading test certs from files
func x509SvidResponse(t *testing.T) *workload.X509SVIDResponse {
	svid, key, err := util.LoadSVIDFixture()
	if err != nil {
		t.Errorf("could not load svid fixture: %v", err)
	}
	ca, _, err := util.LoadCAFixture()
	if err != nil {
		t.Errorf("could not load ca fixture: %v", err)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Errorf("could not marshal private key: %v", err)
	}

	svidMsg := &workload.X509SVID{
		SpiffeId:    "spiffe://example.org/foo",
		X509Svid:    svid.Raw,
		X509SvidKey: keyData,
		Bundle:      ca.Raw,
	}
	return &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{svidMsg},
	}
}
