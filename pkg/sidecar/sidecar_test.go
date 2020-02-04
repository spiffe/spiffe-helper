package sidecar

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//Creates a Sidecar with a Mocked WorkloadAPIClient and tests that
//running the Sidecar Daemon, when a SVID Response is sent to the
//UpdateChan on the WorkloadAPI client, the PEM files are stored on disk
func TestSidecar_RunDaemon(t *testing.T) {
	// Create root CA
	domain1CA := spiffetest.NewCA(t)
	// Create an intermediate certificate
	domain1Inter := domain1CA.CreateCA()
	domain1Bundle := domain1CA.Roots()

	// Svid with intermediate
	svidChainWithIntermediate, svidKeyWithIntermediate := domain1Inter.CreateX509SVID("spiffe://example.test/workloadWithIntermediate")
	require.Len(t, svidChainWithIntermediate, 2)

	// Add cert with intermediate into an svid
	svidWithIntermediate := []spiffetest.X509SVID{
		{
			CertChain: svidChainWithIntermediate,
			Key:       svidKeyWithIntermediate,
		},
	}

	// Concat bundles with intermediate certificate
	bundleWithIntermediate := domain1CA.Roots()
	bundleWithIntermediate = append(bundleWithIntermediate, svidChainWithIntermediate[1:]...)

	// Create a single svid without intermediate
	svidChain, svidKey := domain1CA.CreateX509SVID("spiffe://example.test/workload")
	require.Len(t, svidChain, 1)
	svid := []spiffetest.X509SVID{
		{
			CertChain: svidChain,
			Key:       svidKey,
		},
	}

	tmpdir, err := ioutil.TempDir("", "sidecar-run-daemon")
	require.NoError(t, err)

	defer os.RemoveAll(tmpdir)

	config := &Config{
		Cmd:                "echo",
		CertDir:            tmpdir,
		SvidFileName:       "svid.pem",
		SvidKeyFileName:    "svid_key.pem",
		SvidBundleFileName: "svid_bundle.pem",
	}

	updateMockChan := make(chan *workload.X509SVIDResponse)
	workloadClient := MockWorkloadClient{
		mockChan: updateMockChan,
		mtx:      &sync.RWMutex{},
	}

	sidecar := Sidecar{
		config:            config,
		workloadAPIClient: workloadClient,
		certReadyChan:     make(chan struct{}, 1),
	}
	defer close(sidecar.certReadyChan)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		err = sidecar.RunDaemon(ctx)
		require.NoError(t, err)
	}()

	testCases := []struct {
		name     string
		response *spiffetest.X509SVIDResponse
		certs    []*x509.Certificate
		key      crypto.Signer
		bundle   []*x509.Certificate

		intermediateInBundle bool
	}{
		{
			name: "svid with intermediate",
			response: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
				SVIDs:  svidWithIntermediate,
			},
			certs:  svidChainWithIntermediate,
			key:    svidKeyWithIntermediate,
			bundle: domain1Bundle,
		},
		{
			name: "intermediate in bundle",
			response: &spiffetest.X509SVIDResponse{
				Bundle: domain1Bundle,
				SVIDs:  svidWithIntermediate,
			},
			// Only first certificate is expected
			certs: []*x509.Certificate{svidChainWithIntermediate[0]},
			key:   svidKeyWithIntermediate,
			// A concatenation between bundle and intermediate is expected
			bundle: bundleWithIntermediate,

			intermediateInBundle: true,
		},
		{
			name: "single svid ",
			response: &spiffetest.X509SVIDResponse{
				Bundle: domain1CA.Roots(),
				SVIDs:  svid,
			},
			certs:  svidChain,
			key:    svidKey,
			bundle: domain1Bundle,
		},
	}

	svidFile := path.Join(tmpdir, config.SvidFileName)
	svidKeyFile := path.Join(tmpdir, config.SvidKeyFileName)
	svidBundleFile := path.Join(tmpdir, config.SvidBundleFileName)

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			sidecar.config.MergeCAWithIntermediates = testCase.intermediateInBundle

			// Push response to start updating process
			updateMockChan <- testCase.response.ToProto(t)

			// Wait until response is processed
			select {
			case <-sidecar.CertReadyChan():
			//continue
			case <-ctx.Done():
				require.NoError(t, ctx.Err())
			}

			// Load certificates from disk and validate it is expected
			certs, err := util.LoadCertificates(svidFile)
			require.NoError(t, err)
			require.Equal(t, testCase.certs, certs)

			// Load key from disk and validate it is expected
			key, err := loadPrivateKey(svidKeyFile)
			require.NoError(t, err)
			require.Equal(t, testCase.key, key)

			// Load bundle from disk and validate it is expected
			bundles, err := util.LoadCertificates(svidBundleFile)
			require.NoError(t, err)
			require.Equal(t, testCase.bundle, bundles)
		})
	}
}

//Tests that when there is no defaultTimeout in the config, it uses
//the default defaultTimeout set in a constant in the spiffe_sidecar
func Test_getTimeout_default(t *testing.T) {
	config := &Config{}

	expectedTimeout := defaultTimeout
	actualTimeout, err := getTimeout(config)

	assert.NoError(t, err)
	if actualTimeout != expectedTimeout {
		t.Errorf("Expected defaultTimeout : %v, got %v", expectedTimeout, actualTimeout)
	}
}

//Tests that when there is a timeout set in the config, it's used that one
func Test_getTimeout_custom(t *testing.T) {
	config := &Config{
		Timeout: "10s",
	}

	expectedTimeout := time.Second * 10
	actualTimeout, err := getTimeout(config)

	assert.NoError(t, err)
	if actualTimeout != expectedTimeout {
		t.Errorf("Expected defaultTimeout : %v, got %v", expectedTimeout, actualTimeout)
	}
}

func Test_getTimeout_return_error_when_parsing_fails(t *testing.T) {
	config := &Config{
		Timeout: "invalid",
	}

	actualTimeout, err := getTimeout(config)

	assert.Empty(t, actualTimeout)
	assert.NotEmpty(t, err)
}

type MockWorkloadClient struct {
	mockChan chan *workload.X509SVIDResponse
	current  *workload.X509SVIDResponse

	mtx *sync.RWMutex
}

func (m MockWorkloadClient) Start() error {
	return nil
}

func (m MockWorkloadClient) Stop() {}

func (m MockWorkloadClient) UpdateChan() <-chan *workload.X509SVIDResponse {
	return m.mockChan
}

func (m MockWorkloadClient) CurrentSVID() (*workload.X509SVIDResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.current == nil {
		return nil, errors.New("no SVID received yet")
	}
	return m.current, nil
}

func loadPrivateKey(path string) (crypto.Signer, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(crypto.Signer), nil
}
