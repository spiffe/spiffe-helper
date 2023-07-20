package sidecar

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"path"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/test/spiffetest"
	"github.com/spiffe/spiffe-helper/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Creates a Sidecar with a Mocked WorkloadAPIClient and tests that
// running the Sidecar Daemon, when a SVID Response is sent to the
// UpdateChan on the WorkloadAPI client, the PEM files are stored on disk
func TestSidecar_RunDaemon(t *testing.T) {
	// Create root CA
	domain1CA := spiffetest.NewCA(t)
	// Create an intermediate certificate
	domain1Inter := domain1CA.CreateCA()
	domain1Bundle := domain1CA.Roots()

	// Svid with intermediate
	spiffeIDWithIntermediate, err := spiffeid.FromString("spiffe://example.test/workloadWithIntermediate")
	require.NoError(t, err)
	svidChainWithIntermediate, svidKeyWithIntermediate := domain1Inter.CreateX509SVID(spiffeIDWithIntermediate.String())
	require.Len(t, svidChainWithIntermediate, 2)

	// Add cert with intermediate into an svid
	svidWithIntermediate := []*x509svid.SVID{
		{
			ID:           spiffeIDWithIntermediate,
			Certificates: svidChainWithIntermediate,
			PrivateKey:   svidKeyWithIntermediate,
		},
	}

	// Concat bundles with intermediate certificate
	bundleWithIntermediate := domain1CA.Roots()
	bundleWithIntermediate = append(bundleWithIntermediate, svidChainWithIntermediate[1:]...)

	// Create a single svid without intermediate
	spiffeID, err := spiffeid.FromString("spiffe://example.test/workload")
	require.NoError(t, err)
	svidChain, svidKey := domain1CA.CreateX509SVID(spiffeID.String())
	require.Len(t, svidChain, 1)
	svid := []*x509svid.SVID{
		{
			ID:           spiffeID,
			Certificates: svidChain,
			PrivateKey:   svidKey,
		},
	}

	tmpdir := t.TempDir()

	log, _ := test.NewNullLogger()

	config := &Config{
		Cmd:                "echo",
		CertDir:            tmpdir,
		SvidFileName:       "svid.pem",
		SvidKeyFileName:    "svid_key.pem",
		SvidBundleFileName: "svid_bundle.pem",
		Log:                log,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	sidecar := Sidecar{
		config:        config,
		certReadyChan: make(chan struct{}, 1),
	}
	defer close(sidecar.certReadyChan)

	testCases := []struct {
		name                 string
		response             *workloadapi.X509Context
		certs                []*x509.Certificate
		key                  crypto.Signer
		bundle               []*x509.Certificate
		renewSignal          string
		intermediateInBundle bool
	}{
		{
			name: "svid with intermediate",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeIDWithIntermediate.TrustDomain(), domain1Bundle)),
				SVIDs:   svidWithIntermediate,
			},
			certs:  svidChainWithIntermediate,
			key:    svidKeyWithIntermediate,
			bundle: domain1Bundle,
		},
		{
			name: "intermediate in bundle",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeIDWithIntermediate.TrustDomain(), domain1Bundle)),
				SVIDs:   svidWithIntermediate,
			},
			// Only first certificate is expected
			certs: []*x509.Certificate{svidChainWithIntermediate[0]},
			key:   svidKeyWithIntermediate,
			// A concatenation between bundle and intermediate is expected
			bundle: bundleWithIntermediate,

			intermediateInBundle: true,
		},
		{
			name: "single svid with intermediate in bundle",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), domain1CA.Roots())),
				SVIDs:   svid,
			},
			certs:                svidChain,
			key:                  svidKey,
			bundle:               domain1Bundle,
			intermediateInBundle: true,
		},
		{
			name: "single svid",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), domain1CA.Roots())),
				SVIDs:   svid,
			},
			certs:  svidChain,
			key:    svidKey,
			bundle: domain1Bundle,
		},
		{
			name: "single svid with RenewSignal",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), domain1CA.Roots())),
				SVIDs:   svid,
			},
			certs:       svidChain,
			key:         svidKey,
			bundle:      domain1Bundle,
			renewSignal: "SIGHUP",
		},
	}

	svidFile := path.Join(tmpdir, config.SvidFileName)
	svidKeyFile := path.Join(tmpdir, config.SvidKeyFileName)
	svidBundleFile := path.Join(tmpdir, config.SvidBundleFileName)

	w := x509Watcher{&sidecar}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			sidecar.config.AddIntermediatesToBundle = testCase.intermediateInBundle
			sidecar.config.RenewSignal = testCase.renewSignal
			// Push response to start updating process
			// updateMockChan <- testCase.response.ToProto(t)
			w.OnX509ContextUpdate(testCase.response)

			// Wait until response is processed
			select {
			case <-sidecar.CertReadyChan():
			// continue
			case <-ctx.Done():
				require.NoError(t, ctx.Err())
			}

			// Load certificates from disk and validate it is expected
			certs, err := util.LoadCertificates(svidFile)
			require.NoError(t, err)
			require.Equal(t, testCase.certs, certs)

			// Load key from disk and validate it is expected
			key, err := util.LoadPrivateKey(svidKeyFile)
			require.NoError(t, err)
			require.Equal(t, testCase.key, key)

			// Load bundle from disk and validate it is expected
			bundles, err := util.LoadCertificates(svidBundleFile)
			require.NoError(t, err)
			require.Equal(t, testCase.bundle, bundles)
		})
	}

	cancel()
}

func TestDefaultAgentAddress(t *testing.T) {
	log, _ := test.NewNullLogger()
	spiffeSidecar, err := New("../../test/sidecar/config/helper.conf", log)
	require.NoError(t, err)
	assert.Equal(t, spiffeSidecar.config.AgentAddress, "/tmp/spire-agent/public/api.sock")
}
func TestEnvAgentAddress(t *testing.T) {
	os.Setenv("SPIRE_AGENT_ADDRESS", "/tmp/agent.sock")
	log, _ := test.NewNullLogger()
	spiffeSidecar, err := New("../../test/sidecar/config/helper.conf", log)
	require.NoError(t, err)
	assert.Equal(t, spiffeSidecar.config.AgentAddress, "/tmp/agent.sock")
}

func TestAgentAddress(t *testing.T) {
	// This test is used to verify that we get the agent_address of the .conf file instead of the ENV value, if we have both
	os.Setenv("SPIRE_AGENT_ADDRESS", "/tmp/agent.sock")
	log, _ := test.NewNullLogger()
	spiffeSidecar, err := New("../../test/sidecar/configWithAddress/helper.conf", log)
	require.NoError(t, err)
	assert.Equal(t, spiffeSidecar.config.AgentAddress, "/tmp/spire-agent/public/api.sock")
}

func TestGetCmdArgs(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		expectedArgs []string
		expectedErr  string
	}{
		{
			name:         "Empty input arguments",
			in:           "",
			expectedArgs: []string{},
		},
		{
			name:         "Arguments without double quoted spaces",
			in:           "-flag1 value1 -flag2 value2",
			expectedArgs: []string{"-flag1", "value1", "-flag2", "value2"},
		},
		{
			name:         "Arguments with double quoted spaces",
			in:           `-flag1 "value 1" -flag2 "value 2"`,
			expectedArgs: []string{"-flag1", "value 1", "-flag2", "value 2"},
		},
		{
			name:        "Missing quote",
			in:          `-flag1 "value 1`,
			expectedErr: `missing " in quoted-field`,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			args, err := getCmdArgs(c.in)
			if c.expectedErr != "" {
				require.NotNil(t, err)
				require.Nil(t, args)
				require.Contains(t, err.Error(), c.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expectedArgs, args)
		})
	}
}
