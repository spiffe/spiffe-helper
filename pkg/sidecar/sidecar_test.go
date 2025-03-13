package sidecar

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"path"
	"runtime"
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

	// Used for testing federated trust domains
	domain2CA := spiffetest.NewCA(t)
	domain2Bundle := domain2CA.Roots()

	// SVID with intermediate
	spiffeIDWithIntermediate, err := spiffeid.FromString("spiffe://example.test/workloadWithIntermediate")
	require.NoError(t, err)
	svidChainWithIntermediate, svidKeyWithIntermediate := domain1Inter.CreateX509SVID(spiffeIDWithIntermediate.String())
	require.Len(t, svidChainWithIntermediate, 2)

	// Add cert with intermediate into a svid
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

	bundleWithFederatedDomains := domain1CA.Roots()
	bundleWithFederatedDomains = append(bundleWithFederatedDomains, domain2Bundle[0:]...)
	// Used to create an additional bundle when testing federated trust domains
	federatedSpiffeID, err := spiffeid.FromString("spiffe://foo.test/server")
	require.NoError(t, err)

	tmpdir := t.TempDir()

	log, _ := test.NewNullLogger()

	config := &Config{
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	sidecar := Sidecar{
		config:        config,
		certReadyChan: make(chan struct{}, 1),
		health: Health{
			FileWriteStatuses: FileWriteStatuses{
				X509WriteStatus: writeStatusUnwritten,
				JWTWriteStatus:  make(map[string]string),
			},
		},
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
		federatedDomains     bool
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
		{
			name: "svid with federated trust domains",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), domain1CA.Roots()), x509bundle.FromX509Authorities(federatedSpiffeID.TrustDomain(), domain2CA.Roots())),
				SVIDs:   svid,
			},
			certs:            svidChain,
			key:              svidKey,
			bundle:           bundleWithFederatedDomains,
			federatedDomains: true,
		},
	}

	svidFile := path.Join(tmpdir, config.SVIDFileName)
	svidKeyFile := path.Join(tmpdir, config.SVIDKeyFileName)
	svidBundleFile := path.Join(tmpdir, config.SVIDBundleFileName)

	w := x509Watcher{&sidecar}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.renewSignal != "" && runtime.GOOS == "windows" {
				t.Skip("Skipping test on Windows because it does not support signals")
			}
			sidecar.config.AddIntermediatesToBundle = testCase.intermediateInBundle
			sidecar.config.RenewSignal = testCase.renewSignal
			sidecar.config.IncludeFederatedDomains = testCase.federatedDomains
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
		// Single quotes are not special to the parser
		{
			name:         "Single quotes in double quotes",
			in:           `-c "echo 'hello world'"`,
			expectedArgs: []string{"-c", "echo 'hello world'"},
		},
		{
			name:         "Unpaired single quote",
			in:           `echo Mc'Gougall`,
			expectedArgs: []string{"echo", "Mc'Gougall"},
		},
		// Unlike a shell, spiffe-helper will parse this argument
		// string without considering the single quoted range as a
		// single argument.
		{
			name:         "single quotes do not protect spaces",
			in:           `-c 'echo hello world'`,
			expectedArgs: []string{"-c", "'echo", "hello", "world'"},
		},
		// Unlike a shell, spiffe-helper double quotes within single quotes
		// are not protected. In a bourne-like shell, this would parse
		// as a single argument. A csv-parser sees this as a quoted field
		// without a following delimiter and will return an error.
		{
			name:        "single quotes do not protect spaces",
			in:          `-c "echo 'hello "cruel" world'"`,
			expectedErr: `extraneous or missing " in quoted-field`,
		},
		// unpaired double quotes inside single quotes will result in a parse error
		// for the same reason
		{
			name:        "unpaired double quotes in single quotes",
			in:          `-c "echo 'hello "cruel" world'"`,
			expectedErr: `extraneous or missing " in quoted-field`,
		},
		// backslash escaping of double quotes inside argument strings is not supported
		// by spiffe-helper's parser, and will result in an error not the expected argument
		// vector [`-c`, `echo "hello world"`]
		{
			name:        "Backslash-escaped double quotes in double quotes",
			in:          `-c "echo \"hello world\""`,
			expectedErr: `extraneous or missing " in quoted-field`,
		},
		// spiffe-helper's parser instead uses quote-pairing for escaping double quotes
		{
			name:         "Pair-escaped double quotes in double quotes",
			in:           `-c "echo ""hello world"""`,
			expectedArgs: []string{`-c`, `echo "hello world"`},
		},
		// The argument vector is not processed for metacharacter expansion
		{
			name:         "metacharacters are not special",
			in:           `$$ $var $* ${var} {{var}} $(var) ${{var}} %VAR% %(var)% ${env:VAR}`,
			expectedArgs: []string{`$$`, `$var`, `$*`, `${var}`, `{{var}}`, `$(var)`, `${{var}}`, `%VAR%`, `%(var)%`, `${env:VAR}`},
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

// TestSignalProcess makes sure only one copy of the process is started. It uses a small script that creates a file
// where the name is the process ID of the script. If more then one file exists, then multiple processes were started
func TestSignalProcess(t *testing.T) {
	tempDir := t.TempDir()
	config := &Config{
		Cmd:         "./sidecar_test.sh",
		CmdArgs:     tempDir,
		RenewSignal: "SIGWINCH",
	}
	sidecar := New(config)
	require.NotNil(t, sidecar)

	// Run signalProcess() twice. The second should only signal the process with SIGWINCH which is basically a no op.
	err := sidecar.signalProcess()
	require.NoError(t, err)
	err = sidecar.signalProcess()
	require.NoError(t, err)

	// Give the script some time to run
	time.Sleep(1 * time.Second)

	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	require.Equal(t, 1, len(files))
}
