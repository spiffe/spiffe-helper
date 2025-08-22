package disk

import (
	"io/fs"
	"path"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/test/spiffetest"
	"github.com/spiffe/spiffe-helper/test/util"
	"github.com/stretchr/testify/require"
)

const (
	svidFilename       = "svid.pem"
	svidKeyFilename    = "svid_key.pem"
	svidBundleFilename = "svid_bundle.pem"
	certFileMode       = fs.FileMode(0600)
	keyFileMode        = fs.FileMode(0600)
)

func TestWriteX509Context(t *testing.T) {
	// Create root and intermediate CAs
	rootCA := spiffetest.NewCA(t)
	expiredItermediateCAChain := rootCA.CreateExpiredCA()
	intermediateCA := rootCA.CreateCA()
	federatedCA := spiffetest.NewCA(t)

	tempDir := t.TempDir()

	tests := []struct {
		name                    string
		ca                      *spiffetest.CA
		federatedCA             *spiffetest.CA
		spiffeIDString          string
		chainLength             int
		omitExpired             bool
		includeFederatedDomains bool
		intermediateInBundle    bool
	}{
		{
			name:                    "Single SVID",
			ca:                      rootCA,
			spiffeIDString:          "spiffe://example.test/workload",
			chainLength:             1,
			omitExpired:             false,
			includeFederatedDomains: false,
			intermediateInBundle:    false,
		},
		{
			name:                    "Single SVID with intermediate in bundle",
			ca:                      rootCA,
			spiffeIDString:          "spiffe://example.test/workload2",
			chainLength:             1,
			omitExpired:             false,
			includeFederatedDomains: false,
			intermediateInBundle:    true,
		},
		{
			name:                    "SVID with intermediate CA",
			ca:                      intermediateCA,
			spiffeIDString:          "spiffe://example.test/workloadWithIntermediate",
			chainLength:             2,
			omitExpired:             false,
			includeFederatedDomains: false,
			intermediateInBundle:    false,
		},
		{
			name:                    "SVID with intermediate CA and intermediate in bundle",
			ca:                      intermediateCA,
			spiffeIDString:          "spiffe://example.test/workloadWithIntermediate",
			chainLength:             2,
			omitExpired:             false,
			includeFederatedDomains: false,
			intermediateInBundle:    true,
		},
		{
			name:                    "SVID with expired intermediate in bundle and omit expired certs",
			ca:                      expiredItermediateCAChain,
			spiffeIDString:          "spiffe://example.test/workloadWithIntermediate",
			chainLength:             2,
			omitExpired:             true,
			includeFederatedDomains: false,
			intermediateInBundle:    true,
		},
		{
			name:                    "SVID with federated trust domains",
			ca:                      rootCA,
			federatedCA:             federatedCA,
			spiffeIDString:          "spiffe://example.test/workload",
			chainLength:             1,
			omitExpired:             false,
			includeFederatedDomains: true,
			intermediateInBundle:    false,
		},
		{
			name:                    "SVID with federated trust domains but not included in bundle",
			ca:                      rootCA,
			federatedCA:             federatedCA,
			spiffeIDString:          "spiffe://example.test/workload",
			chainLength:             1,
			omitExpired:             false,
			includeFederatedDomains: false,
			intermediateInBundle:    false,
		},
		{
			name:                    "SVID with federated trust domains and intermediate in bundle",
			ca:                      intermediateCA,
			federatedCA:             federatedCA,
			spiffeIDString:          "spiffe://example.test/workload",
			chainLength:             2,
			omitExpired:             false,
			includeFederatedDomains: true,
			intermediateInBundle:    true,
		},
	}
	for _, hint := range []string{"", "other"} {
		prefixSpiffeID, err := spiffeid.FromString("spiffe://example.test/shouldnt/ever/get")
		require.NoError(t, err)
		for _, test := range tests {
			test := test
			t.Run(test.name, func(t *testing.T) {
				spiffeID, err := spiffeid.FromString(test.spiffeIDString)
				require.NoError(t, err)
				certs, key := test.ca.CreateX509SVID(spiffeID.String())
				require.Len(t, certs, test.chainLength)

				svids := []*x509svid.SVID{
					{
						ID:           spiffeID,
						Certificates: certs,
						PrivateKey:   key,
						Hint:         "other",
					},
				}
				if hint != "" {
					// Prepend on a test cert so that the hinted one is last
					svids = append([]*x509svid.SVID{
						{
							ID:           prefixSpiffeID,
							Certificates: certs,
							PrivateKey:   key,
							Hint:         "first",
						},
					}, svids...)
				}
				x509Context := &workloadapi.X509Context{
					Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), test.ca.Roots())),
					SVIDs:   svids,
				}

				bundle := test.ca.Roots()

				if test.intermediateInBundle {
					bundle = append(bundle, certs[1:]...)
					certs = certs[:1]
				}

				if test.omitExpired {
					bundle = bundle[:1]
				}

				if test.federatedCA != nil {
					federatedTrustDomain := spiffeid.RequireTrustDomainFromString("federated.test")
					x509Context.Bundles.Add(x509bundle.FromX509Authorities(federatedTrustDomain, test.federatedCA.Roots()))

					if test.includeFederatedDomains {
						bundle = append(bundle, test.federatedCA.Roots()...)
					}
				}

				err = WriteX509Context(x509Context, test.intermediateInBundle, test.includeFederatedDomains, test.omitExpired, tempDir, svidFilename, svidKeyFilename, svidBundleFilename, certFileMode, keyFileMode, hint)
				require.NoError(t, err)

				// Load certificates from disk and validate it is expected
				actualCerts, err := util.LoadCertificates(path.Join(tempDir, svidFilename))
				require.NoError(t, err)
				require.Equal(t, certs, actualCerts)

				// Load key from disk and validate it is expected
				actualKey, err := util.LoadPrivateKey(path.Join(tempDir, svidKeyFilename))
				require.NoError(t, err)
				require.Equal(t, key, actualKey)

				// Load bundle from disk and validate it is expected
				actualBundle, err := util.LoadCertificates(path.Join(tempDir, svidBundleFilename))
				require.NoError(t, err)
				require.Equal(t, bundle, actualBundle)
			})
		}
	}
}
