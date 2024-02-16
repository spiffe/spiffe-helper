package disk

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	certsFileMode = os.FileMode(0644)
	keyFileMode   = os.FileMode(0600)
)

// WriteX509Context takes a X509Context, representing a svid message from
// the Workload API, and calls writeCerts and writeKey to write to disk
// the svid, key and bundle of certificates.
// It is possible to change output setting `addIntermediatesToBundle` as true.
func WriteX509Context(x509Context *workloadapi.X509Context, addIntermediatesToBundle, includeFederatedDomains bool, certDir, svidFilename, svidKeyFilename, svidBundleFilename string) error {
	svidFile := path.Join(certDir, svidFilename)
	svidKeyFile := path.Join(certDir, svidKeyFilename)
	svidBundleFile := path.Join(certDir, svidBundleFilename)

	// There may be more than one certificate, but we're only interested in the default one
	svid := x509Context.DefaultSVID()
	certs := svid.Certificates

	// Extract bundle for the default SVID
	bundleSet, found := x509Context.Bundles.Get(svid.ID.TrustDomain())
	if !found {
		return fmt.Errorf("no bundles found for %s trust domain", svid.ID.TrustDomain().String())
	}
	bundles := bundleSet.X509Authorities()

	// Extract private key
	privateKey, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	if err != nil {
		return err
	}

	// Add intermediates into bundles and remove them from certs
	if addIntermediatesToBundle {
		bundles = append(bundles, certs[1:]...)
		certs = []*x509.Certificate{certs[0]}
	}

	// If using federated domains, add them to the CA bundle
	if includeFederatedDomains {
		for _, bundle := range x509Context.Bundles.Bundles() {
			// The bundle corresponding to svid.ID.TrustDomain is already stored
			if bundle.TrustDomain().Name() != svid.ID.TrustDomain().Name() {
				bundles = append(bundles, bundle.X509Authorities()...)
			}
		}
	}

	// Write cert, key, and bundle to disk
	if err := writeCerts(svidFile, certs); err != nil {
		return err
	}

	if err := writeKey(svidKeyFile, privateKey); err != nil {
		return err
	}

	return writeCerts(svidBundleFile, bundles)
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
