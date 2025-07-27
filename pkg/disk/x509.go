package disk

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// WriteX509Context takes a X509Context, representing a svid message from
// the Workload API, and calls writeCerts and writeKey to write to disk
// the svid, key and bundle of certificates.
// It is possible to change output setting `addIntermediatesToBundle` as true.
func (d *Disk) WriteX509Context(x509Context *workloadapi.X509Context) error {
	svidFile := path.Join(d.c.X509.Dir, d.c.X509.SVIDFileName)
	svidBundleFile := path.Join(d.c.X509.Dir, d.c.X509.SVIDBundleFileName)

	svid, err := getX509SVID(x509Context, d.c.Hint)
	if err != nil {
		return err
	}

	// Extract bundle for the default SVID
	bundleSet, found := x509Context.Bundles.Get(svid.ID.TrustDomain())
	if !found {
		return fmt.Errorf("no bundles found for %q trust domain", svid.ID.TrustDomain().String())
	}
	bundles := bundleSet.X509Authorities()

	// Extract private key
	privateKey, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	if err != nil {
		return err
	}

	// Add intermediates into bundles and remove them from certs
	certs := svid.Certificates
	if d.c.X509.AddIntermediatesToBundle {
		bundles = append(bundles, certs[1:]...)
		certs = certs[:1]
	}

	// If using federated domains, add them to the CA bundle
	if d.c.X509.IncludeFederatedDomains {
		for _, bundle := range x509Context.Bundles.Bundles() {
			// The bundle corresponding to svid.ID.TrustDomain is already stored
			if bundle.TrustDomain().Name() != svid.ID.TrustDomain().Name() {
				bundles = append(bundles, bundle.X509Authorities()...)
			}
		}
	}

	// Write cert, key, and bundle to disk
	if err := d.writeCerts(svidFile, certs); err != nil {
		return err
	}

	if err := d.writeKey(privateKey); err != nil {
		return err
	}

	return d.writeCerts(svidBundleFile, bundles)
}

// writeCerts takes an array of certificates,
// and encodes them as PEM blocks, writing them to file
func (d *Disk) writeCerts(file string, certs []*x509.Certificate) error {
	var pemData []byte
	for _, cert := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return os.WriteFile(file, pemData, d.c.X509.CertFileMode)
}

// writeKey takes a private key as a slice of bytes,
// formats as PEM, and writes it to file
func (d *Disk) writeKey(data []byte) error {
	b := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	}

	svidKeyFile := path.Join(d.c.X509.Dir, d.c.X509.SVIDKeyFileName)
	return os.WriteFile(svidKeyFile, pem.EncodeToMemory(b), d.c.X509.KeyFileMode)
}

// getX509SVID extracts the x509 SVID that matches the hint or returns the default
// if hint is empty
func getX509SVID(x509Context *workloadapi.X509Context, hint string) (*x509svid.SVID, error) {
	if hint == "" {
		return x509Context.DefaultSVID(), nil
	}

	for _, svid := range x509Context.SVIDs {
		if svid.Hint == hint {
			return svid, nil
		}
	}

	return nil, fmt.Errorf("failed to find the hinted x509 SVID")
}
