package disk

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type X509Config struct {
	Dir                string
	SVIDFileName       string
	SVIDKeyFileName    string
	SVIDBundleFileName string
	CertFileMode       fs.FileMode
	KeyFileMode        fs.FileMode

	AddIntermediatesToBundle bool
	IncludeFederatedDomains  bool
	OmitExpired              bool
	Hint                     string
}

type X509 struct {
	c X509Config
}

func NewX509(c X509Config) *X509 {
	return &X509{
		c: c,
	}
}

// WriteX509Context takes a X509Context, representing a svid message from
// the Workload API, and calls writeCerts and writeKey to write to disk
// the svid, key and bundle of certificates.
// It is possible to change output setting `addIntermediatesToBundle` as true.
func (x *X509) WriteX509Context(x509Context *workloadapi.X509Context) error {
	svidFile := path.Join(x.c.Dir, x.c.SVIDFileName)
	svidBundleFile := path.Join(x.c.Dir, x.c.SVIDBundleFileName)

	svid, err := x.getX509SVID(x509Context)
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
	if x.c.AddIntermediatesToBundle {
		bundles = append(bundles, certs[1:]...)
		certs = certs[:1]
	}

	// If using federated domains, add them to the CA bundle
	if x.c.IncludeFederatedDomains {
		for _, bundle := range x509Context.Bundles.Bundles() {
			// The bundle corresponding to svid.ID.TrustDomain is already stored
			if bundle.TrustDomain().Name() != svid.ID.TrustDomain().Name() {
				bundles = append(bundles, bundle.X509Authorities()...)
			}
		}
	}

	// Write cert, key, and bundle to disk
	if err := x.writeCerts(svidFile, certs); err != nil {
		return err
	}

	if err := x.writeKey(privateKey); err != nil {
		return err
	}

	return x.writeCerts(svidBundleFile, bundles)
}

// writeCerts takes an array of certificates,
// and encodes them as PEM blocks, writing them to file
func (x *X509) writeCerts(file string, certs []*x509.Certificate) error {
	var pemData []byte
	for _, cert := range certs {
		if x.c.OmitExpired && time.Now().UTC().After(cert.NotAfter) {
			continue
		}
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return os.WriteFile(file, pemData, x.c.CertFileMode)
}

// writeKey takes a private key as a slice of bytes,
// formats as PEM, and writes it to file
func (x *X509) writeKey(data []byte) error {
	b := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	}

	svidKeyFile := path.Join(x.c.Dir, x.c.SVIDKeyFileName)
	return os.WriteFile(svidKeyFile, pem.EncodeToMemory(b), x.c.KeyFileMode)
}

// SVIDPath returns the full path for the SVID file
func (x *X509) SVIDPath() string {
	return path.Join(x.c.Dir, x.c.SVIDFileName)
}

// SVIDKeyPath returns the full path for the SVID key file
func (x *X509) SVIDKeyPath() string {
	return path.Join(x.c.Dir, x.c.SVIDKeyFileName)
}

// SVIDBundlePath returns the full path for the SVID bundle file
func (x *X509) SVIDBundlePath() string {
	return path.Join(x.c.Dir, x.c.SVIDBundleFileName)
}

// getX509SVID extracts the x509 SVID that matches the hint or returns the default
// if hint is empty
func (x *X509) getX509SVID(x509Context *workloadapi.X509Context) (*x509svid.SVID, error) {
	if x.c.Hint == "" {
		return x509Context.DefaultSVID(), nil
	}

	for _, svid := range x509Context.SVIDs {
		if svid.Hint == x.c.Hint {
			return svid, nil
		}
	}

	return nil, fmt.Errorf("failed to find the hinted x509 SVID")
}
