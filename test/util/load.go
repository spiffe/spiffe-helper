package util

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
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

// LoadCertificates loads one or more certificates into an []*x509.Certificate from
// a PEM file on disk.
func LoadCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certs, err := ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("load certificates from %s: %w", path, err)
	}

	return certs, nil
}

func ParseCertificate(data []byte) (*x509.Certificate, error) {
	certs, err := ParseCertificates(data)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for blockNumber := 0; ; blockNumber++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate in block %d: %w", blockNumber, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in file")
	}

	return certs, nil
}
