package driver

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// CertsToPEMFile saves a certificate chain to a local PEM file.
// Skips saving if the file already exists to avoid overwriting.
func CertsToPEMFile(certs []*x509.Certificate, file string) error {
	if fileExists(file) {
		return nil
	}
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for _, cert := range certs {
		err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return err
		}
	}
	return nil
}

// RawCertToPEMFile saves raw certificate bytes to a local PEM file.
// Skips saving if the file already exists to avoid overwriting.
func RawCertToPEMFile(cert []byte, file string) error {
	if fileExists(file) {
		return nil
	}
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return err
}

// fileExists checks if a file exists at the given path.
// Returns true if the file exists and can be accessed.
func fileExists(f string) bool {
	_, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}
