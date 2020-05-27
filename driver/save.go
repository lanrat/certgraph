package driver

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// CertsToPEMFile saves certificates to local pem file
func CertsToPEMFile(certs []*x509.Certificate, file string) error {
	if fileExists(file) {
		return nil
	}
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, cert := range certs {
		err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return err
		}
	}
	return nil
}

// RawCertToPEMFile saves raw certificate to local pem file
func RawCertToPEMFile(cert []byte, file string) error {
	if fileExists(file) {
		return nil
	}
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return err
}

func fileExists(f string) bool {
	_, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}
