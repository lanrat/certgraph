package ssl

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// CertsToPEMFile saves certificates to local pem file
func CertsToPEMFile(certs []*x509.Certificate, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, cert := range certs {
		pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return nil
}

// RawCertToPEMFile saves raw certificate to local pem file
func RawCertToPEMFile(cert []byte, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return nil
}
