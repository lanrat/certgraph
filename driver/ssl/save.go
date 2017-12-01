package ssl

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// function to convert certificats to PEM formate
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

func RawCertToPEMFile(cert []byte, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return nil
}
