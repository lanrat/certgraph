package crtsh

/*
 * This file implements an unofficial API client for Comodo's
 * Certificate Transparency search
 * https://crt.sh/
 *
 * As the API is unofficial and has been reverse engineered it may stop working
 * at any time and comes with no guarantees.
 */

import (
	"database/sql"
	"fmt"
	"path"
	"time"

	"github.com/lanrat/certgraph/driver/ct"
	"github.com/lanrat/certgraph/driver/ssl"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/graph"
	_ "github.com/lib/pq" // portgresql
)

const connStr = "postgresql://guest@crt.sh/certwatch?sslmode=disable"

type crtsh struct {
	db         *sql.DB
	queryLimit int
	timeout    time.Duration
	save       bool
	savePath   string
}

// NewCTDriver creates a new CT driver for crt.sh
func NewCTDriver(maxQueryResults int, timeout time.Duration, savePath string) (ct.Driver, error) {
	d := new(crtsh)
	d.queryLimit = maxQueryResults
	var err error

	if len(savePath) > 0 {
		d.save = true
		d.savePath = savePath
	}

	d.db, err = sql.Open("postgres", connStr)

	d.setSQLTimeout(d.timeout.Seconds())

	return d, err
}

func (d *crtsh) setSQLTimeout(sec float64) error {
	_, err := d.db.Exec(fmt.Sprintf("SET statement_timeout TO %f;", (1000 * sec)))
	return err
}

func (d *crtsh) QueryDomain(domain string, includeExpired bool, includeSubdomains bool) ([]fingerprint.Fingerprint, error) {
	results := make([]fingerprint.Fingerprint, 0, 5)

	queryStr := ""

	if includeSubdomains {
		if includeExpired {
			queryStr = `SELECT digest(certificate.certificate, 'sha256') sha256
					FROM certificate_identity, certificate
					WHERE certificate.id = certificate_identity.certificate_id
					AND (reverse(lower(certificate_identity.name_value)) LIKE reverse(lower('%%.'||$1))
                	OR reverse(lower(certificate_identity.name_value)) LIKE reverse(lower($1)))
					LIMIT $2`
		} else {
			queryStr = `SELECT digest(certificate.certificate, 'sha256') sha256
					FROM certificate_identity, certificate
					WHERE certificate.id = certificate_identity.certificate_id
					AND x509_notAfter(certificate.certificate) > statement_timestamp()
					AND (reverse(lower(certificate_identity.name_value)) LIKE reverse(lower('%%.'||$1))
                	OR reverse(lower(certificate_identity.name_value)) LIKE reverse(lower($1)))
					LIMIT $2`
		}
	} else {
		if includeExpired {
			queryStr = `SELECT digest(certificate.certificate, 'sha256') sha256
					FROM certificate_identity, certificate
					WHERE certificate.id = certificate_identity.certificate_id
					AND reverse(lower(certificate_identity.name_value)) LIKE reverse(lower($1))
					LIMIT $2`
		} else {
			queryStr = `SELECT digest(certificate.certificate, 'sha256') sha256
					FROM certificate_identity, certificate
					WHERE certificate.id = certificate_identity.certificate_id
					AND x509_notAfter(certificate.certificate) > statement_timestamp()
					AND reverse(lower(certificate_identity.name_value)) LIKE reverse(lower($1))
					LIMIT $2`
		}
	}

	if includeSubdomains {
		domain = fmt.Sprintf("%%.%s", domain)
	}

	rows, err := d.db.Query(queryStr, domain, d.queryLimit)
	if err != nil {
		return results, err
	}

	for rows.Next() {
		var hash []byte
		err = rows.Scan(&hash)
		if err != nil {
			return results, err
		}
		results = append(results, fingerprint.FromHashBytes(hash))
	}

	return results, nil
}

func (d *crtsh) QueryCert(fp fingerprint.Fingerprint) (*graph.CertNode, error) {
	certNode := new(graph.CertNode)
	certNode.Fingerprint = fp
	certNode.Domains = make([]string, 0, 5)
	certNode.CT = true

	queryStr := `SELECT DISTINCT certificate_identity.name_value
				FROM certificate, certificate_identity
				WHERE certificate.id = certificate_identity.certificate_id
				AND certificate_identity.name_type in ('dNSName', 'commonName')
				AND digest(certificate.certificate, 'sha256') = $1`

	rows, err := d.db.Query(queryStr, fp[:])
	if err != nil {
		return certNode, err
	}

	for rows.Next() {
		var domain string
		rows.Scan(&domain)
		certNode.Domains = append(certNode.Domains, domain)
	}

	if d.save {
		var rawCert []byte
		queryStr = `SELECT certificate.certificate
					FROM certificate
					WHERE digest(certificate.certificate, 'sha256') = $1`
		row := d.db.QueryRow(queryStr, fp[:])
		err = row.Scan(&rawCert)
		if err != nil {
			return certNode, err
		}

		ssl.RawCertToPEMFile(rawCert, path.Join(d.savePath, fp.HexString())+".pem")
	}

	return certNode, nil
}

// CTexample is a demo function used to test the crt.sh driver
func CTexample(domain string) error {
	d, err := NewCTDriver(1000, time.Duration(10)*time.Second, "")
	if err != nil {
		return err
	}
	s, err := d.QueryDomain(domain, false, false)
	if err != nil {
		return err
	}

	for i := range s {
		fmt.Println(s[i].HexString(), " ", s[i].B64Encode())
		cert, err := d.QueryCert(s[i])
		if err != nil {
			return err
		}
		for j := range cert.Domains {
			fmt.Println("\t", cert.Domains[j])
		}
	}

	return nil
}
