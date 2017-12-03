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
	"github.com/lanrat/certgraph/graph"
	_ "github.com/lib/pq"
)

const connStr = "postgresql://guest@crt.sh/certwatch?sslmode=disable"

// TODO add timeout option

type crtsh struct {
	db          *sql.DB
	query_limit int
	timeout     time.Duration
	save        bool
	savePath    string
}

func NewCTDriver(max_query_results int, timeout time.Duration, savePath string) (ct.Driver, error) {
	d := new(crtsh)
	d.query_limit = max_query_results
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
	_, err := d.db.Exec(fmt.Sprintf("SET statement_timeout TO %d;", (1000 * sec)))
	return err
}

func (d *crtsh) QueryDomain(domain string, include_expired bool, include_subdomains bool) ([]graph.Fingerprint, error) {
	results := make([]graph.Fingerprint, 0, 5)

	queryStr := "SELECT digest(certificate.certificate, 'sha256') sha256 FROM certificate_identity, certificate WHERE certificate.id = certificate_identity.certificate_id AND x509_notAfter(certificate.certificate) > statement_timestamp() AND reverse(lower(certificate_identity.name_value)) LIKE reverse(lower($1)) LIMIT $2"
	if include_expired {
		queryStr = "SELECT digest(certificate.certificate, 'sha256') sha256 FROM certificate_identity, certificate WHERE certificate.id = certificate_identity.certificate_id AND reverse(lower(certificate_identity.name_value)) LIKE reverse(lower($1)) LIMIT $2"
	}

	if include_subdomains {
		domain = fmt.Sprintf("%%.%s", domain)
	}

	rows, err := d.db.Query(queryStr, domain, d.query_limit)
	if err != nil {
		return results, err
	}

	for rows.Next() {
		var hash []byte
		err = rows.Scan(&hash)
		if err != nil {
			return results, err
		}
		results = append(results, graph.FingerprintFromBytes(hash))
	}

	return results, nil
}

func (d *crtsh) QueryCert(fp graph.Fingerprint) (*graph.CertNode, error) {
	certnode := new(graph.CertNode)
	certnode.Fingerprint = fp
	certnode.Domains = make([]string, 0, 5)
	certnode.CT = true

	queryStr := "SELECT DISTINCT certificate_identity.name_value FROM certificate, certificate_identity WHERE certificate.id = certificate_identity.certificate_id AND  certificate_identity.name_type in ('dNSName', 'commonName') AND digest(certificate.certificate, 'sha256') = $1"

	rows, err := d.db.Query(queryStr, fp[:])
	if err != nil {
		return certnode, err
	}

	for rows.Next() {
		var domain string
		rows.Scan(&domain)
		certnode.Domains = append(certnode.Domains, domain)
	}

	if d.save {
		var raw_cert []byte
		queryStr = "SELECT certificate.certificate FROM certificate WHERE digest(certificate.certificate, 'sha256') = $1"
		row := d.db.QueryRow(queryStr, fp[:])
		err = row.Scan(&raw_cert)
		if err != nil {
			return certnode, err
		}

		ssl.RawCertToPEMFile(raw_cert, path.Join(d.savePath, fp.HexString())+".pem")
	}

	return certnode, nil
}

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
