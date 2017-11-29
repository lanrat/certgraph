package crtsh

import (
	"database/sql"
	"fmt"
	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/graph"
	_ "github.com/lib/pq"
)

const connStr = "postgresql://guest@crt.sh/certwatch?sslmode=disable"

type crtsh struct {
	db *sql.DB
}

func NewCRTshDriver() (driver.Driver, error) {
	d := new(crtsh)
	var err error

	d.db, err = sql.Open("postgres", connStr)

	return d, err
}

func (d *crtsh) QueryDomain(domain string, include_expired bool, include_subdomains bool) ([]graph.Fingerprint, error) {
	results := make([]graph.Fingerprint, 0, 5)

	queryStr := "SELECT digest(certificate.certificate, 'sha256') sha256 FROM certificate_identity, certificate WHERE certificate.id = certificate_identity.certificate_id AND x509_notAfter(certificate.certificate) > statement_timestamp() AND reverse(lower(certificate_identity.name_value)) LIKE reverse(lower($1))"
	if include_expired {
		queryStr = "SELECT digest(certificate.certificate, 'sha256') sha256 FROM certificate_identity, certificate WHERE certificate.id = certificate_identity.certificate_id AND reverse(lower(certificate_identity.name_value)) LIKE reverse(lower($1))"
	}

	if include_subdomains {
		domain = fmt.Sprintf("%%.%s", domain)
	}

	rows, err := d.db.Query(queryStr, domain)
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

	queryStr := "SELECT DISTINCT certificate_identity.name_value FROM certificate, certificate_identity WHERE certificate.id = certificate_identity.certificate_id AND digest(certificate.certificate, 'sha256') = $1"

	rows, err := d.db.Query(queryStr, fp[:])
	if err != nil {
		return certnode, err
	}

	for rows.Next() {
		var domain string
		rows.Scan(&domain)
		certnode.Domains = append(certnode.Domains, domain)
	}

	return certnode, nil
}

func (d *crtsh) CTexample(domain string) error {
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
