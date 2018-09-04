package crtsh

/*
 * This file implements an unofficial API client for Comodo's
 * Certificate Transparency search
 * https://crt.sh/
 *
 * As the API is unofficial and has been reverse engineered it may stop working
 * at any time and comes with no guarantees.
 */

// TODO running in verbose gives error: pq: unnamed prepared statement does not exist

import (
	"database/sql"
	"fmt"
	"path"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
	_ "github.com/lib/pq" // portgresql
)

const connStr = "postgresql://guest@crt.sh/certwatch?sslmode=disable"
const driverName = "crtsh"

func init() {
	driver.AddDriver(driverName)
}

type crtsh struct {
	db                *sql.DB
	queryLimit        int
	timeout           time.Duration
	save              bool
	savePath          string
	includeSubdomains bool
	includeExpired    bool
}

type crtshCertDriver struct {
	host         string
	fingerprints driver.FingerprintMap
	driver       *crtsh
}

func (c *crtshCertDriver) GetFingerprints() (driver.FingerprintMap, error) {
	return c.fingerprints, nil
}

func (c *crtshCertDriver) GetStatus() status.Map {
	return status.NewMap(c.host, status.New(status.CT))
}

func (c *crtshCertDriver) GetRelated() ([]string, error) {
	return make([]string, 0), nil
}

func (c *crtshCertDriver) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	return c.driver.QueryCert(fp)
}

// Driver creates a new CT driver for crt.sh
func Driver(maxQueryResults int, timeout time.Duration, savePath string, includeSubdomains, includeExpired bool) (driver.Driver, error) {
	d := new(crtsh)
	d.queryLimit = maxQueryResults
	d.includeSubdomains = includeSubdomains
	d.includeExpired = includeExpired
	var err error

	if len(savePath) > 0 {
		d.save = true
		d.savePath = savePath
	}

	d.db, err = sql.Open("postgres", connStr)

	d.setSQLTimeout(d.timeout.Seconds())

	return d, err
}

func (d *crtsh) GetName() string {
	return driverName
}

func (d *crtsh) setSQLTimeout(sec float64) error {
	_, err := d.db.Exec(fmt.Sprintf("SET statement_timeout TO %f;", (1000 * sec)))
	return err
}

func (d *crtsh) QueryDomain(domain string) (driver.Result, error) {
	results := &crtshCertDriver{
		host:         domain,
		fingerprints: make(driver.FingerprintMap),
		driver:       d,
	}

	queryStr := ""

	if d.includeSubdomains {
		if d.includeExpired {
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
		if d.includeExpired {
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

	if d.includeSubdomains {
		domain = fmt.Sprintf("%%.%s", domain)
	}

	try := 0
	var err error
	var rows *sql.Rows
	for try < 5 {
		// this is a hack while crt.sh gets there stuff togeather
		try++
		rows, err = d.db.Query(queryStr, domain, d.queryLimit)
		if err == nil {
			break
		}
	}
	/*if try > 1 {
		fmt.Println("QueryDomain try ", try)
	}*/
	if err != nil {
		return results, err
	}

	for rows.Next() {
		var hash []byte
		err = rows.Scan(&hash)
		if err != nil {
			return results, err
		}
		results.fingerprints.Add(domain, fingerprint.FromHashBytes(hash))
	}

	return results, nil
}

func (d *crtsh) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	certNode := new(driver.CertResult)
	certNode.Fingerprint = fp
	certNode.Domains = make([]string, 0, 5)

	queryStr := `SELECT DISTINCT certificate_identity.name_value
				FROM certificate, certificate_identity
				WHERE certificate.id = certificate_identity.certificate_id
				AND certificate_identity.name_type in ('dNSName', 'commonName')
				AND digest(certificate.certificate, 'sha256') = $1`

	try := 0
	var err error
	var rows *sql.Rows
	for try < 5 {
		// this is a hack while crt.sh gets there stuff togeather
		try++
		rows, err = d.db.Query(queryStr, fp[:])
		if err == nil {
			break
		}
	}
	/*if try > 1 {
		fmt.Println("QueryCert try ", try)
	}*/
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

		driver.RawCertToPEMFile(rawCert, path.Join(d.savePath, fp.HexString())+".pem")
	}

	return certNode, nil
}
