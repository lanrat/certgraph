// Package crtsh implements an unofficial API client for Comodo's
// Certificate Transparency search
// https://crt.sh/
//
// As the API is unofficial and has been reverse engineered it may stop working
// at any time and comes with no guarantees.
// view SQL example: https://crt.sh/?showSQL=Y&exclude=expired&q=
package crtsh

import (
	"database/sql"
	"fmt"
	"log"
	"path"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
	_ "github.com/lib/pq"
)

const connStr = "postgresql://guest@crt.sh/certwatch?sslmode=disable&fallback_application_name=certgraph&binary_parameters=yes"
const driverName = "crtsh"

const debug = false

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
	return nil, nil // Return nil instead of empty slice for better memory efficiency
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
	if err != nil {
		return nil, err
	}

	// Configure connection pool to prevent resource leaks and optimize for concurrent usage
	// Scale connections based on expected load patterns
	d.db.SetMaxOpenConns(25)                  // Increased for better concurrency
	d.db.SetMaxIdleConns(5)                   // More idle connections for faster reconnection
	d.db.SetConnMaxLifetime(30 * time.Minute) // Shorter lifetime for better connection health
	d.db.SetConnMaxIdleTime(5 * time.Minute)  // Close idle connections sooner

	err = d.setSQLTimeout(d.timeout.Seconds())

	return d, err
}

func (d *crtsh) GetName() string {
	return driverName
}

// Close closes the database connection
func (d *crtsh) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
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

	queryStr := `WITH myconstants (include_expired, include_subdomains) as (
		values ($1::bool, $2::bool)
	 ),
	 ci AS (
		 SELECT digest(sub.CERTIFICATE, 'sha256') sha256, -- added
				min(sub.CERTIFICATE_ID) ID,
				min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
				array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES
			 FROM (SELECT *
					   FROM certificate_and_identities cai, myconstants
					   WHERE plainto_tsquery('certwatch', $4) @@ identities(cai.CERTIFICATE)
						  AND (
							  -- domain only
							  (NOT myconstants.include_subdomains AND cai.NAME_VALUE ILIKE ($4))
							  OR
							  -- include sub-domains
							  (myconstants.include_subdomains AND (cai.NAME_VALUE ILIKE ($4) OR cai.NAME_VALUE ILIKE ('%.' || $4)))
						  )
						   AND (
							   -- added
							   cai.NAME_TYPE = '2.5.4.3' -- commonName
							   OR
								 cai.NAME_TYPE = 'san:dNSName' -- dNSName
							   )
						   AND
							   -- include expired?
							   (myconstants.include_expired OR (coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')
							   AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'))
					   LIMIT $3
				  ) sub
			 GROUP BY sub.CERTIFICATE
	 )
	 SELECT
		 ci.sha256 -- added
		 --array_to_string(ci.name_values, chr(10)) name_value,
		 --ci.id id
		 FROM ci;`

	try := 0
	var err error
	var rows *sql.Rows
	baseDelay := 100 * time.Millisecond

	for try < 5 {
		// this is a hack while crt.sh gets there stuff together
		try++
		if debug {
			log.Printf("QueryDomain try %d: %s", try, queryStr)
		}
		rows, err = d.db.Query(queryStr, d.includeExpired, d.includeSubdomains, d.queryLimit, domain)
		if err == nil {
			break
		}
		if debug {
			log.Printf("crtsh pq error on domain %q: %s", domain, err.Error())
		}

		// Exponential backoff before retry (except on last attempt)
		if try < 5 {
			delay := baseDelay * time.Duration(1<<(try-1)) // 100ms, 200ms, 400ms, 800ms
			time.Sleep(delay)
		}
	}
	/*if try > 1 {
		fmt.Println("QueryDomain try ", try)
	}*/
	if err != nil {
		return results, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var hash []byte
		err = rows.Scan(&hash)
		if err != nil {
			return results, err
		}
		results.fingerprints.Add(domain, fingerprint.FromHashBytes(hash))
	}

	if debug {
		log.Printf("crtsh: got %d results for %s.", len(results.fingerprints[domain]), domain)
	}

	return results, nil
}

func (d *crtsh) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	certNode := new(driver.CertResult)
	certNode.Fingerprint = fp
	certNode.Domains = make([]string, 0, 5)

	queryStr := `SELECT DISTINCT NAME_VALUE FROM certificate_and_identities WHERE digest(certificate, 'sha256') = $1 AND (NAME_TYPE = '2.5.4.3' OR NAME_TYPE = 'san:dNSName');`

	try := 0
	var err error
	var rows *sql.Rows
	baseDelay := 100 * time.Millisecond

	for try < 5 {
		// this is a hack while crt.sh gets there stuff together
		try++
		rows, err = d.db.Query(queryStr, fp[:])
		if err == nil {
			break
		}

		// Exponential backoff before retry (except on last attempt)
		if try < 5 {
			delay := baseDelay * time.Duration(1<<(try-1)) // 100ms, 200ms, 400ms, 800ms
			time.Sleep(delay)
		}
	}
	/*if try > 1 {
		fmt.Println("QueryCert try ", try)
	}*/
	if err != nil {
		return certNode, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var domain string
		err = rows.Scan(&domain)
		if err != nil {
			return nil, err
		}
		certNode.Domains = append(certNode.Domains, domain)
	}

	if d.save {
		var rawCert []byte
		queryStr = `SELECT certificate FROM certificate_and_identities WHERE digest(certificate, 'sha256') = $1;`
		row := d.db.QueryRow(queryStr, fp[:])
		err = row.Scan(&rawCert)
		if err != nil {
			return certNode, err
		}

		err = driver.RawCertToPEMFile(rawCert, path.Join(d.savePath, fp.HexString())+".pem")
		if err != nil {
			return certNode, err
		}
	}

	return certNode, nil
}
