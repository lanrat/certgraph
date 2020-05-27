// Package driver exposes interfaces and types certgraph drivers must implement
package driver

import (
	"crypto/x509"
	"sort"
	"strings"

	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
)

// TODO add context instead of timeout on all requests

// Drivers contains all the drivers that have been registered
var Drivers []string

// AddDriver should be called in the init() function of every driver to register them here
func AddDriver(name string) {
	Drivers = append(Drivers, name)
}

// Driver is a universal unifying interface to support CT, http and much more!
type Driver interface {
	// QueryDomain is the main entrypoint for Driver Searching
	// The domain provided will return a CertDriver instance which can be used to query the
	// certificates for the provided domain using the driver
	QueryDomain(domain string) (Result, error)

	// GetName returns the name of the driver
	GetName() string
}

// Result is a sub-driver that allows querying certificate details from a previously queried domain
type Result interface {
	// GetStatus returns the status of the initial domain queried with the Driver.QueryDomain call
	GetStatus() status.Map

	// returns a list of additional related domains discovered while looking up the provided domain
	GetRelated() ([]string, error)

	// GetFingerprints returns an array of the certificate fingerprints associated with the Domain
	// pass return fingerprints to QueryCert to get certificate details
	GetFingerprints() (FingerprintMap, error)

	// QueryCert returns the details of the provided certificate or an error if not found
	QueryCert(fp fingerprint.Fingerprint) (*CertResult, error)
}

// FingerprintMap stores a mapping of domains to Fingerprints returned from the driver
// in the case where multiple domains where queries (redirects, related, etc..) the
// matching certificates will be in this map
// the fingerprints returned are guaranteed to be a complete result for the domain's certs, but related domains may or may not be complete
type FingerprintMap map[string][]fingerprint.Fingerprint

// Add adds a domain and fingerprint to the map
func (f FingerprintMap) Add(domain string, fp fingerprint.Fingerprint) {
	f[domain] = append(f[domain], fp)
}

// CertResult is an object to hold the fingerprint and Domains for a returned certificate
type CertResult struct {
	Fingerprint fingerprint.Fingerprint
	Domains     []string
}

// NewCertResult creates a new CertResult struct from an x509 cert
func NewCertResult(cert *x509.Certificate) *CertResult {
	certResult := new(CertResult)

	// generate Fingerprint
	certResult.Fingerprint = fingerprint.FromBytes(cert.Raw)

	// domains
	// used to ensure uniq entries in domains array
	domainMap := make(map[string]bool)
	// add the CommonName just to be safe
	cn := strings.ToLower(cert.Subject.CommonName)
	if len(cn) > 0 {
		domainMap[cn] = true
	}
	for _, domain := range cert.DNSNames {
		if len(domain) > 0 {
			domain = strings.ToLower(domain)
			domainMap[domain] = true
		}
	}
	for domain := range domainMap {
		certResult.Domains = append(certResult.Domains, domain)
	}
	sort.Strings(certResult.Domains)

	return certResult
}
