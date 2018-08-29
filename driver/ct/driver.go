package ct

import (
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/graph"
)

// Driver interface to set the methods required for CT
type Driver interface {
	QueryDomain(domain string, includeExpired bool, includeSubdomains bool) ([]fingerprint.Fingerprint, error)
	QueryCert(fp fingerprint.Fingerprint) (*graph.CertNode, error)
}
