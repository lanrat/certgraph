package ct

import (
	"github.com/lanrat/certgraph/graph"
)

// Driver interface to set the methods required for CT
type Driver interface {
	QueryDomain(domain string, includeExpired bool, includeSubdomains bool) ([]graph.Fingerprint, error)
	QueryCert(fp graph.Fingerprint) (*graph.CertNode, error)
}
