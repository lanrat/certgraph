package driver

import (
	"github.com/lanrat/certgraph/graph"
)

type Driver interface {
	QueryDomain(domain string, include_expired bool, include_subdomains bool) ([]graph.Fingerprint, error)
	QueryCert(fp graph.Fingerprint) (*graph.CertNode, error)
	CTexample(domain string) error
}
