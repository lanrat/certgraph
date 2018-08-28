package ssl

import (
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/status"
)

// Driver interface to set the methods required for SSL
type Driver interface {
	GetCert(host string) (status.DomainStatus, *graph.CertNode, error)
}
