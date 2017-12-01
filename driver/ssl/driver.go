package ssl

import (
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/status"
)

type Driver interface {
	GetCert(host string) (status.DomainStatus, *graph.CertNode, error)
}
