// Package graph implements the graph data structures used by certgraph to build the certificate graph
package graph

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lanrat/certgraph/fingerprint"
)

// CertGraph main graph storage engine
type CertGraph struct {
	domains    sync.Map
	certs      sync.Map
	numDomains int64
	depth      uint
}

// NewCertGraph creates and returns a new empty certificate graph.
// The graph uses concurrent-safe maps for storing domains and certificates.
func NewCertGraph() *CertGraph {
	graph := new(CertGraph)
	return graph
}

// AddCert add a CertNode to the graph
func (graph *CertGraph) AddCert(certNode *CertNode) {
	// save the cert to the graph
	// if it already exists we overwrite, it is simpler than checking first.
	graph.certs.Store(certNode.Fingerprint, certNode)
}

// AddDomain add a DomainNode to the graph
func (graph *CertGraph) AddDomain(domainNode *DomainNode) {
	atomic.AddInt64(&graph.numDomains, 1)
	// save the new maximum depth if greater then current
	if domainNode.Depth > graph.depth {
		graph.depth = domainNode.Depth
	}
	// save the domain to the graph
	// if it already exists we overwrite, it is simpler than checking first.
	// graph.numDomains should still be accurate because we only call this after checking that we have not visited the node before.
	graph.domains.Store(domainNode.Domain, domainNode)
}

// NumDomains returns the number of domains in the graph
func (graph *CertGraph) NumDomains() int {
	return int(atomic.LoadInt64(&graph.numDomains))
}

// DomainDepth returns the maximum depth of the graph from the initial root domains
func (graph *CertGraph) DomainDepth() uint {
	return graph.depth
}

// GetCert returns (CertNode, found) for the certificate with the provided Fingerprint in the graph if found
func (graph *CertGraph) GetCert(fp fingerprint.Fingerprint) (*CertNode, bool) {
	node, ok := graph.certs.Load(fp)
	if ok {
		return node.(*CertNode), true
	}
	return nil, false
}

// GetDomain returns (DomainNode, found) for the domain in the graph if found
func (graph *CertGraph) GetDomain(domain string) (*DomainNode, bool) {
	node, ok := graph.domains.Load(domain)
	if ok {
		return node.(*DomainNode), true
	}
	return nil, false
}

// GetDomainNeighbors given a domain, return the list of all other domains that share a certificate with the provided domain that are in the graph
// cdn will include CDN certs as well
func (graph *CertGraph) GetDomainNeighbors(domain string, cdn bool, maxSANsSize int) []string {
	neighbors := make(map[string]bool)

	domain = nonWildcard(domain)
	node, ok := graph.domains.Load(domain)
	if ok {
		domainNode := node.(*DomainNode)
		// related cert neighbors
		for relatedDomain := range domainNode.RelatedDomains {
			neighbors[relatedDomain] = true
		}

		// Cert neighbors
		for _, fp := range domainNode.GetCertificates() {
			node, ok := graph.certs.Load(fp)
			if ok {
				certNode := node.(*CertNode)
				if !cdn && certNode.CDNCert() {
					//v(domain, "-> CDN CERT")
				} else if maxSANsSize > 0 && certNode.ApexCount() > maxSANsSize {
					//v(domain, "-> Large CERT")
				} else {
					for _, neighbor := range certNode.Domains {
						neighbors[neighbor] = true
						//v(domain, "-- CT -->", neighbor)
					}
				}
			}
		}
	}

	//exclude domain from own neighbors list
	neighbors[domain] = false

	// convert map to array
	neighborList := make([]string, 0, len(neighbors))
	for key := range neighbors {
		if neighbors[key] {
			neighborList = append(neighborList, key)
		}
	}
	return neighborList
}

// GenerateMap returns a map representation of the certificate graph
// used for JSON serialization
func (graph *CertGraph) GenerateMap() map[string]interface{} {
	m := make(map[string]interface{})
	nodes := make([]map[string]string, 0, 2*graph.numDomains)
	links := make([]map[string]string, 0, 2*graph.numDomains)

	// add all domain nodes
	graph.domains.Range(func(key, value interface{}) bool {
		domainNode := value.(*DomainNode)
		nodes = append(nodes, domainNode.ToMap())
		for fingerprint, found := range domainNode.Certs {
			links = append(links, map[string]string{"source": domainNode.Domain, "target": fingerprint.HexString(), "type": strings.Join(found, " ")})
		}
		return true
	})

	// add all cert nodes
	graph.certs.Range(func(key, value interface{}) bool {
		certNode := value.(*CertNode)
		nodes = append(nodes, certNode.ToMap())
		for _, domain := range certNode.Domains {
			domain = nonWildcard(domain)
			_, ok := graph.GetDomain(domain)
			if ok {
				links = append(links, map[string]string{"source": certNode.Fingerprint.HexString(), "target": domain, "type": "sans"})
			}
		}
		return true
	})

	m["nodes"] = nodes
	m["links"] = links
	m["depth"] = graph.depth
	m["numDomains"] = graph.numDomains
	return m
}
