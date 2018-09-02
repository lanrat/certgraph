package graph

import (
	"sync"

	"github.com/lanrat/certgraph/fingerprint"
)

// CertGraph main graph storage engine
type CertGraph struct {
	domains    sync.Map
	certs      sync.Map
	numDomains int
}

// NewCertGraph instantiates a new empty CertGraph
func NewCertGraph() *CertGraph {
	graph := new(CertGraph)
	return graph
}

// LoadOrStoreCert will return the CertNode in the graph with the provided node's fingerprint, or store the node if it did not already exist
// returned bool is true if the CertNode was found, false if stored
func (graph *CertGraph) LoadOrStoreCert(node *CertNode) (*CertNode, bool) {
	foundNode, ok := graph.certs.LoadOrStore(node.Fingerprint, node)
	return foundNode.(*CertNode), ok
}

// AddCert add a CertNode to the graph
func (graph *CertGraph) AddCert(certnode *CertNode) {
	// save the cert to the graph
	// if it already exists we overwrite, it is simpler than checking first.
	graph.certs.Store(certnode.Fingerprint, certnode)
}

// AddDomain add a DomainNode to the graph
func (graph *CertGraph) AddDomain(domainnode *DomainNode) {
	graph.numDomains++
	// save the domain to the graph
	// if it already exists we overwrite, it is simpler than checking first.
	// graph.numDomains should still be accurate because we only call this after checking that we have not visited the node before.
	graph.domains.Store(domainnode.Domain, domainnode)
}

//Len returns the number of domains in the graph
func (graph *CertGraph) Len() int {
	return graph.numDomains
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
func (graph *CertGraph) GetDomainNeighbors(domain string, cdn bool) []string {
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
		for _, fp := range domainNode.Certs {
			node, ok := graph.certs.Load(fp)
			if ok {
				certNode := node.(*CertNode)
				if !cdn && certNode.CDNCert() {
					//v(domain, "-> CDN CERT")
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
		// TODO replace this with something once I create a replacement for DomainNode.VisitedCert.
		/*if domainNode.Status == status.GOOD {
			links = append(links, map[string]string{"source": domainNode.Domain, "target": domainNode.VisitedCert.HexString(), "type": "uses"})
		}*/
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
	return m
}
