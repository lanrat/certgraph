package graph

import (
	"sync"

	"github.com/lanrat/certgraph/status"
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
	nodeout, ok := graph.certs.LoadOrStore(node.Fingerprint, node)
	return nodeout.(*CertNode), ok
}

// AddCert add a CertNode to the graph
// TODO check for existing?
func (graph *CertGraph) AddCert(certnode *CertNode) {
	graph.certs.Store(certnode.Fingerprint, certnode)
}

// AddDomain add a DomainNode to the graph
// TODO check for existing?
func (graph *CertGraph) AddDomain(domainnode *DomainNode) {
	graph.numDomains++
	graph.domains.Store(domainnode.Domain, domainnode)
}

//Len returns the number of domains in the graph
func (graph *CertGraph) Len() int {
	return graph.numDomains
}

// GetCert returns (CertNode, found) for the certificate with the provided Fingerprint in the graph if found
func (graph *CertGraph) GetCert(fp Fingerprint) (*CertNode, bool) {
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

	//domain = directDomain(domain)
	node, ok := graph.domains.Load(domain)
	if ok {
		domainnode := node.(*DomainNode)
		// visited cert neighbors
		node, ok := graph.certs.Load(domainnode.VisitedCert)
		if ok {
			certnode := node.(*CertNode)
			if !cdn && certnode.CDNCert() {
				//v(domain, "-> CDN CERT")
			} else {
				for _, neighbor := range certnode.Domains {
					neighbors[neighbor] = true
					//v(domain, "- CERT ->", neighbor)
				}

			}
		}

		// CT neighbors
		for _, fp := range domainnode.CTCerts {
			node, ok := graph.certs.Load(fp)
			if ok {
				certnode := node.(*CertNode)
				if !cdn && certnode.CDNCert() {
					//v(domain, "-> CDN CERT")
				} else {
					for _, neighbor := range certnode.Domains {
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
		domainnode := value.(*DomainNode)
		nodes = append(nodes, domainnode.ToMap())
		if domainnode.Status == status.GOOD {
			links = append(links, map[string]string{"source": domainnode.Domain, "target": domainnode.VisitedCert.HexString(), "type": "uses"})
		}
		return true
	})

	// add all cert nodes
	graph.certs.Range(func(key, value interface{}) bool {
		certnode := value.(*CertNode)
		nodes = append(nodes, certnode.ToMap())
		for _, domain := range certnode.Domains {
			domain := directDomain(domain)
			_, ok := graph.GetDomain(domain)
			if ok {
				links = append(links, map[string]string{"source": certnode.Fingerprint.HexString(), "target": domain, "type": "sans"})
			} // TODO do something with alt-names that are not in graph like wildcards
		}
		return true
	})

	m["nodes"] = nodes
	m["links"] = links
	return m
}
