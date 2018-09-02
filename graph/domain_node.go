package graph

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
)

// DomainNode structure to store a domain and its edges
type DomainNode struct {
	Domain string
	Depth  uint
	// VisitedCert fingerprint.Fingerprint
	// TODO change to map of meta -> fingerprint
	Certs          []fingerprint.Fingerprint
	RelatedDomains status.Map
	Status         status.Status
	Root           bool
}

// NewDomainNode constructor for DomainNode, converts domain to directDomain
func NewDomainNode(domain string, depth uint) *DomainNode {
	node := new(DomainNode)
	node.Domain = directDomain(domain)
	node.Depth = depth
	node.Certs = make([]fingerprint.Fingerprint, 0, 0)
	node.RelatedDomains = make(status.Map)
	return node
}

// AddStatusMap adds the status' in the map to the DomainNode
// also sets the Node's own status if it is in the Map
func (d *DomainNode) AddStatusMap(m status.Map) {
	if status, ok := m[d.Domain]; ok {
		d.Status = status
		delete(m, d.Domain)
	}
	for domain, status := range m {
		d.RelatedDomains[domain] = status
	}
}

// get the string representation of a node
func (d *DomainNode) String() string {
	cert := ""
	// Certs
	if len(d.Certs) > 0 {
		for i := range d.Certs {
			cert = fmt.Sprintf("%s %s", cert, d.Certs[i].HexString())
		}
		return fmt.Sprintf("%s\t%d\t%s", d.Domain, d.Depth, cert)
	}
	/*// non-ct
	if d.Status == status.GOOD {
		cert = d.VisitedCert.HexString()
	}*/
	return fmt.Sprintf("%s\t%d\t%s\t%s", d.Domain, d.Depth, d.Status, cert)
}

// AddCertFingerprint appends a Fingerprint to the DomainNode's list of certificates
func (d *DomainNode) AddCertFingerprint(fp fingerprint.Fingerprint) {
	d.Certs = append(d.Certs, fp)
}

// ToMap returns a map of the DomainNode's fields (weak serialization)
func (d *DomainNode) ToMap() map[string]string {
	related := make([]string, 0, len(d.RelatedDomains))
	for domain := range d.RelatedDomains {
		related = append(related, domain)
	}
	relatedString := strings.Join(related, " ")
	m := make(map[string]string)
	m["type"] = "domain"
	m["id"] = d.Domain
	m["status"] = d.Status.String()
	m["root"] = strconv.FormatBool(d.Root)
	m["depth"] = strconv.FormatUint(uint64(d.Depth), 10)
	// TODO store metadata
	m["related"] = relatedString
	return m
}
