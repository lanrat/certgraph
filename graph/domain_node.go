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
	Domain         string
	Depth          uint
	Certs          map[fingerprint.Fingerprint][]string
	RelatedDomains status.Map
	Status         status.Status
	Root           bool
}

// NewDomainNode constructor for DomainNode, converts domain to nonWildcard
func NewDomainNode(domain string, depth uint) *DomainNode {
	domainNode := new(DomainNode)
	domainNode.Domain = nonWildcard(domain)
	domainNode.Depth = depth
	domainNode.Certs = make(map[fingerprint.Fingerprint][]string)
	domainNode.RelatedDomains = make(status.Map)
	return domainNode
}

// AddRelatedDomains adds the domains in the provided array to the domainNode's
// related domains status map with an unknown status if they are not already
// in the map
func (d *DomainNode) AddRelatedDomains(domains []string) {
	for _, domain := range domains {
		if _, ok := d.RelatedDomains[domain]; ok {
			continue
		}
		d.RelatedDomains[domain] = status.New(status.UNKNOWN)
	}
}

// AddStatusMap adds the status' in the map to the DomainNode
// also sets the Node's own status if it is in the Map
// side effect: will delete its own status from the provided map
func (d *DomainNode) AddStatusMap(m status.Map) {
	if status, ok := m[d.Domain]; ok {
		d.Status = status
		delete(m, d.Domain)
	}
	for domain, status := range m {
		d.RelatedDomains[domain] = status
	}
}

// GetCertificates returns a list of known certificate fingerprints for the domain
func (d *DomainNode) GetCertificates() []fingerprint.Fingerprint {
	fingerprints := make([]fingerprint.Fingerprint, 0, len(d.Certs))
	for fingerprint := range d.Certs {
		fingerprints = append(fingerprints, fingerprint)
	}
	return fingerprints
}

// get the string representation of a node
func (d *DomainNode) String() string {
	certString := ""
	// Certs
	if len(d.Certs) > 0 {
		for fingerprint := range d.Certs {
			certString = fmt.Sprintf("%s %s", certString, fingerprint.HexString())
		}
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s", d.Domain, d.Depth, d.Status.String(), certString)
}

// AddCertFingerprint appends a Fingerprint to the DomainNode's list of certificates
func (d *DomainNode) AddCertFingerprint(fp fingerprint.Fingerprint, certSource string) {
	d.Certs[fp] = append(d.Certs[fp], certSource)
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
	m["related"] = relatedString
	return m
}
