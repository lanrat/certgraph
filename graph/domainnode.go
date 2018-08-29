package graph

import (
	"fmt"
	"strconv"

	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
)

// DomainNode structure to store a domain and its edges
type DomainNode struct {
	Domain      string
	Depth       uint
	VisitedCert fingerprint.Fingerprint
	CTCerts     []fingerprint.Fingerprint
	Status      status.DomainStatus
	Root        bool
}

// NewDomainNode constructor for DomainNode, converts domain to directDomain
func NewDomainNode(domain string, depth uint) *DomainNode {
	node := new(DomainNode)
	node.Domain = directDomain(domain)
	node.Depth = depth
	node.CTCerts = make([]fingerprint.Fingerprint, 0, 0)
	return node
}

// get the string representation of a node
func (d *DomainNode) String() string {
	cert := ""
	// CT
	if len(d.CTCerts) > 0 {
		for i := range d.CTCerts {
			cert = fmt.Sprintf("%s %s", cert, d.CTCerts[i].HexString())
		}
		return fmt.Sprintf("%s\t%d\t%s", d.Domain, d.Depth, cert)
	}
	// non-ct
	if d.Status == status.GOOD {
		cert = d.VisitedCert.HexString()
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s", d.Domain, d.Depth, d.Status, cert)
}

// AddCTFingerprint appends a Fingerprint to the DomainNode
func (d *DomainNode) AddCTFingerprint(fp fingerprint.Fingerprint) {
	d.CTCerts = append(d.CTCerts, fp)
}

// ToMap returns a map of the DomainNode's fields (weak serialization)
func (d *DomainNode) ToMap() map[string]string {
	m := make(map[string]string)
	m["type"] = "domain"
	m["id"] = d.Domain
	m["status"] = d.Status.String()
	m["root"] = strconv.FormatBool(d.Root)
	m["depth"] = strconv.FormatUint(uint64(d.Depth), 10)
	return m
}
