package graph

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lanrat/certgraph/dns"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
)

// DomainNode represents a domain in the certificate graph with its discovered relationships.
// It tracks the domain's position in the BFS traversal, associated certificates,
// related domains found through various discovery methods, and DNS status.
type DomainNode struct {
	Domain         string                               // The domain name (normalized to lowercase, wildcards removed)
	Depth          uint                                 // BFS depth from root domains (0 for initial domains)
	Certs          map[fingerprint.Fingerprint][]string // Map of certificate fingerprints to discovery sources
	RelatedDomains status.Map                           // Related domains discovered during certificate queries
	Status         status.Status                        // Domain connection status (success, timeout, error, etc.)
	Root           bool                                 // True if this was an initial seed domain
	HasDNS         bool                                 // True if DNS records exist for this domain
}

// NewDomainNode creates a new DomainNode with normalized domain name and specified depth.
// The domain is converted to lowercase and wildcard prefixes are removed for consistency.
// Initializes empty maps for certificates and related domains.
func NewDomainNode(domain string, depth uint) *DomainNode {
	domainNode := new(DomainNode)
	domainNode.Domain = nonWildcard(strings.ToLower(domain))
	domainNode.Depth = depth
	domainNode.Certs = make(map[fingerprint.Fingerprint][]string)
	domainNode.RelatedDomains = make(status.Map)
	return domainNode
}

// AddRelatedDomains adds the domains in the provided slice to the domainNode's
// related domains status map with UNKNOWN status if they are not already present.
// Domain names are normalized to lowercase before adding.
func (d *DomainNode) AddRelatedDomains(domains []string) {
	for _, domain := range domains {
		domain = strings.ToLower(domain)
		if _, ok := d.RelatedDomains[domain]; ok {
			continue
		}
		d.RelatedDomains[domain] = status.New(status.UNKNOWN)
	}
}

// CheckForDNS checks for the existence of DNS records for the domain.
// Updates the node's HasDNS field and returns the result.
// Uses a cached DNS lookup with the specified timeout duration.
func (d *DomainNode) CheckForDNS(timeout time.Duration) (bool, error) {
	hasDNS, err := dns.HasRecordsCache(d.Domain, timeout)

	d.HasDNS = hasDNS
	return hasDNS, err
}

// AddStatusMap adds status information from the provided map to the DomainNode.
// If the map contains a status for this node's domain, it updates the node's Status field
// and removes that entry from the map. All remaining statuses are added to RelatedDomains.
// Side effect: modifies the provided map by removing the node's own status entry.
func (d *DomainNode) AddStatusMap(m status.Map) {
	if status, ok := m[d.Domain]; ok {
		d.Status = status
		delete(m, d.Domain)
	}
	for domain, status := range m {
		d.RelatedDomains[domain] = status
	}
}

// GetCertificates returns a slice of certificate fingerprints associated with this domain.
// The fingerprints represent all certificates discovered for this domain through various drivers.
func (d *DomainNode) GetCertificates() []fingerprint.Fingerprint {
	fingerprints := make([]fingerprint.Fingerprint, 0, len(d.Certs))
	for fingerprint := range d.Certs {
		fingerprints = append(fingerprints, fingerprint)
	}
	return fingerprints
}

// String returns a tab-separated string representation of the domain node.
// Format: domain, depth, status, certificate_fingerprints (space-separated)
func (d *DomainNode) String() string {
	var certBuilder strings.Builder
	// Certs
	if len(d.Certs) > 0 {
		for fingerprint := range d.Certs {
			if certBuilder.Len() > 0 {
				certBuilder.WriteByte(' ')
			}
			certBuilder.WriteString(fingerprint.HexString())
		}
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s", d.Domain, d.Depth, d.Status.String(), certBuilder.String())
}

// AddCertFingerprint associates a certificate fingerprint with this domain node.
// Records the source driver that discovered this certificate-domain relationship.
// Multiple sources can be recorded for the same certificate.
func (d *DomainNode) AddCertFingerprint(fp fingerprint.Fingerprint, certSource string) {
	d.Certs[fp] = append(d.Certs[fp], certSource)
}

// ToMap returns a map representation of the DomainNode for serialization purposes.
// Converts all fields to string values suitable for JSON export and graph visualization.
// Related domains are joined into a space-separated string.
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
	m["hasDNS"] = strconv.FormatBool(d.HasDNS)
	return m
}
