package graph

import (
	"fmt"
	"strings"
	"sync"

	"github.com/lanrat/certgraph/dns"
	"github.com/lanrat/certgraph/fingerprint"
)

// CertNode represents a certificate in the graph with its associated domains.
// It tracks which drivers discovered the certificate and provides thread-safe
// access to the discovery information.
type CertNode struct {
	Fingerprint  fingerprint.Fingerprint // SHA-256 fingerprint of the certificate
	Domains      []string                // List of domains covered by this certificate
	foundMap     map[string]bool         // Map of driver names that found this certificate
	foundMapLock sync.Mutex              // Mutex for thread-safe access to foundMap
}

// String returns a tab-separated string representation of the certificate node.
// Format: fingerprint, found_drivers, domains
func (c *CertNode) String() string {
	return fmt.Sprintf("%s\t%s\t%v", c.Fingerprint.HexString(), c.Found(), c.Domains)
}

// Found returns a list of driver names that discovered this certificate.
// Thread-safe method that returns a copy of the driver list.
func (c *CertNode) Found() []string {
	found := make([]string, 0, len(c.foundMap))
	for i := range c.foundMap {
		found = append(found, i)
	}
	return found
}

// AddFound records that a specific driver discovered this certificate.
// Thread-safe method that initializes the foundMap if needed.
func (c *CertNode) AddFound(driver string) {
	c.foundMapLock.Lock()
	defer c.foundMapLock.Unlock()
	if c.foundMap == nil {
		c.foundMap = make(map[string]bool)
	}
	c.foundMap[driver] = true
}

// CDNCert returns true if we think the certificate belongs to a CDN
// very weak detection, only supports fastly & cloudflare
func (c *CertNode) CDNCert() bool {
	for _, domain := range c.Domains {
		// cloudflare
		if strings.HasSuffix(domain, ".cloudflaressl.com") {
			return true
		}
		// fastly
		if strings.HasSuffix(domain, "fastly.net") {
			return true
		}
		// akamai
		if strings.HasSuffix(domain, ".akamai.net") {
			return true
		}

	}
	return false
}

// ApexCount returns the number of unique apex domains (TLD+1) covered by this certificate.
// This helps identify certificates that cover multiple organizations or domain families.
func (c *CertNode) ApexCount() int {
	apexDomains := make(map[string]bool)
	for _, domain := range c.Domains {
		apexDomain, err := dns.ApexDomain(domain)
		if err != nil {
			continue
		}
		apexDomains[apexDomain] = true
	}
	return len(apexDomains)
}

// ToMap returns a map representation of the certificate node for serialization.
// Used primarily for JSON export functionality.
func (c *CertNode) ToMap() map[string]string {
	m := make(map[string]string)
	m["type"] = "certificate"
	m["id"] = c.Fingerprint.HexString()
	m["found"] = strings.Join(c.Found(), " ")
	return m
}
