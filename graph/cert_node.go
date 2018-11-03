package graph

import (
	"fmt"
	"strings"

	"github.com/lanrat/certgraph/dns"
	"github.com/lanrat/certgraph/fingerprint"
)

// CertNode graph node to store certificate information
type CertNode struct {
	Fingerprint fingerprint.Fingerprint
	Domains     []string
	foundMap    map[string]bool
}

func (c *CertNode) String() string {
	return fmt.Sprintf("%s\t%s\t%v", c.Fingerprint.HexString(), c.Found(), c.Domains)
}

// Found returns a list of drivers that found this cert
func (c *CertNode) Found() []string {
	found := make([]string, 0, len(c.foundMap))
	for i := range c.foundMap {
		found = append(found, i)
	}
	return found
}

// AddFound adds a driver name to the source of the certificate
func (c *CertNode) AddFound(driver string) {
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

// ApexCount the number of tld+1 domains in the certificate
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

// ToMap returns a map of the CertNode's fields (weak serialization)
func (c *CertNode) ToMap() map[string]string {
	m := make(map[string]string)
	m["type"] = "certificate"
	m["id"] = c.Fingerprint.HexString()
	m["found"] = strings.Join(c.Found(), " ")
	return m
}
