package graph

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/lanrat/certgraph/fingerprint"
	"golang.org/x/net/publicsuffix"
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
// very weak detection, only supports fastly & cloudflair
func (c *CertNode) CDNCert() bool {
	for _, domain := range c.Domains {
		// cloudflair
		matched, _ := regexp.MatchString("([0-9][a-z])*\\.cloudflaressl\\.com", domain)
		if matched {
			return true
		}
		// fastly
		if strings.HasSuffix(domain, "fastly.net") {
			return true
		}
	}
	return false
}

// TLDPlus1Count the number of tld+1 domains in the certificate
func (c *CertNode) TLDPlus1Count() int {
	tldPlus1Domains := make(map[string]bool)
	for _, domain := range c.Domains {
		tldPlus1, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			continue
		}
		tldPlus1Domains[tldPlus1] = true
	}
	return len(tldPlus1Domains)
}

// ToMap returns a map of the CertNode's fields (weak serialization)
func (c *CertNode) ToMap() map[string]string {
	m := make(map[string]string)
	m["type"] = "certificate"
	m["id"] = c.Fingerprint.HexString()
	m["found"] = strings.Join(c.Found(), " ")
	return m
}
