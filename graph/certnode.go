package graph

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/lanrat/certgraph/fingerprint"
)

// CertNode graph node to store certificate information
type CertNode struct {
	Fingerprint fingerprint.Fingerprint
	Domains     []string
	CT          bool
	HTTP        bool
}

func (c *CertNode) String() string {
	ct := ""
	if c.CT {
		ct = "CT"
	}
	http := ""
	if c.HTTP {
		http = "HTTP"
	}
	return fmt.Sprintf("%s\t%s %s\t%v", c.Fingerprint.HexString(), http, ct, c.Domains)
}

// CDNCert returns true if we think the certificate belongs to a CDN
func (c *CertNode) CDNCert() bool {
	for _, domain := range c.Domains {
		// cloudflair
		matched, _ := regexp.MatchString("([0-9][a-z])*\\.cloudflaressl\\.com", domain)
		if matched {
			return true
		}

		if strings.HasSuffix(domain, "fastly.net") {
			return true
		}
		// TODO include other CDNs
		// this detection is weak, might want to change to filter certs with > n alt-names
		// n = 80 might be a good start
	}
	return false
}

// ToMap returns a map of the CertNode's fields (weak serialization)
func (c *CertNode) ToMap() map[string]string {
	m := make(map[string]string)
	m["type"] = "certificate"
	m["id"] = c.Fingerprint.HexString()
	str := ""
	if c.HTTP {
		str = "HTTP "
	}
	if c.CT {
		str = str + "CT"
	}
	m["status"] = strings.TrimSuffix(str, " ")
	return m
}

// NewCertNode creates a CertNode from the provided certificate
func NewCertNode(cert *x509.Certificate) *CertNode {
	certNode := new(CertNode)

	// generate Fingerprint
	certNode.Fingerprint = fingerprint.FromBytes(cert.Raw)

	// domains
	// used to ensure uniq entries in domains array
	domainMap := make(map[string]bool)
	// add the CommonName just to be safe
	cn := strings.ToLower(cert.Subject.CommonName)
	if len(cn) > 0 {
		domainMap[cn] = true
	}
	for _, domain := range cert.DNSNames {
		if len(domain) > 0 {
			domain = strings.ToLower(domain)
			domainMap[domain] = true
		}
	}
	for domain := range domainMap {
		certNode.Domains = append(certNode.Domains, domain)
	}
	sort.Strings(certNode.Domains)

	return certNode
}
