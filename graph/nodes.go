package graph

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/lanrat/certgraph/status"
)

// structure to store a domain and its edges
type DomainNode struct {
	Domain      string
	Depth       uint
	VisitedCert Fingerprint
	CTCerts     []Fingerprint
	Status      status.DomainStatus
	Root        bool
}

// constructor for DomainNode, converts domain to directDomain
func NewDomainNode(domain string, depth uint) *DomainNode {
	node := new(DomainNode)
	node.Domain = directDomain(domain)
	node.Depth = depth
	node.CTCerts = make([]Fingerprint, 0, 0)
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

func (d *DomainNode) AddCTFingerprint(fp Fingerprint) {
	d.CTCerts = append(d.CTCerts, fp)
}

func (d *DomainNode) ToMap() map[string]string {
	m := make(map[string]string)
	m["type"] = "domain"
	m["id"] = d.Domain
	m["status"] = d.Status.String()
	m["root"] = strconv.FormatBool(d.Root)
	m["depth"] = strconv.FormatUint(uint64(d.Depth), 10)
	return m
}

type CertNode struct {
	Fingerprint Fingerprint
	Domains     []string
	CT          bool
	HTTP        bool
}

func (c *CertNode) String() string {
	//TODO Currently unused..
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

func (c *CertNode) CDNCert() bool {
	for _, domain := range c.Domains {
		// cloudflair
		matched, _ := regexp.MatchString("([0-9][a-z])*\\.cloudflaressl\\.com", domain)
		if matched {
			return true
		}

		if domain == "i.ssl.fastly.net" {
			return true
		}
		// TODO include other CDNs
	}
	return false
}

func (c *CertNode) ToMap() map[string]string {
	m := make(map[string]string)
	m["type"] = "certificate"
	m["id"] = c.Fingerprint.HexString()
	s := ""
	if c.HTTP {
		s = "HTTP "
	}
	if c.CT {
		s = s + "CT"
	}
	m["status"] = strings.TrimSuffix(s, " ")
	return m
}

func NewCertNode(cert *x509.Certificate) *CertNode {
	certnode := new(CertNode)

	// generate Fingerprint
	certnode.Fingerprint = sha256.Sum256(cert.Raw)

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
		certnode.Domains = append(certnode.Domains, domain)
	}
	sort.Strings(certnode.Domains)

	return certnode
}
