package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

/* TODO
follow http redirects
cert chain
*/

// vars
var conf = &tls.Config{InsecureSkipVerify: true}
var markedDomains = make(map[string]bool) // TODO move to graph?
var graph = NewCertGraph()
var depth uint
var save bool
var git_date = "none"
var git_hash = "DEADBEEF"

// flags
var port string
var timeout time.Duration
var verbose bool
var maxDepth uint
var parallel uint
var starttls bool
var savePath string
var details bool
var printJSON bool
var ct bool
var tls_connect bool
var ver bool

// domain node conection status
type domainStatus int

const (
	UNKNOWN = iota
	GOOD    = iota
	TIMEOUT = iota
	NO_HOST = iota
	REFUSED = iota
	ERROR   = iota
)

type fingerprint [sha256.Size]byte

// print fingerprint as hex
func (fp fingerprint) HexString() string {
	return fmt.Sprintf("%X", fp)
}

// return domain status for printing
func (status domainStatus) String() string {
	switch status {
	case UNKNOWN:
		return "Unknown"
	case GOOD:
		return "Good"
	case TIMEOUT:
		return "Timeout"
	case NO_HOST:
		return "No Host"
	case REFUSED:
		return "Refused"
	case ERROR:
		return "Error"
	}
	return "?"
}

// structure to store a domain and its edges
type DomainNode struct {
	Domain      string
	Depth       uint
	VisitedCert fingerprint
	CTCerts     []fingerprint
	Status      domainStatus
	Root        bool
}

// constructor for DomainNode, converts domain to directDomain
func NewDomainNode(domain string, depth uint) *DomainNode {
	node := new(DomainNode)
	node.Domain = directDomain(domain)
	node.Depth = depth
	node.CTCerts = make([]fingerprint, 0, 0)
	return node
}

// get the string representation of a node
func (d *DomainNode) String() string {
	if details {
		cert := ""
		if d.Status == GOOD {
			cert = d.VisitedCert.HexString()
		}
		return fmt.Sprintf("%s\t%d\t%s\t%s", d.Domain, d.Depth, d.Status, cert)
	}
	return fmt.Sprintf("%s", d.Domain)
}

func (d *DomainNode) AddCTFingerprint(fp fingerprint) {
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
	Fingerprint fingerprint
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

// main graph storage engine
type CertGraph struct {
	domains sync.Map
	certs   sync.Map
}

func NewCertGraph() *CertGraph {
	graph := new(CertGraph)
	return graph
}

func (graph *CertGraph) LoadOrStoreCert(nodein *CertNode) (*CertNode, bool) {
	nodeout, ok := graph.certs.LoadOrStore(nodein.Fingerprint, nodein)
	return nodeout.(*CertNode), ok
}

// TODO check for existing?
func (graph *CertGraph) AddCert(certnode *CertNode) {
	graph.certs.Store(certnode.Fingerprint, certnode)
}

// TODO check for existing?
func (graph *CertGraph) AddDomain(domainnode *DomainNode) {
	graph.domains.Store(domainnode.Domain, domainnode)
}

func (graph *CertGraph) GetCert(fp fingerprint) (*CertNode, bool) {
	node, ok := graph.certs.Load(fp)
	if ok {
		return node.(*CertNode), true
	}
	return nil, false
}

func (graph *CertGraph) GetDomain(domain string) (*DomainNode, bool) {
	node, ok := graph.domains.Load(domain)
	if ok {
		return node.(*DomainNode), true
	}
	return nil, false
}

func (graph *CertGraph) GetDomainNeighbors(domain string) []string {
	neighbors := make(map[string]bool)

	//domain = directDomain(domain)
	node, ok := graph.domains.Load(domain)
	if ok {
		domainnode := node.(*DomainNode)
		// visited cert neighbors
		certnode, ok := graph.certs.Load(domainnode.VisitedCert)
		if ok {
			for _, neighbor := range certnode.(*CertNode).Domains {
				neighbors[neighbor] = true
				v(domain, "- CERT ->", neighbor)
			}
		}

		// CT neighbors
		for _, fp := range domainnode.CTCerts {
			certnode, ok := graph.certs.Load(fp)
			if ok {
				for _, neighbor := range certnode.(*CertNode).Domains {
					neighbors[neighbor] = true
					v(domain, "-- CT -->", neighbor)
				}
			}
		}
	}

	//exclude domain from own neighbors list
	neighbors[domain] = false

	// convert map to array
	neighbor_list := make([]string, 0, len(neighbors))
	for key := range neighbors {
		if neighbors[key] {
			neighbor_list = append(neighbor_list, key)
		}
	}
	return neighbor_list
}

func (graph *CertGraph) GenerateMap() map[string][]map[string]string {
	m := make(map[string][]map[string]string)
	m["nodes"] = make([]map[string]string, 0, 2*len(markedDomains))
	m["links"] = make([]map[string]string, 0, 2*len(markedDomains))

	// add all domain nodes
	graph.domains.Range(func(key, value interface{}) bool {
		domainnode := value.(*DomainNode)
		m["nodes"] = append(m["nodes"], domainnode.ToMap())
		if domainnode.Status == GOOD {
			m["links"] = append(m["links"], map[string]string{"source": domainnode.Domain, "target": domainnode.VisitedCert.HexString(), "type": "uses"})
		}
		return true
	})

	// add all cert nodes
	graph.certs.Range(func(key, value interface{}) bool {
		certnode := value.(*CertNode)
		m["nodes"] = append(m["nodes"], certnode.ToMap())
		for _, domain := range certnode.Domains {
			m["links"] = append(m["links"], map[string]string{"source": certnode.Fingerprint.HexString(), "target": directDomain(domain), "type": "sans"})
		}
		return true
	})

	return m
}

func main() {
	var notls bool
	flag.BoolVar(&ver, "version", false, "print version and exit")
	portPtr := flag.Uint("port", 443, "tcp port to connect to")
	timeoutPtr := flag.Uint("timeout", 5, "tcp timeout in seconds")
	flag.BoolVar(&verbose, "verbose", false, "verbose logging")
	flag.BoolVar(&ct, "ct", false, "use certificate transparancy search to find certificates")
	flag.BoolVar(&notls, "notls", false, "don't connect to hosts to collect certificates")
	flag.UintVar(&maxDepth, "depth", 20, "maximum BFS depth to go")
	flag.UintVar(&parallel, "parallel", 10, "number of certificates to retrieve in parallel")
	flag.BoolVar(&starttls, "starttls", false, "connect without TLS and then upgrade with STARTTLS for SMTP, useful with -port 25")
	flag.BoolVar(&details, "details", false, "print details about the domains crawled")
	flag.BoolVar(&printJSON, "json", false, "print the graph as json, can be used for graph in web UI")
	flag.StringVar(&savePath, "save", "", "save certs to folder in PEM formate")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: [OPTION]... HOST...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	tls_connect = !notls

	if ver {
		fmt.Printf("Git commit: [%s] %s\n", git_date, git_hash)
		return
	}

	if !ct && !tls_connect {
		fmt.Fprintln(os.Stderr, "Must allow TLS or CT or both.")
		return
	}

	if flag.NArg() < 1 {
		flag.Usage()
		return
	}
	if parallel < 1 {
		fmt.Fprintln(os.Stderr, "Must enter a positive number of parallel threads")
		flag.Usage()
		return
	}
	port = strconv.FormatUint(uint64(*portPtr), 10)
	timeout = time.Duration(*timeoutPtr) * time.Second
	startDomains := flag.Args()
	for i, domain := range startDomains {
		startDomains[i] = strings.ToLower(domain)
	}
	if len(savePath) > 0 {
		save = true
		err := os.MkdirAll(savePath, 0777)
		if err != nil {
			fmt.Println(err)
			return
		}
		if !tls_connect {
			fmt.Fprintln(os.Stderr, "Can not save certificates from CT search")
			return
		}
	}

	BFS(startDomains)

	if printJSON {
		printJSONGraph()
	}

	v("Found", len(markedDomains), "domains")
	v("Graph Depth:", depth)
}

// verbose log
func v(a ...interface{}) {
	if verbose {
		fmt.Fprintln(os.Stderr, a...)
	}
}

// Check for errors, print if network related
func checkNetErr(err error) domainStatus {
	if err == nil {
		return GOOD
	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		return TIMEOUT
	} else {
		switch t := err.(type) {
		case *net.OpError:
			if t.Op == "dial" {
				return NO_HOST
			} else if t.Op == "read" {
				return REFUSED
			}
		case syscall.Errno:
			if t == syscall.ECONNREFUSED {
				return REFUSED
			}
		}
	}
	return ERROR
}

// given a domain returns the non-wildcard version of that domain
func directDomain(domain string) string {
	if len(domain) < 3 {
		return domain
	}
	if domain[0:2] == "*." {
		domain = domain[2:]
	}
	return domain
}

// prnts the graph as a json object
func printJSONGraph() {
	jsonGraph := graph.GenerateMap()

	j, err := json.MarshalIndent(jsonGraph, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(j))
}

// perform Breadth first search to build the graph
func BFS(roots []string) {
	var wg sync.WaitGroup
	domainChan := make(chan *DomainNode, 5)      // input queue
	domainGraphChan := make(chan *DomainNode, 5) // output queue

	// thread limit code
	threadPass := make(chan bool, parallel)
	for i := uint(0); i < parallel; i++ {
		threadPass <- true
	}

	// put root nodes/domains into queue
	for _, root := range roots {
		wg.Add(1)
		n := NewDomainNode(root, 0)
		n.Root = true
		domainChan <- n
	}
	// thread to start all other threads from DomainChan
	go func() {
		for {
			domainNode := <-domainChan

			// depth check
			if domainNode.Depth > maxDepth {
				v("Max depth reached, skipping:", domainNode.Domain)
				wg.Done()
				continue
			}
			if domainNode.Depth > depth {
				depth = domainNode.Depth
			}

			if !markedDomains[domainNode.Domain] {
				markedDomains[domainNode.Domain] = true
				graph.AddDomain(domainNode)
				go func(domainNode *DomainNode) {
					defer wg.Done()
					// wait for pass
					<-threadPass
					defer func() { threadPass <- true }()

					// do things
					v("Visiting", domainNode.Depth, domainNode.Domain)
					BFSVisit(domainNode) // visit
					domainGraphChan <- domainNode
					for _, neighbor := range graph.GetDomainNeighbors(domainNode.Domain) {
						wg.Add(1)
						domainChan <- NewDomainNode(neighbor, domainNode.Depth+1)
					}
				}(domainNode)
			} else {
				wg.Done()
			}
		}
	}()

	// save/output thread
	done := make(chan bool)
	go func() {
		for {
			domainNode, more := <-domainGraphChan
			if more {
				if !printJSON {
					fmt.Println(domainNode)
				}
			} else {
				done <- true
				return
			}
		}
	}()

	wg.Wait() // wait for querying to finish
	close(domainGraphChan)
	<-done // wait for save to finish
}

// visit each node and get and set its neighbors
func BFSVisit(node *DomainNode) {
	if tls_connect {
		visitTLS(node)
	}
	if ct {
		visitCT(node)
	}
}

// visit nodes by searching certificate transparancy logs
func visitCT(node *DomainNode) {
	// perform ct search
	// TODO do pagnation in multiple threads to not block on long searches
	search_result, err := QueryDomain(node.Domain, false, false)
	if err != nil {
		v(err)
		return
	}

	// add cert nodes to graph
	for _, result := range search_result {
		// add certnode to graph
		fp := result.GetFingerprint()

		certnode, exists := graph.GetCert(fp)

		if !exists {
			// get cert details
			cert_result, err := QueryHash(result.Hash)
			if err != nil {
				v(err)
				continue
			}

			certnode = new(CertNode)
			certnode.Fingerprint = fp
			certnode.Domains = cert_result.DnsNames
			graph.AddCert(certnode)
		}

		certnode.CT = true
		node.AddCTFingerprint(certnode.Fingerprint)
	}
}

// visit nodes by connecting to them
func visitTLS(node *DomainNode) {
	var certs []*x509.Certificate
	node.Status, certs = getPeerCerts(node.Domain)
	if save && len(certs) > 0 {
		certToPEMFile(certs, path.Join(savePath, node.Domain)+".pem")
	}

	if len(certs) == 0 {
		return
	}

	// TODO iterate over all certs, needs to also update graph.GetDomainNeighbors() too
	certnode := NewCertNode(certs[0])
	certnode, _ = graph.LoadOrStoreCert(certnode)

	certnode.HTTP = true
	node.VisitedCert = certnode.Fingerprint
}

// gets the certificats found for a given domain
func getPeerCerts(host string) (dStatus domainStatus, certs []*x509.Certificate) {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}
	dStatus = ERROR

	if starttls {
		conn, err := dialer.Dial("tcp", addr)
		dStatus = checkNetErr(err)
		if dStatus != GOOD {
			v(dStatus, host)
			return
		}
		defer conn.Close()
		smtp, err := smtp.NewClient(conn, host)
		if err != nil {
			v(err)
			return
		}
		err = smtp.StartTLS(conf)
		if err != nil {
			v(err)
			return
		}
		connState, ok := smtp.TLSConnectionState()
		if !ok {
			return
		}
		return GOOD, connState.PeerCertificates
	} else {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
		dStatus = checkNetErr(err)
		if dStatus != GOOD {
			v(dStatus, host)
			return
		}
		conn.Close()
		connState := conn.ConnectionState()
		return GOOD, connState.PeerCertificates
	}
}

// function to convert certificats to PEM formate
func certToPEMFile(certs []*x509.Certificate, file string) {
	f, err := os.Create(file)
	if err != nil {
		v(err)
		return
	}
	defer f.Close()
	for _, cert := range certs {
		pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
}
