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
var markedDomains = make(map[string]bool)
//var domainGraph = make(map[string]*DomainNode)
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
	Status      domainStatus
	Root        bool
}

// constructor for DomainNode, converts domain to directDomain
func NewDomainNode(domain string, depth uint) *DomainNode {
	node := new(DomainNode)
	node.Domain = directDomain(domain)
	node.Depth = depth
	return node
}

// get the string representation of a node
func (d *DomainNode) String() string {
	if details {
		// TODO need to update this and documentation after refractor
		cert := ""
		if d.Status == GOOD {
			cert = d.VisitedCert.HexString()
		}
		return fmt.Sprintf("%s\t%d\t%s\t%s", d.Domain, d.Depth, d.Status, cert)
	}
	return fmt.Sprintf("%s", d.Domain)
}

func (d *DomainNode) ToMap() map[string]string {
	m := make(map[string]string)
	m["type"] = "domain"
	m["id"] = d.Domain
	m["status"] = d.Status.String()
	m["root"] = strconv.FormatBool(d.Root)
	return m
}

type CertNode struct {
	Fingerprint fingerprint
	Domains 	[]string
	CT 			bool
	HTTP		bool
}

func (c *CertNode) String() string {
	// TODO need to update this and documentation after refractor
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
	//TODO switch to syncmap?
	domains  	map[string]*DomainNode
	certs 	 	map[fingerprint]*CertNode

}

func NewCertGraph() *CertGraph {
	graph := new(CertGraph)
	graph.domains = make(map[string]*DomainNode)
	graph.certs = make(map[fingerprint]*CertNode)
	return graph
}

// TODO check for existing?
func (graph CertGraph) AddCert(certnode *CertNode) {
	graph.certs[certnode.Fingerprint] = certnode
}

// TODO check for existing?
func (graph CertGraph) AddDomain(domainnode *DomainNode) {
	graph.domains[domainnode.Domain] = domainnode
}

func (graph CertGraph) GetCert(fp fingerprint) (*CertNode, bool) {
	node, ok := graph.certs[fp]
	return node, ok
}

func (graph CertGraph) GetDomain(domain string) (*DomainNode, bool) {
	node, ok := graph.domains[domain]
	return node, ok
}

func (graph CertGraph) GetDomainNeighbors(domain string) ([]string) {
	neighbors := make([]string, 0, 3)
	//domain = directDomain(domain)
	v("GetDomainNeighbors host", domain)
	node, ok1 := graph.domains[domain]
	if ok1 {
		v("GetDomainNeighbors domainnode", node)
		certnode, ok2 := graph.certs[node.VisitedCert]
		if ok2 {
			v("GetDomainNeighbors cert", certnode)
			neighbors = certnode.Domains
		} 
	}
	return neighbors
}

func (graph CertGraph) GenerateMap() map[string][]map[string]string {
	m := make(map[string][]map[string]string)
	m["nodes"] = make([]map[string]string, 0, 2*len(markedDomains))
	m["links"] = make([]map[string]string, 0, 2*len(markedDomains))


	// add all domain nodes
	for _, domainNode := range graph.domains {
		m["nodes"] = append(m["nodes"], domainNode.ToMap())
		if domainNode.Status == GOOD {
			m["links"] = append(m["links"], map[string]string{"source": domainNode.Domain, "target": domainNode.VisitedCert.HexString(), "type": "uses"})
		}
	}

	// add all cert nodes
	for _, certNode := range graph.certs {
		m["nodes"] = append(m["nodes"], certNode.ToMap())
		for _, domain := range certNode.Domains {
			m["links"] = append(m["links"], map[string]string{"source": certNode.Fingerprint.HexString(), "target": directDomain(domain), "type": "sans"})
		}
	}

	return m
}


func main() {
	flag.BoolVar(&ver, "version", false, "print version and exit")
	portPtr := flag.Uint("port", 443, "tcp port to connect to")
	timeoutPtr := flag.Uint("timeout", 5, "tcp timeout in seconds")
	flag.BoolVar(&verbose, "verbose", false, "verbose logging")
	flag.BoolVar(&ct, "ct", false, "use certificate transparancy instead of connecting to hosts")
	flag.UintVar(&maxDepth, "depth", 20, "maximum BFS depth to go, default: 20")
	flag.UintVar(&parallel, "parallel", 10, "number of certificates to retrieve in parallel, default: 10")
	flag.BoolVar(&starttls, "starttls", false, "connect without TLS and then upgrade with STARTTLS for SMTP, useful with -port 25")
	flag.BoolVar(&details, "details", false, "print details about the domains crawled")
	flag.BoolVar(&printJSON, "json", false, "print the graph as json, can be used for graph in web UI")
	flag.StringVar(&savePath, "save", "", "save certs to folder in PEM formate")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: [OPTION]... HOST...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if ver {
		fmt.Printf("Git commit: [%s] %s\n", git_date, git_hash)
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
	for i := range startDomains {
		startDomains[i] = strings.ToLower(startDomains[i])
	}
	if len(savePath) > 0 {
		save = true
		err := os.MkdirAll(savePath, 0777)
		if err != nil {
			fmt.Println(err);
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
		fmt.Fprintln( os.Stderr, a...)
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
	domainChan := make(chan *DomainNode, 5) // input queue
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
					// TODO iterate over all certs?
					for _, neighbor := range graph.GetDomainNeighbors(domainNode.Domain) {
						wg.Add(1)
						v("Adding node:", domainNode.Domain, neighbor)
						domainChan <- NewDomainNode(neighbor, domainNode.Depth+1)
					}
				}(domainNode)
			} else {
				wg.Done()
			}
		}
	}()

	// save thread
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
// TODO combo mode!
func BFSVisit(node *DomainNode) {
	if ct {
		visitCT(node)
	} else {
		visitTLS(node)
	}
}

// visit nodes by searching certificate transparancy logs
func visitCT(node *DomainNode) {
	node.Status = UNKNOWN
	// get neighbors domains
	/*s, err := QueryDomain(node.Domain, false, false)
	if err != nil {
		v(err)
		return
	}*/
/*
	for i := range s {
		//fmt.Print(s[i].Hash, " ")
		h, err := QueryHash(s[i].Hash)
		if err != nil {
			v(err)
			return
		}
		fmt.Println(h.SerialNumber)
		/*for j := range h.DnsNames {
		    fmt.Println("\t", h.DnsNames[j])
		}*/
//	}

	// lowercase all domains

	// TODO

	// TODO need to refractor so that domaingraph is indexed by cert hash
}

// visit nodes by connecting to them
func visitTLS(node *DomainNode) {
	var certs []*x509.Certificate
	node.Status, certs = getPeerCerts(node.Domain)
	v("num certs:", len(certs))
	if save && len(certs) > 0 {
		// TODO move to own thread to reduce disk io?
		certToPEMFile(certs, path.Join(savePath, node.Domain)+".pem")
	}

	if len(certs) == 0 {
		return
	}

	// TODO iterate over all certs, nedds to also update graph.GetDomainNeighbors() too
	// TODO check for cert already existing before add
	certnode := NewCertNode(certs[0])
	certnode.HTTP = true
	graph.AddCert(certnode)
	v("New cert:", certnode)
	node.VisitedCert = certnode.Fingerprint
}

// gets the certificats found for a given domain
func getPeerCerts(host string) (dStatus domainStatus, certs []*x509.Certificate) {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}
	dStatus = ERROR

	v("peer certs", host)

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
