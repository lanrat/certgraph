package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
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
var domainGraph = make(map[string]*DomainNode)
var depth uint
var save bool

// flags
var port string
var timeout time.Duration
var verbose bool
var maxDepth uint
var parallel uint
var starttls bool
var sortCerts bool
var savePath string
var list bool
var printJSON bool

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
	Depth       uint `json:"-"`
	Fingerprint []byte
	Neighbors   []string
	Status      domainStatus
}

// constructor for DomainNode, converts domain to directDomain
func NewDomainNode(domain string, depth uint) *DomainNode {
	var node DomainNode
	node.Domain = directDomain(domain)
	node.Depth = depth
	return &node
}

// get the string representation of a node
func (d *DomainNode) String() string {
	if list {
		return fmt.Sprintf("%s", d.Domain)
	}
	return fmt.Sprintf("%s\t%d\t%s\t%X\t%v", d.Domain, d.Depth, d.Status, d.Fingerprint, d.Neighbors)
}

func main() {
	portPtr := flag.Uint("port", 443, "tcp port to connect to")
	timeoutPtr := flag.Uint("timeout", 5, "tcp timeout in seconds")
	flag.BoolVar(&verbose, "verbose", false, "verbose logging")
	flag.UintVar(&maxDepth, "depth", 20, "maximum BFS depth to go")
	flag.UintVar(&parallel, "parallel", 10, "number of certificates to retrieve in parallel")
	flag.BoolVar(&starttls, "starttls", false, "connect without TLS and then upgrade with STARTTLS for SMTP, useful with -port 25")
	flag.BoolVar(&sortCerts, "sort", false, "visit and print domains in sorted order")
	flag.BoolVar(&list, "list", false, "only print the domains found and not the entire graph")
	flag.BoolVar(&printJSON, "json", false, "print the graph as json")
	flag.StringVar(&savePath, "save", "", "save certs to folder in PEM formate")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: [OPTION]... HOST...\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if printJSON {
		// these arguments conflict
		sortCerts = true
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
			v(err)
			return
		}
	}

	BFS(startDomains)

	if printJSON {
		printJSONGraph()
	} else if sortCerts {
		printSortedGraph()
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
	j, err := json.Marshal(domainGraph)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(j))
}

// prints the adjacency list in sorted order
func printSortedGraph() {
	domains := make([]string, 0, len(domainGraph))
	for domain := range domainGraph {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		fmt.Println(domainGraph[domain])
	}
}

// perform Breadth-first_search to build the graph
func BFS(roots []string) {
	var wg sync.WaitGroup
	domainChan := make(chan *DomainNode, 5)
	domainGraphChan := make(chan *DomainNode, 5)

	// thread limit code
	threadPass := make(chan bool, parallel)
	for i := uint(0); i < parallel; i++ {
		threadPass <- true
	}

	for _, root := range roots {
		wg.Add(1)
		domainChan <- NewDomainNode(root, 0)
	}
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
				go func(domainNode *DomainNode) {
					defer wg.Done()
					// wait for pass
					<-threadPass
					defer func() { threadPass <- true }()

					// do things
					v("Visiting", domainNode.Depth, domainNode.Domain)
					BFSPeers(domainNode) // visit
					domainGraphChan <- domainNode
					for _, neighbor := range domainNode.Neighbors {
						wg.Add(1)
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
				if sortCerts {
					domainGraph[domainNode.Domain] = domainNode // not thread safe
				} else {
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

// visit each node and get & set its neighbors
func BFSPeers(node *DomainNode) {
	var certs []*x509.Certificate
	node.Status, certs = getPeerCerts(node.Domain)
	if save && len(certs) > 0 {
		// TODO move to own thread to reduce disk io?
		certToPEMFile(certs, path.Join(savePath, node.Domain)+".pem")
	}

	if len(certs) == 0 {
		return
	}

	// used to ensure uniq entries in domains array
	domainMap := make(map[string]bool)

	if len(certs) > 0 {
		// add the CommonName just to be safe
		cn := strings.ToLower(certs[0].Subject.CommonName)
		if len(cn) > 0 {
			domainMap[cn] = true
		}
		// only bother looking at the first cert
		for _, domain := range certs[0].DNSNames {
			if len(domain) > 0 {
				domain = strings.ToLower(domain)
				domainMap[domain] = true
			}
		}
	}
	// cert fingerprint
	h := sha256.New()
	h.Write(certs[0].Raw)
	node.Fingerprint = h.Sum(nil)

	for domain := range domainMap {
		node.Neighbors = append(node.Neighbors, domain)
	}
	if sortCerts {
		sort.Strings(node.Neighbors)
	}
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
