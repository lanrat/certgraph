package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

/* TODO
follow http redirects
starttls
*/

// structure to store a domain and its edges
type DomainNode struct {
	Domain    string
	Depth     uint
	Neighbors *[]string
}

// vars
var conf = &tls.Config{InsecureSkipVerify: true}
var markedDomains = make(map[string]bool)
var domainGraph = make(map[string]*DomainNode)
var depth uint

// flags
var port string
var timeout time.Duration
var verbose bool
var maxDepth uint
var parallel uint

func main() {
	portPtr := flag.Uint("port", 443, "tcp port to connect to")
	timeoutPtr := flag.Uint("timeout", 5, "tcp timeout in seconds")
	flag.BoolVar(&verbose, "verbose", false, "verbose logging")
	flag.UintVar(&maxDepth, "depth", 20, "maximum BFS depth to go")
	flag.UintVar(&parallel, "parallel", 10, "number of certificates to retrieve in parallel")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: [OPTION]... HOST...\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Pass at least one host to scan")
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

	BFS(startDomains)

	v("Done...")

	printGraph()
	v("Found", len(domainGraph), "domains")
	v("Graph Depth:", depth)
}

// verbose log
func v(a ...interface{}) {
	if verbose {
		fmt.Fprintln(os.Stderr, a...)
	}
}

// Check for errors, print if network related
func checkNetErr(err error, domain string) bool {
	if err == nil {
		return false

	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		v("Timeout", domain)
	} else {
		switch t := err.(type) {
		case *net.OpError:
			if t.Op == "dial" {
				v("Unknown host", domain)
			} else if t.Op == "read" {
				v("Connection refused", domain)
			}

		case syscall.Errno:
			if t == syscall.ECONNREFUSED {
				v("Connection refused", domain)
			}
		}
	}
	return true
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

// prints the adjacency list in sorted order
func printGraph() {
	domains := make([]string, 0, len(domainGraph))
	for domain, _ := range domainGraph {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		fmt.Println(domain, domainGraph[domain].Depth, *domainGraph[domain].Neighbors)
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
		domainChan <- &DomainNode{root, 0, nil}
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

			dDomain := directDomain(domainNode.Domain)
			if !markedDomains[dDomain] {
				markedDomains[dDomain] = true
				go func(domainNode *DomainNode) {
					defer wg.Done()
					// wait for pass
					<-threadPass
					defer func() { threadPass <- true }()

					// do things
					dDomain := directDomain(domainNode.Domain)
					v("Visiting", domainNode.Depth, dDomain)
					neighbors := BFSPeers(dDomain) // visit
					domainNode.Neighbors = &neighbors
					domainGraphChan <- domainNode
					for _, neighbor := range neighbors {
						wg.Add(1)
						domainChan <- &DomainNode{neighbor, domainNode.Depth + 1, nil}
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
				dDomain := directDomain(domainNode.Domain)
				domainGraph[dDomain] = domainNode // not thread safe
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

// visit each node and get its neighbors
func BFSPeers(host string) []string {
	domains := make([]string, 0)
	certs := getPeerCerts(host)

	if len(certs) == 0 {
		return domains
	}

	// used to ensure uniq entries in domains array
	domainMap := make(map[string]bool)

	// add the CommonName just to be safe
	if len(certs) > 0 {
		cn := strings.ToLower(certs[0].Subject.CommonName)
		if len(cn) > 0 {
			domainMap[cn] = true
		}
	}

	for _, cert := range certs {
		for _, domain := range cert.DNSNames {
			if len(domain) > 0 {
				domain = strings.ToLower(domain)
				domainMap[domain] = true
			}
		}
	}

	for domain, _ := range domainMap {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains

}

// gets the certificats found for a given domain
func getPeerCerts(host string) []*x509.Certificate {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if checkNetErr(err, host) {
		return make([]*x509.Certificate, 0)

	}
	conn.Close()
	connState := conn.ConnectionState()
	return connState.PeerCertificates
}
