package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
	"sync"
)

// TODO follow https redirects?, MX records? (add www, mx, mail....

type DomainNode struct {
	Domain string
	Depth  int
    Neighbors *[]string
}

// vars
var conf = &tls.Config{
	InsecureSkipVerify: true,
}
var markedDomains = make(map[string]bool)
var domainGraph = make(map[string]*DomainNode) // TODO make node containging depth? domains, and more data? (port(s), backendges, parents)
var timeout time.Duration
var port string
var quiet bool
var depth int
var maxDepth int
var threads int

func checkNetErr(err error) bool {
	if err == nil {
		return false

	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		log.Println("Timeout")
	} else {
		switch t := err.(type) {
		case *net.OpError:
			if t.Op == "dial" {
				log.Println("Unknown host")
			} else if t.Op == "read" {
				log.Println("Connection refused")
			}

		case syscall.Errno:
			if t == syscall.ECONNREFUSED {
				log.Println("Connection refused")
			}
		}
	}
	return true
}

/*
* given a domain returns the non-wildecard version of that domain
 */
func directDomain(domain string) string {
	if domain[0:2] == "*." {
		domain = domain[2:]
	}
	return domain
}

func printGraph() {
	// print map in sorted order
	domains := make([]string, 0, len(domainGraph))
	for domain, _ := range domainGraph {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		fmt.Println(domain, domainGraph[domain].Depth, domainGraph[domain].Neighbors)
	}
}

func main() {
	log.SetFlags(0)
	host := flag.String("host", "localhost", "Host to Scan")
	flag.StringVar(&port, "port", "443", "Port to connect to")
	timeoutPtr := flag.Int("timeout", 5, "TCP Timeout in seconds")
	flag.BoolVar(&quiet, "quiet", false, "Do not print domains as they are visited")
	flag.IntVar(&maxDepth, "depth", 20, "Maximum BFS Depth to go")
	flag.IntVar(&threads, "threads", 10, "Number of certificates to retrieve in parallel")

	flag.Parse()
	if quiet {
		log.SetOutput(ioutil.Discard)
	}
	timeout = time.Duration(*timeoutPtr) * time.Second

	startDomain := strings.ToLower(*host)

	BFS(startDomain)

	log.Println("Done...")

	printGraph()

	log.Println("Found", len(domainGraph), "domains")
	log.Println("Graph Depth:", depth)

}

func BFS(root string) {
	// parallel code
	var wg sync.WaitGroup
	domainChan := make(chan *DomainNode, 5)
	domainGraphChan := make(chan *DomainNode, 5)

	// thread limit code
	threadPass := make(chan bool, threads)
	for i:=0; i< threads; i++ {
		threadPass <-true
	}

	wg.Add(1)
	domainChan <- &DomainNode{root, 0, nil}
	go func() {
		for {
			domainNode := <- domainChan

			// depth check
			if domainNode.Depth > maxDepth {
				log.Println("Max depth reached, skipping:", domainNode.Domain)
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
				 	defer func() {threadPass <- true}()

					// do things
					dDomain := directDomain(domainNode.Domain)
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
			domainNode, more := <- domainGraphChan
			if more {
				dDomain := directDomain(domainNode.Domain)
				domainGraph[dDomain] = domainNode // not thread safe
			} else {
				done <- true
				return
			}
		}
	}()

	wg.Wait() // wait for query to finish
	close(domainGraphChan)
	<-done // wait for save to finish
}

func BFSPeers(host string) []string {
	log.Println("Visiting", host)
	domains := make([]string, 0)
	certs := getPeerCerts(host)

	if len(certs) == 0 {
		return domains
	}

	// used to ensure uniq entries in domains array
	domainMap := make(map[string]bool)

	cn := strings.ToLower(certs[0].Subject.CommonName)
	domainMap[cn] = true

	for _, cert := range certs {
		for _, domain := range cert.DNSNames {
			domain = strings.ToLower(domain)
			domainMap[domain] = true
		}
	}

	for domain, _ := range domainMap {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains

}

func getPeerCerts(host string) []*x509.Certificate {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if checkNetErr(err) {
		return make([]*x509.Certificate, 0)

	}
	conn.Close()
	connState := conn.ConnectionState()
	return connState.PeerCertificates
}
