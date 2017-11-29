package main

import (
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/driver/crtsh"
	"github.com/lanrat/certgraph/driver/google"
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/status"
)

/* TODO
follow http redirects
*/

// vars
var conf = &tls.Config{InsecureSkipVerify: true}
var markedDomains = make(map[string]bool) // TODO move to graph?
var dgraph = graph.NewCertGraph()
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
var include_ct_sub bool
var tls_connect bool
var ver bool
var skipCDN bool
var crtsh_driver bool
var ctDriver driver.Driver

func generateGraphMetadata() map[string]interface{} {
	data := make(map[string]interface{})
	data["version"] = version()
	data["website"] = "https://lanrat.github.io"
	data["scan_date"] = time.Now().UTC()
	data["command"] = strings.Join(os.Args, " ")
	options := make(map[string]interface{})
	options["starttls"] = starttls
	options["parallel"] = parallel
	options["depth"] = depth
	options["tls"] = tls_connect
	options["ct"] = ct
	options["ct_subdomains"] = include_ct_sub
	options["timeout"] = timeout
	options["port"] = port
	data["options"] = options
	return data
}

func version() string {
	return fmt.Sprintf("Git commit: %s [%s]", git_date, git_hash)

}

func main() {
	var notls bool
	flag.BoolVar(&ver, "version", false, "print version and exit")
	portPtr := flag.Uint("port", 443, "tcp port to connect to")
	timeoutPtr := flag.Uint("timeout", 5, "tcp timeout in seconds")
	flag.BoolVar(&verbose, "verbose", false, "verbose logging")
	flag.BoolVar(&ct, "ct", false, "use certificate transparancy search to find certificates")
	flag.BoolVar(&crtsh_driver, "crtsh", false, "use the CRT.sh api instead of Google for CT")
	flag.BoolVar(&include_ct_sub, "ct-subdomains", false, "include sub-domains in certificate transparancy search")
	flag.BoolVar(&skipCDN, "skip-cdn", false, "do not crawl into CDN certs")
	flag.BoolVar(&notls, "notls", false, "don't connect to hosts to collect certificates")
	flag.UintVar(&maxDepth, "depth", 5, "maximum BFS depth to go")
	flag.UintVar(&parallel, "parallel", 10, "number of certificates to retrieve in parallel")
	flag.BoolVar(&starttls, "starttls", false, "connect without TLS and then upgrade with STARTTLS for SMTP, useful with -port 25")
	flag.BoolVar(&details, "details", false, "print details about the domains crawled")
	flag.BoolVar(&printJSON, "json", false, "print the graph as json, can be used for graph in web UI")
	flag.StringVar(&savePath, "save", "", "save certs to folder in PEM formate")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: [OPTION]... HOST...\n\thttps://github.com/lanrat/certgraph\nOPTIONS:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	tls_connect = !notls

	if ver {
		fmt.Println(version())
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

	// TODO better driver support
	if ct {
		var err error
		if crtsh_driver {
			ctDriver, err = crtsh.NewCRTshDriver()
		} else {
			ctDriver, err = google.NewGoogleCTDriver()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	// set verbose loggin
	graph.Verbose = verbose

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

// prnts the graph as a json object
func printJSONGraph() {
	jsonGraph := dgraph.GenerateMap()
	jsonGraph["certgraph"] = generateGraphMetadata()

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
	domainChan := make(chan *graph.DomainNode, 5)      // input queue
	domainGraphChan := make(chan *graph.DomainNode, 5) // output queue

	// thread limit code
	threadPass := make(chan bool, parallel)
	for i := uint(0); i < parallel; i++ {
		threadPass <- true
	}

	// put root nodes/domains into queue
	for _, root := range roots {
		wg.Add(1)
		n := graph.NewDomainNode(root, 0)
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
				dgraph.AddDomain(domainNode)
				go func(domainNode *graph.DomainNode) {
					defer wg.Done()
					// wait for pass
					<-threadPass
					defer func() { threadPass <- true }()

					// do things
					v("Visiting", domainNode.Depth, domainNode.Domain)
					BFSVisit(domainNode) // visit
					domainGraphChan <- domainNode
					for _, neighbor := range dgraph.GetDomainNeighbors(domainNode.Domain, skipCDN) {
						wg.Add(1)
						domainChan <- graph.NewDomainNode(neighbor, domainNode.Depth+1)
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
					if details {
						fmt.Fprintln(os.Stdout, domainNode)
					} else {
						fmt.Fprintln(os.Stdout, domainNode.Domain)
					}
				} else if details {
					fmt.Fprintln(os.Stderr, domainNode)
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
func BFSVisit(node *graph.DomainNode) {
	if tls_connect {
		visitTLS(node)
	}
	if ct {
		visitCT(node)
	}
}

// visit nodes by searching certificate transparancy logs
func visitCT(node *graph.DomainNode) {
	// perform ct search
	// TODO do pagnation in multiple threads to not block on long searches
	fingerprints, err := ctDriver.QueryDomain(node.Domain, false, include_ct_sub)
	if err != nil {
		v(err)
		return
	}

	// add cert nodes to graph
	for _, fp := range fingerprints {
		// add certnode to graph

		certnode, exists := dgraph.GetCert(fp)

		if !exists {
			// get cert details
			certnode, err = ctDriver.QueryCert(fp)
			if err != nil {
				v(err)
				continue
			}

			dgraph.AddCert(certnode)
		}

		certnode.CT = true
		node.AddCTFingerprint(certnode.Fingerprint)
	}
}

// visit nodes by connecting to them
func visitTLS(node *graph.DomainNode) {
	var certs []*x509.Certificate
	node.Status, certs = getPeerCerts(node.Domain)
	if save && len(certs) > 0 {
		certToPEMFile(certs, path.Join(savePath, node.Domain)+".pem")
	}

	if len(certs) == 0 {
		return
	}

	// TODO iterate over all certs, needs to also update dgraph.GetDomainNeighbors() too
	certnode := graph.NewCertNode(certs[0])

	certnode, _ = dgraph.LoadOrStoreCert(certnode)

	certnode.HTTP = true
	node.VisitedCert = certnode.Fingerprint
}

// gets the certificats found for a given domain
func getPeerCerts(host string) (dStatus status.DomainStatus, certs []*x509.Certificate) {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}
	dStatus = status.ERROR

	if starttls {
		conn, err := dialer.Dial("tcp", addr)
		dStatus = status.CheckNetErr(err)
		if dStatus != status.GOOD {
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
		return status.GOOD, connState.PeerCertificates
	} else {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
		dStatus = status.CheckNetErr(err)
		if dStatus != status.GOOD {
			v(dStatus, host)
			return
		}
		conn.Close()
		connState := conn.ConnectionState()
		return status.GOOD, connState.PeerCertificates
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
