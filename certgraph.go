package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lanrat/certgraph/driver/ct"
	"github.com/lanrat/certgraph/driver/ct/crtsh"
	"github.com/lanrat/certgraph/driver/ct/google"
	"github.com/lanrat/certgraph/driver/ssl"
	"github.com/lanrat/certgraph/driver/ssl/http"
	"github.com/lanrat/certgraph/driver/ssl/smtp"
	"github.com/lanrat/certgraph/graph"
)

var (
	depth     uint
	gitDate   = "none"
	certGraph = graph.NewCertGraph()
	gitHash   = "DEADBEEF"
	startDomains = make([]string, 0, 1)
)

// driver types
var ctDriver ct.Driver
var sslDriver ssl.Driver

// config & flags
var config struct {
	timeout             time.Duration
	verbose             bool
	maxDepth            uint
	parallel            uint
	savePath            string
	details             bool
	printJSON           bool
	ct                  bool
	driver              string
	includeCTSubdomains bool
	includeCTExpired    bool
	cdn                 bool
	printVersion        bool
}

func init() {
	var timeoutSeconds uint
	flag.BoolVar(&config.printVersion, "version", false, "print version and exit")
	flag.UintVar(&timeoutSeconds, "timeout", 10, "tcp timeout in seconds")
	flag.BoolVar(&config.verbose, "verbose", false, "verbose logging")
	flag.StringVar(&config.driver, "driver", "http", "driver to use [http, smtp, google, crtsh]")
	flag.BoolVar(&config.includeCTSubdomains, "ct-subdomains", false, "include sub-domains in certificate transparency search")
	flag.BoolVar(&config.includeCTExpired, "ct-expired", false, "include expired certificates in certificate transparency search")
	flag.BoolVar(&config.cdn, "cdn", false, "include certificates from CDNs")
	flag.UintVar(&config.maxDepth, "depth", 5, "maximum BFS depth to go")
	flag.UintVar(&config.parallel, "parallel", 10, "number of certificates to retrieve in parallel")
	flag.BoolVar(&config.details, "details", false, "print details about the domains crawled")
	flag.BoolVar(&config.printJSON, "json", false, "print the graph as json, can be used for graph in web UI")
	flag.StringVar(&config.savePath, "save", "", "save certs to folder in PEM format")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: [OPTION]... HOST...\n\thttps://github.com/lanrat/certgraph\nOPTIONS:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	config.timeout = time.Duration(timeoutSeconds) * time.Second
}

func main() {
	if config.printVersion {
		fmt.Println(version())
		return
	}

	if flag.NArg() < 1 {
		flag.Usage()
		return
	}

	if config.parallel < 1 {
		fmt.Fprintln(os.Stderr, "Must enter a positive number of parallel threads")
		flag.Usage()
		return
	}

	for _, domain := range flag.Args() {
		d := strings.ToLower(domain)
		if len(d) > 0 {
			startDomains = append(startDomains, d)
		}
	}

	err := setDriver(config.driver)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(config.savePath) > 0 {
		err := os.MkdirAll(config.savePath, 0777)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	BFS(startDomains)

	if config.printJSON {
		printJSONGraph()
	}

	v("Found", certGraph.Len(), "domains")
	v("Graph Depth:", depth)
}

// setDriver sets the driver variable for the provided driver string and does any necessary driver prep work
func setDriver(driver string) error {
	var err error
	switch driver {
	case "google":
		config.ct = true
		ctDriver, err = google.NewCTDriver(50, config.savePath)
	case "crtsh":
		config.ct = true
		ctDriver, err = crtsh.NewCTDriver(1000, config.timeout, config.savePath)
	case "http":
		sslDriver, err = http.NewSSLDriver(config.timeout, config.savePath)
	case "smtp":
		sslDriver, err = smtp.NewSSLDriver(config.timeout, config.savePath)
		for _, domain := range startDomains {
			mx, err := smtp.GetMX(domain)
			if err == nil {
				startDomains = append(startDomains, mx...)
			}
		}
	default:
		return fmt.Errorf("Unknown driver name: %s", config.driver)
	}
	return err
}

// verbose logging
func v(a ...interface{}) {
	if config.verbose {
		fmt.Fprintln(os.Stderr, a...)
	}
}

// prints the graph as a json object
func printJSONGraph() {
	jsonGraph := certGraph.GenerateMap()
	jsonGraph["certgraph"] = generateGraphMetadata()

	j, err := json.MarshalIndent(jsonGraph, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(j))
}

// BFS perform Breadth first search to build the graph
func BFS(roots []string) {
	var wg sync.WaitGroup
	markedDomains := make(map[string]bool)
	domainChan := make(chan *graph.DomainNode, 5)      // input queue
	domainGraphChan := make(chan *graph.DomainNode, 5) // output queue

	// thread limit code
	threadPass := make(chan bool, config.parallel)
	for i := uint(0); i < config.parallel; i++ {
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
			if domainNode.Depth > config.maxDepth {
				v("Max depth reached, skipping:", domainNode.Domain)
				wg.Done()
				continue
			}
			if domainNode.Depth > depth {
				depth = domainNode.Depth
			}

			if !markedDomains[domainNode.Domain] {
				markedDomains[domainNode.Domain] = true
				certGraph.AddDomain(domainNode)
				go func(domainNode *graph.DomainNode) {
					defer wg.Done()
					// wait for pass
					<-threadPass
					defer func() { threadPass <- true }()

					// do things
					v("Visiting", domainNode.Depth, domainNode.Domain)
					BFSVisit(domainNode) // visit
					domainGraphChan <- domainNode
					for _, neighbor := range certGraph.GetDomainNeighbors(domainNode.Domain, config.cdn) {
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
				if !config.printJSON {
					if config.details {
						fmt.Fprintln(os.Stdout, domainNode)
					} else {
						fmt.Fprintln(os.Stdout, domainNode.Domain)
					}
				} else if config.details {
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

// BFSVisit visit each node and get and set its neighbors
func BFSVisit(node *graph.DomainNode) {
	if config.ct {
		visitCT(node)
	} else {
		visitSSL(node)
	}
}

// visit nodes by searching certificate transparency logs
func visitCT(node *graph.DomainNode) {
	// perform ct search
	// TODO do pagination in multiple threads to not block on long searches
	fingerprints, err := ctDriver.QueryDomain(node.Domain, config.includeCTExpired, config.includeCTSubdomains)
	if err != nil {
		v(err)
		return
	}

	// add cert nodes to graph
	for _, fp := range fingerprints {
		// add certnode to graph

		certNode, exists := certGraph.GetCert(fp)

		if !exists {
			// get cert details
			certNode, err = ctDriver.QueryCert(fp)
			if err != nil {
				v(err)
				continue
			}

			certGraph.AddCert(certNode)
		}

		node.AddCTFingerprint(certNode.Fingerprint)
	}
}

// visit nodes by connecting to them
func visitSSL(node *graph.DomainNode) {
	domainStatus, certNode, err := sslDriver.GetCert(node.Domain)
	if err != nil {
		v(err)
	}
	node.Status = domainStatus

	if certNode != nil {
		certNode, _ = certGraph.LoadOrStoreCert(certNode)
		node.VisitedCert = certNode.Fingerprint
	}
}

func generateGraphMetadata() map[string]interface{} {
	data := make(map[string]interface{})
	data["version"] = version()
	data["website"] = "https://lanrat.github.io"
	data["scan_date"] = time.Now().UTC()
	data["command"] = strings.Join(os.Args, " ")
	options := make(map[string]interface{})
	options["parallel"] = config.parallel
	options["depth"] = depth
	options["driver"] = config.driver
	options["ct_subdomains"] = config.includeCTSubdomains
	options["ct_expired"] = config.includeCTExpired
	options["cdn"] = config.cdn
	options["timeout"] = config.timeout
	data["options"] = options
	return data
}

func version() string {
	return fmt.Sprintf("Git commit: %s [%s]", gitDate, gitHash)
}
