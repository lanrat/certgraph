// Package main implements certgraph, a tool to crawl the graph of certificate Alternate Names.
//
// CertGraph discovers SSL certificates by building a directed graph where each domain is a node
// and the certificate alternative names are edges to other domain nodes. It supports multiple
// data sources including direct HTTPS connections, SMTP STARTTLS, and Certificate Transparency
// logs via crt.sh and Censys.
//
// The tool is designed for security reconnaissance and certificate discovery, helping to map
// an organization's certificate usage and discover related domains through certificate
// alternative names.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/lanrat/certgraph/dns"
	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/driver/censys"
	"github.com/lanrat/certgraph/driver/crtsh"
	"github.com/lanrat/certgraph/driver/http"
	"github.com/lanrat/certgraph/driver/multi"
	"github.com/lanrat/certgraph/driver/smtp"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/web"
)

var (
	version             = "dev"
	certGraph           = graph.NewCertGraph()
	processedCerts      = make(map[fingerprint.Fingerprint]bool) // Session-wide cache for processed certificates
	processedCertsMutex sync.Mutex                               // Protects processedCerts map
)

// temp flag vars
var (
	timeoutSeconds uint
	regexString    string
)

// webContent holds our static web server content.
//
//go:embed docs/*
var webContent embed.FS

var certDriver driver.Driver

// config & flags
// TODO move driver options to own struct
var config struct {
	timeout             time.Duration
	verbose             bool
	maxDepth            uint
	parallel            uint
	savePath            string
	details             bool
	printJSON           bool
	driver              string
	includeCTSubdomains bool
	includeCTExpired    bool
	cdn                 bool
	maxSANsSize         int
	apex                bool
	updatePSL           bool
	checkDNS            bool
	printVersion        bool
	serve               string
	regex               *regexp.Regexp
}

// init initializes command-line flags and their default values.
// Sets up all configuration options for certificate discovery including
// drivers, timeouts, search parameters, and output formats.
func init() {
	flag.BoolVar(&config.printVersion, "version", false, "print version and exit")
	flag.UintVar(&timeoutSeconds, "timeout", 10, "tcp timeout in seconds")
	flag.BoolVar(&config.verbose, "verbose", false, "verbose logging")
	flag.StringVar(&config.driver, "driver", "http", fmt.Sprintf("driver(s) to use [%s]", strings.Join(driver.Drivers, ", ")))
	flag.BoolVar(&config.includeCTSubdomains, "ct-subdomains", false, "include sub-domains in certificate transparency search")
	flag.BoolVar(&config.includeCTExpired, "ct-expired", false, "include expired certificates in certificate transparency search")
	flag.IntVar(&config.maxSANsSize, "sanscap", 80, "maximum number of uniq apex domains in certificate to include, 0 has no limit")
	flag.BoolVar(&config.cdn, "cdn", false, "include certificates from CDNs")
	flag.BoolVar(&config.checkDNS, "dns", false, "check for DNS records to determine if domain is registered")
	flag.BoolVar(&config.apex, "apex", false, "for every domain found, add the apex domain of the domain's parent")
	flag.BoolVar(&config.updatePSL, "updatepsl", false, "Update the default Public Suffix List")
	flag.UintVar(&config.maxDepth, "depth", 5, "maximum BFS depth to go")
	flag.UintVar(&config.parallel, "parallel", 10, "number of certificates to retrieve in parallel")
	flag.BoolVar(&config.details, "details", false, "print details about the domains crawled")
	flag.BoolVar(&config.printJSON, "json", false, "print the graph as json, can be used for graph in web UI")
	flag.StringVar(&config.savePath, "save", "", "save certs to folder in PEM format")
	flag.StringVar(&config.serve, "serve", "", "address:port to serve html UI on")
	flag.StringVar(&regexString, "regex", "", "regex domains must match to be part of the graph")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s: [OPTION]... HOST...\n\thttps://github.com/lanrat/certgraph\nOPTIONS:\n", os.Args[0])
		flag.PrintDefaults()
	}
}

// main is the entry point for the certgraph application.
// It parses command-line arguments, initializes the selected certificate discovery driver,
// and performs a breadth-first search to build the certificate graph.
func main() {
	flag.Parse()
	config.timeout = time.Duration(timeoutSeconds) * time.Second
	var err error

	// check for version flag
	if config.printVersion {
		fmt.Println(showVersion())
		return
	}

	// check for regex
	if len(regexString) > 0 {
		config.regex, err = regexp.Compile(regexString)
		if err != nil {
			e(err)
			return
		}
	}

	if len(config.serve) > 0 {
		err = web.Serve(config.serve, webContent)
		e(err)
		return
	}

	// print usage if no domain passed
	if flag.NArg() < 1 {
		flag.Usage()
		return
	}

	// cant run on 0 threads
	if config.parallel < 1 {
		fmt.Fprintln(os.Stderr, "Must enter a positive number of parallel threads")
		flag.Usage()
		return
	}

	// update the public suffix list if required
	if config.updatePSL {
		err = dns.UpdatePublicSuffixList(config.timeout)
		if err != nil {
			e(err)
			return
		}
	}

	// add domains passed to startDomains
	startDomains := make([]string, 0, 1)
	for _, domain := range flag.Args() {
		d := strings.ToLower(domain)
		if len(d) > 0 {
			startDomains = append(startDomains, cleanInput(d))
			if config.apex {
				apexDomain, err := dns.ApexDomain(domain)
				if err != nil {
					continue
				}
				startDomains = append(startDomains, apexDomain)
			}
		}
	}

	// set driver
	certDriver, err = setDriver(config.driver)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// create the output directory if it does not exist
	if len(config.savePath) > 0 {
		err := os.MkdirAll(config.savePath, 0755)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	// perform breath-first-search on the graph
	breathFirstSearch(startDomains)

	// print the json output
	if config.printJSON {
		printJSONGraph()
	}

	v("Found", certGraph.NumDomains(), "domains")
	v("Graph Depth:", certGraph.DomainDepth())
}

// setDriver initializes and returns the appropriate certificate discovery driver(s).
// It supports single drivers or multiple comma-separated drivers that will be merged.
func setDriver(name string) (driver.Driver, error) {
	if strings.Contains(name, ",") {
		names := strings.Split(name, ",")
		drivers := make([]driver.Driver, 0, len(names))
		for _, driverName := range names {
			d, err := getDriverSingle(driverName)
			if err != nil {
				return nil, err
			}
			drivers = append(drivers, d)
		}
		return multi.Driver(drivers), nil
	}
	return getDriverSingle(name)
}

// getDriverSingle sets the driver variable for the provided driver string and does any necessary driver prep work
// TODO make config generic and move this to driver module
func getDriverSingle(name string) (driver.Driver, error) {
	var err error
	var d driver.Driver
	switch name {
	case "crtsh":
		d, err = crtsh.Driver(1000, config.timeout, config.savePath, config.includeCTSubdomains, config.includeCTExpired)
	case "http":
		d, err = http.Driver(config.timeout, config.savePath)
	case "smtp":
		d, err = smtp.Driver(config.timeout, config.savePath)
	case "censys":
		d, err = censys.Driver(config.savePath, config.includeCTSubdomains, config.includeCTExpired)
	default:
		return nil, fmt.Errorf("unknown driver name: %s", name)
	}
	return d, err
}

// v prints verbose logging output to stderr when verbose mode is enabled.
func v(a ...interface{}) {
	if config.verbose {
		e(a...)
	}
}

// e prints error messages and general output to stderr.
func e(a ...interface{}) {
	if a != nil {
		fmt.Fprintln(os.Stderr, a...)
	}
}

// printJSONGraph outputs the complete certificate graph as formatted JSON.
// Includes both the graph data and metadata about the scan parameters.
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

// breathFirstSearch performs a breadth-first search to build the certificate graph.
// It starts from the provided root domains and explores certificate alternative names
// to discover related domains, respecting the configured maximum depth and parallelism.
// The function uses multiple goroutines with careful synchronization to efficiently
// process domains concurrently while avoiding duplicate work.
func breathFirstSearch(roots []string) {
	var wg sync.WaitGroup
	// Dynamic buffer sizing based on parallelism and expected workload
	bufferSize := int(config.parallel) * 2
	if bufferSize < 10 {
		bufferSize = 10 // Minimum buffer size
	}
	domainNodeInputChan := make(chan *graph.DomainNode, bufferSize)
	domainNodeOutputChan := make(chan *graph.DomainNode, bufferSize)

	// thread limit code
	threadPass := make(chan bool, config.parallel)
	for i := uint(0); i < config.parallel; i++ {
		threadPass <- true
	}

	// thread to put root nodes/domains into queue
	wg.Add(1)
	go func() {
		// the waitGroup Add and Done for this thread ensures that we don't exit before any of the inputs domains are put into the Queue
		defer wg.Done()
		for _, root := range roots {
			wg.Add(1)
			n := graph.NewDomainNode(root, 0)
			n.Root = true
			domainNodeInputChan <- n
		}
	}()
	// thread to start all other threads from DomainChan
	go func() {
		for domainNode := range domainNodeInputChan {

			// depth check
			if domainNode.Depth > config.maxDepth {
				v("Max depth reached, skipping:", domainNode.Domain)
				wg.Done()
				continue
			}
			// use certGraph.domains map as list of
			// domains that are queued to be visited, or already have been

			if _, found := certGraph.GetDomain(domainNode.Domain); !found {
				certGraph.AddDomain(domainNode)
				go func(domainNode *graph.DomainNode) {
					defer wg.Done()
					// wait for pass
					<-threadPass
					defer func() { threadPass <- true }()

					// regex match check
					if config.regex != nil && !config.regex.MatchString(domainNode.Domain) {
						// skip domain that does not match regex
						v("domain does not match regex, skipping :", domainNode.Domain)
						return
					}

					// operate on the node
					v("Visiting", domainNode.Depth, domainNode.Domain)
					visit(domainNode)
					domainNodeOutputChan <- domainNode
					for _, neighbor := range certGraph.GetDomainNeighbors(domainNode.Domain, config.cdn, config.maxSANsSize) {
						wg.Add(1)
						domainNodeInputChan <- graph.NewDomainNode(neighbor, domainNode.Depth+1)
						if config.apex {
							apexDomain, err := dns.ApexDomain(neighbor)
							if err != nil {
								continue
							}
							wg.Add(1)
							domainNodeInputChan <- graph.NewDomainNode(apexDomain, domainNode.Depth+1)
						}
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
			domainNode, more := <-domainNodeOutputChan
			if more {
				if !config.printJSON {
					printNode(domainNode)
				} else if config.details {
					fmt.Fprintln(os.Stderr, domainNode)
				}
			} else {
				done <- true
				return
			}
		}
	}()

	wg.Wait()                  // wait for querying to finish
	close(domainNodeInputChan) // close input channel to signal goroutine to exit
	close(domainNodeOutputChan)
	<-done // wait for save to finish
}

// visit processes a single domain node to discover and collect certificate information.
// It queries the configured driver for certificates, extracts domain alternatives,
// and updates the graph with discovered relationships. This is the core discovery
// function that implements the certificate crawling logic.
func visit(domainNode *graph.DomainNode) {
	// check NS if necessary
	if config.checkDNS {
		_, err := domainNode.CheckForDNS(config.timeout)
		if err != nil {
			v("CheckForNS", err)
		}
	}

	// perform cert search
	// TODO do pagination in multiple threads to not block on long searches
	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()
	results, err := certDriver.QueryDomain(ctx, domainNode.Domain)
	if err != nil {
		// this is VERY common to error, usually this is a DNS or tcp connection related issue
		// we will skip the domain if we can't query it
		v("QueryDomain", domainNode.Domain, err)
		return
	}
	statuses := results.GetStatus()
	domainNode.AddStatusMap(statuses)
	relatedDomains, err := results.GetRelated()
	if err != nil {
		v("GetRelated", domainNode.Domain, err)
		return
	}
	domainNode.AddRelatedDomains(relatedDomains)

	// TODO fix printing domains as they are found with new driver
	// add cert nodes to graph
	fingerprintMap, err := results.GetFingerprints()
	if err != nil {
		v("GetFingerprints", err)
		return
	}

	// fingerprints for the domain queried
	fingerprints := fingerprintMap[domainNode.Domain]
	
	// Parallelize certificate processing using worker pool
	type certWork struct {
		fp fingerprint.Fingerprint
		result *graph.CertNode
		err error
	}
	
	certChan := make(chan fingerprint.Fingerprint, len(fingerprints))
	resultChan := make(chan certWork, len(fingerprints))
	
	// Start worker goroutines
	numWorkers := min(config.parallel, uint(len(fingerprints)))
	if numWorkers == 0 {
		numWorkers = 1
	}
	
	for i := uint(0); i < numWorkers; i++ {
		go func() {
			for fp := range certChan {
				var work certWork
				work.fp = fp
				
				// Check if we've already attempted to process this certificate
				processedCertsMutex.Lock()
				if processedCerts[fp] {
					processedCertsMutex.Unlock()
					work.err = fmt.Errorf("already processed")
					resultChan <- work
					continue
				}
				processedCerts[fp] = true
				processedCertsMutex.Unlock()

				// get cert details
				certResult, err := results.QueryCert(ctx, fp)
				if err != nil {
					work.err = err
					resultChan <- work
					continue
				}

				work.result = certNodeFromCertResult(certResult)
				resultChan <- work
			}
		}()
	}
	
	// Send work to workers
	workCount := 0
	for _, fp := range fingerprints {
		// Check if cert already exists in graph
		if _, exists := certGraph.GetCert(fp); exists {
			continue
		}
		certChan <- fp
		workCount++
	}
	close(certChan)
	
	// Collect results
	for i := 0; i < workCount; i++ {
		work := <-resultChan
		if work.err != nil {
			if work.err.Error() != "already processed" {
				v("QueryCert", work.err)
			}
			continue
		}
		
		if work.result != nil {
			certGraph.AddCert(work.result)
		}
	}
	
	// Add relationships after all certificates are processed
	for _, fp := range fingerprints {
		certNode, exists := certGraph.GetCert(fp)
		if exists {
			certNode.AddFound(certDriver.GetName())
			domainNode.AddCertFingerprint(certNode.Fingerprint, certDriver.GetName())
		}
	}

	// we don't process any other certificates returned, they will be collected
	//  when we process the related domains
}

// printNode outputs information about a discovered domain node.
// The output format depends on the details flag and includes DNS status if enabled.
func printNode(domainNode *graph.DomainNode) {
	if config.details {
		_, _ = fmt.Fprintln(os.Stdout, domainNode)
	} else {
		_, _ = fmt.Fprintln(os.Stdout, domainNode.Domain)
	}
	if config.checkDNS && !domainNode.HasDNS {
		realDomain, _ := dns.ApexDomain(domainNode.Domain)
		if config.details {
			_, _ = fmt.Fprintf(os.Stdout, "  ⚠ DNS resolution failed for apex domain: %s\n", realDomain)
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "  [NO DNS] %s\n", realDomain)
		}

	}
}

// certNodeFromCertResult convert certResult to certNode
func certNodeFromCertResult(certResult *driver.CertResult) *graph.CertNode {
	certNode := &graph.CertNode{
		Fingerprint: certResult.Fingerprint,
		Domains:     certResult.Domains,
	}
	return certNode
}

// generateGraphMetadata creates metadata information for JSON output.
// Returns a map containing version, scan parameters, and execution details
// for inclusion in the JSON graph output.
func generateGraphMetadata() map[string]interface{} {
	data := make(map[string]interface{})
	data["version"] = version
	data["website"] = "https://lanrat.github.io/certgraph/"
	data["scan_date"] = time.Now().UTC()
	data["command"] = strings.Join(os.Args, " ")
	options := make(map[string]interface{})
	options["parallel"] = config.parallel
	options["driver"] = config.driver
	options["ct_subdomains"] = config.includeCTSubdomains
	options["ct_expired"] = config.includeCTExpired
	options["sanscap"] = config.maxSANsSize
	options["cdn"] = config.cdn
	options["timeout"] = config.timeout
	options["regex"] = regexString
	data["options"] = options
	return data
}

// showVersion returns a formatted version string for display.
func showVersion() string {
	return fmt.Sprintf("Version: %s", version)
}

// cleanInput normalizes domain input by extracting hostnames from URLs and removing trailing dots.
// If URL parsing fails, returns the original string. This helps handle various input formats
// including full URLs, bare domains, and domains with trailing dots.
func cleanInput(host string) string {
	host = strings.TrimSuffix(host, ".")
	u, err := url.Parse(host)
	if err != nil {
		return host
	}
	hostname := u.Hostname()
	if hostname == "" {
		return host
	}
	return hostname
}
