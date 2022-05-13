package main

import (
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
	"github.com/lanrat/certgraph/driver/google"
	"github.com/lanrat/certgraph/driver/http"
	"github.com/lanrat/certgraph/driver/multi"
	"github.com/lanrat/certgraph/driver/smtp"
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/web"
)

// version vars
var (
	gitDate   = "none"
	gitHash   = "master"
	certGraph = graph.NewCertGraph()
)

// temp flag vars
var (
	timeoutSeconds uint
	regexString    string
)

// webContent holds our static web server content.
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

func main() {
	flag.Parse()
	config.timeout = time.Duration(timeoutSeconds) * time.Second
	var err error

	// check for version flag
	if config.printVersion {
		fmt.Println(version())
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
		err := os.MkdirAll(config.savePath, 0777)
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
	case "google":
		d, err = google.Driver(50, config.savePath, config.includeCTSubdomains, config.includeCTExpired)
	case "crtsh":
		d, err = crtsh.Driver(1000, config.timeout, config.savePath, config.includeCTSubdomains, config.includeCTExpired)
	case "http":
		d, err = http.Driver(config.timeout, config.savePath)
	case "smtp":
		d, err = smtp.Driver(config.timeout, config.savePath)
	case "censys":
		d, err = censys.Driver(config.savePath, config.includeCTSubdomains, config.includeCTExpired)
	default:
		return nil, fmt.Errorf("unknown driver name: %s", config.driver)
	}
	return d, err
}

// verbose logging
func v(a ...interface{}) {
	if config.verbose {
		e(a...)
	}
}

func e(a ...interface{}) {
	if a != nil {
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

// breathFirstSearch perform Breadth first search to build the graph
func breathFirstSearch(roots []string) {
	var wg sync.WaitGroup
	domainNodeInputChan := make(chan *graph.DomainNode, 5)  // input queue
	domainNodeOutputChan := make(chan *graph.DomainNode, 5) // output queue

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
		for {
			domainNode := <-domainNodeInputChan

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

	wg.Wait() // wait for querying to finish
	close(domainNodeOutputChan)
	<-done // wait for save to finish
}

// visit visits each node and get and set its neighbors
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
	results, err := certDriver.QueryDomain(domainNode.Domain)
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

	// TODO parallelize this
	// TODO fix printing domains as they are found with new driver
	// add cert nodes to graph
	fingerprintMap, err := results.GetFingerprints()
	if err != nil {
		v("GetFingerprints", err)
		return
	}

	// fingerprints for the domain queried
	fingerprints := fingerprintMap[domainNode.Domain]
	for _, fp := range fingerprints {
		// add certnode to graph
		certNode, exists := certGraph.GetCert(fp)
		if !exists {
			// get cert details
			certResult, err := results.QueryCert(fp)
			if err != nil {
				v("QueryCert", err)
				continue
			}

			certNode = certNodeFromCertResult(certResult)
			certGraph.AddCert(certNode)
		}

		certNode.AddFound(certDriver.GetName())
		domainNode.AddCertFingerprint(certNode.Fingerprint, certDriver.GetName())
	}

	// we don't process any other certificates returned, they will be collected
	//  when we process the related domains
}

func printNode(domainNode *graph.DomainNode) {
	if config.details {
		fmt.Fprintln(os.Stdout, domainNode)
	} else {
		fmt.Fprintln(os.Stdout, domainNode.Domain)
	}
	if config.checkDNS && !domainNode.HasDNS {
		// TODO print this in a better way
		// TODO for debugging
		realDomain, _ := dns.ApexDomain(domainNode.Domain)
		fmt.Fprintf(os.Stdout, "* Missing DNS for: %s\n", realDomain)

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

// generates metadata for the JSON output
// TODO map all config json
func generateGraphMetadata() map[string]interface{} {
	data := make(map[string]interface{})
	data["version"] = version()
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

// returns the version string
func version() string {
	return fmt.Sprintf("Git commit: %s [%s]", gitDate, gitHash)
}

// cleanInput attempts to parse the input string as a url to extract the hostname
// if it fails, then the input string is returned
// also removes tailing '.'
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
