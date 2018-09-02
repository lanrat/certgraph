package driver

import (
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/status"
)

// Drivers contains all the drivers that have been registered
var Drivers []string

// AddDriver should be called in the init() function of every driver to register them here
func AddDriver(name string) {
	Drivers = append(Drivers, name)
}

// Driver is a universal unifying interface to support CT, http and much more!
type Driver interface {
	// QueryDomain is the main entrypoint for Driver Searching
	// The domain provided will return a CertDriver instance which can be used to query the
	// certificates for the provided domain using the driver
	QueryDomain(domain string) (Result, error)

	// GetName returns the name of the driver
	GetName() string
}

// Result is a sub-driver that allows querying certificate details from a previously queried domain
type Result interface {
	// GetStatus returns the status of the initial domain queried with the Driver.QueryDomain call
	GetStatus() status.Map

	// GetFingerprints returns an array of the certificate fingerprints associated with the Domain
	// pass return fingerprints to QueryCert to get certificate details
	GetFingerprints() ([]fingerprint.Fingerprint, error)

	// QueryCert returns the details of the provided certificate or an error if not found
	QueryCert(fp fingerprint.Fingerprint) (*graph.CertNode, error)
	// TODO do I really want this ^^ to be a certnode?
}
