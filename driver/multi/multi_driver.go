// Package multi exposes a generic driver interface allowing you to merge the results of multiple other drivers
package multi

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
	"golang.org/x/sync/errgroup"
)

// multiDriver combines multiple certificate discovery drivers into a single interface.
// It executes queries against all drivers concurrently and merges the results.
type multiDriver struct {
	drivers []driver.Driver
}

// Driver creates a new multi-driver instance that combines the provided drivers.
// The resulting driver will query all drivers concurrently and merge their results.
func Driver(drivers []driver.Driver) driver.Driver {
	md := new(multiDriver)
	md.drivers = drivers
	return md
}

// GetName returns a descriptive name listing all combined drivers.
// Format: "multi[driver1,driver2,driver3]"
func (d *multiDriver) GetName() string {
	names := make([]string, 0, len(d.drivers))
	for _, driver := range d.drivers {
		names = append(names, driver.GetName())
	}
	return fmt.Sprintf("multi[%s]", strings.Join(names, ","))
}

// QueryDomain executes domain queries against all drivers concurrently.
// Returns a merged result containing certificates and status information from all drivers.
func (d *multiDriver) QueryDomain(domain string) (driver.Result, error) {
	r := newResult(domain)
	var group errgroup.Group
	for _, d := range d.drivers {
		goFunc := func(localDriver driver.Driver) func() error {
			return func() error {
				return func(localDriver driver.Driver) error {
					result, err := localDriver.QueryDomain(domain)
					if err != nil {
						return err
					}
					return r.add(result)
				}(localDriver)
			}
		}

		group.Go(goFunc(d))
	}
	err := group.Wait()
	if err != nil {
		return nil, err
	}
	return r, nil
}

// newResult creates a new multiResult instance for collecting merged driver results.
func newResult(host string) *multiResult {
	r := new(multiResult)
	r.host = host
	r.results = make([]driver.Result, 0, 2)
	r.fingerprints = make(driver.FingerprintMap)
	return r
}

// multiResult aggregates results from multiple drivers for a single domain query.
// It provides thread-safe access to merged certificate fingerprints and related data.
type multiResult struct {
	host         string                // The queried domain
	results      []driver.Result       // Results from individual drivers
	resultLock   sync.Mutex            // Protects results and fingerprints maps
	fingerprints driver.FingerprintMap // Merged fingerprints from all drivers
}

// add merges a driver result into this multiResult instance.
// Thread-safe method that combines fingerprints and stores the result.
func (c *multiResult) add(r driver.Result) error {
	c.resultLock.Lock()
	defer c.resultLock.Unlock()
	fpm, err := r.GetFingerprints()
	if err != nil {
		return err
	}
	for domain := range fpm {
		for _, fp := range fpm[domain] {
			// TODO does not dedupe across drivers
			c.fingerprints.Add(domain, fp)
		}
	}

	c.results = append(c.results, r)
	return nil
}

// QueryCert attempts to retrieve certificate details from any of the drivers.
// Returns the first successful result found among the combined drivers.
func (c *multiResult) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	for _, result := range c.results {
		cr, err := result.QueryCert(fp)
		if err != nil {
			return nil, err
		}
		if cr != nil {
			return cr, nil
		}
	}
	return nil, errors.New("unable to find working driver with QueryCert()")
}

// GetFingerprints returns the merged fingerprint map from all drivers.
func (c *multiResult) GetFingerprints() (driver.FingerprintMap, error) {
	return c.fingerprints, nil
}

// GetStatus returns a status map indicating this is a multi-driver result.
// TODO: Consider nesting individual driver statuses for more detailed reporting.
func (c *multiResult) GetStatus() status.Map {
	return status.NewMap(c.host, status.New(status.MULTI))
}

// GetRelated returns a deduplicated list of related domains from all drivers.
// Merges related domain lists from all individual driver results.
func (c *multiResult) GetRelated() ([]string, error) {
	relatedMap := make(map[string]bool)
	for _, result := range c.results {
		related, err := result.GetRelated()
		if err != nil {
			return nil, err
		}
		for _, r := range related {
			relatedMap[r] = true
		}
	}
	related := make([]string, 0, len(relatedMap))
	for r := range relatedMap {
		related = append(related, r)
	}
	return related, nil
}
