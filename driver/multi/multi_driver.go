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

type multiDriver struct {
	drivers []driver.Driver
}

// Driver returns a new instance of multi driver for the provided drivers
func Driver(drivers []driver.Driver) driver.Driver {
	md := new(multiDriver)
	md.drivers = drivers
	return md
}

func (d *multiDriver) GetName() string {
	names := make([]string, 0, len(d.drivers))
	for _, driver := range d.drivers {
		names = append(names, driver.GetName())
	}
	return fmt.Sprintf("multi[%s]", strings.Join(names, ","))
}

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

func newResult(host string) *multiResult {
	r := new(multiResult)
	r.host = host
	r.results = make([]driver.Result, 0, 2)
	r.fingerprints = make(driver.FingerprintMap)
	return r
}

type multiResult struct {
	host         string
	results      []driver.Result
	resultLock   sync.Mutex // also protects fingerprints
	fingerprints driver.FingerprintMap
}

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

func (c *multiResult) GetFingerprints() (driver.FingerprintMap, error) {
	return c.fingerprints, nil
}

func (c *multiResult) GetStatus() status.Map {
	// TODO nest other status inside
	return status.NewMap(c.host, status.New(status.MULTI))
}

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
