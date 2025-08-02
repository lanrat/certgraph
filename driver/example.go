package driver

import (
	"context"
	"fmt"
)

// Example provides a simple entrypoint to test a driver on an individual domain
func Example(domain string, driver Driver) error {
	ctx := context.Background()
	certDriver, err := driver.QueryDomain(ctx, domain)
	if err != nil {
		return err
	}

	relatedDomains, err := certDriver.GetRelated()
	if err != nil {
		return err
	}
	if len(relatedDomains) > 0 {
		fmt.Printf("Related:\n")
	}
	for _, relatedDomain := range relatedDomains {
		fmt.Printf("\t%s\n", relatedDomain)
	}

	fingerprintMap, err := certDriver.GetFingerprints()
	if err != nil {
		return err
	}
	for domain, fingerprints := range fingerprintMap {
		for i := range fingerprints {
			fmt.Printf("%s: %s\n", domain, fingerprints[i].HexString())
			cert, err := certDriver.QueryCert(ctx, fingerprints[i])
			if err != nil {
				return err
			}
			for j := range cert.Domains {
				fmt.Println("\t", cert.Domains[j])
			}
		}
	}

	return nil
}
