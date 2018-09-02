package driver

import "fmt"

// Example provides a simple entrypoint to test a driver on an individual domain
func Example(domain string, driver Driver) error {
	certDriver, err := driver.QueryDomain(domain)
	if err != nil {
		return err
	}

	fingerprints, err := certDriver.GetFingerprints()
	if err != nil {
		return err
	}
	for i := range fingerprints {
		fmt.Println(fingerprints[i].HexString(), " ", fingerprints[i].B64Encode())
		cert, err := certDriver.QueryCert(fingerprints[i])
		if err != nil {
			return err
		}
		for j := range cert.Domains {
			fmt.Println("\t", cert.Domains[j])
		}
	}

	return nil
}
