// Package dns adds utility functions for performing dns queries
package dns

import (
	"context"
	"net"
	"time"
)

var (
	dnsCache    = make(map[string]bool)
	dnsResolver = &net.Resolver{}
)

func init() {
	//dnsResolver.PreferGo = true
	dnsResolver.StrictErrors = false
}

func noSuchHostDNSError(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		// not a DNSError
		return false
	}
	return dnsErr.Err == "no such host"
}

// HasRecords does NS, CNAME, A, and AAAA lookups with a timeout
// returns error when no NS found, does not use alexDomain
func HasRecords(domain string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// first check for NS
	ns, err := dnsResolver.LookupNS(ctx, domain)
	if err != nil && !noSuchHostDNSError(err) {
		//fmt.Println("NS error ", err)
		return false, err
	}
	if len(ns) > 0 {
		//fmt.Printf("Found %d NS for %s\n", len(ns), domain)
		return true, nil
	}

	// next check for CNAME
	cname, err := dnsResolver.LookupCNAME(ctx, domain)
	if err != nil && !noSuchHostDNSError(err) {
		//fmt.Println("cname error ", err)
		return false, err
	}
	if len(cname) > 2 {
		//fmt.Printf("found CNAME %s for %s\n", cname, domain)
		return true, nil
	}

	// next check for IP
	addrs, err := dnsResolver.LookupHost(ctx, domain)
	if err != nil && !noSuchHostDNSError(err) {
		//fmt.Println("ip error ", err)
		return false, err
	}
	if len(addrs) > 0 {
		//fmt.Printf("Found %d IPs for %s\n", len(addrs), domain)
		return true, nil
	}

	//fmt.Printf("Found no DNS records for %s\n", domain)
	return false, nil
}

// HasRecordsCache returns true if the domain has no DNS records (at the apex domain level)
// uses a cache to store results to prevent lots of DNS lookups
func HasRecordsCache(domain string, timeout time.Duration) (bool, error) {
	domain, err := ApexDomain(domain)
	if err != nil {
		return false, err
	}
	hasDNS, found := dnsCache[domain]
	if found {
		return hasDNS, nil
	}
	hasRecords, err := HasRecords(domain, timeout)
	if err != nil {
		dnsCache[domain] = hasRecords
	}
	return hasRecords, err
}
