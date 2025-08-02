// Package dns adds utility functions for performing dns queries
package dns

import (
	"context"
	"net"
	"sync"
	"time"
)

// dnsCacheEntry represents a cached DNS lookup result with TTL expiration.
type dnsCacheEntry struct {
	result    bool      // Whether DNS records were found
	expiredAt time.Time // When this cache entry expires
}

// dnsCacheWithTTL implements a thread-safe TTL-based cache for DNS lookup results.
// Automatically expires entries after the specified TTL duration.
type dnsCacheWithTTL struct {
	cache sync.Map      // Thread-safe map for storing cache entries
	ttl   time.Duration // Time-to-live for cache entries
}

// newDNSCache creates a new DNS cache instance with the specified TTL.
func newDNSCache(ttl time.Duration) *dnsCacheWithTTL {
	return &dnsCacheWithTTL{
		ttl: ttl,
	}
}

// get retrieves a cached DNS result if it exists and hasn't expired.
// Returns (result, found) where found indicates if a valid cache entry was found.
func (c *dnsCacheWithTTL) get(key string) (bool, bool) {
	if entry, found := c.cache.Load(key); found {
		cacheEntry := entry.(dnsCacheEntry)
		if time.Now().Before(cacheEntry.expiredAt) {
			return cacheEntry.result, true
		}
		// Entry expired, remove it
		c.cache.Delete(key)
	}
	return false, false
}

// set stores a DNS lookup result in the cache with automatic expiration.
func (c *dnsCacheWithTTL) set(key string, value bool) {
	entry := dnsCacheEntry{
		result:    value,
		expiredAt: time.Now().Add(c.ttl),
	}
	c.cache.Store(key, entry)
}

var (
	dnsCache    = newDNSCache(5 * time.Minute) // 5 minute TTL
	dnsResolver = &net.Resolver{}
)

func init() {
	//dnsResolver.PreferGo = true
	dnsResolver.StrictErrors = false
}

// noSuchHostDNSError checks if an error is a "no such host" DNS error.
// Used to distinguish between network errors and legitimate "no records" responses.
func noSuchHostDNSError(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		// not a DNSError
		return false
	}
	return dnsErr.Err == "no such host"
}

// HasRecords performs comprehensive DNS lookups (NS, CNAME, A, AAAA) to determine if a domain exists.
// Returns true if any DNS records are found, false if no records exist.
// Uses the provided timeout for all DNS queries.
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

// HasRecordsCache performs cached DNS record lookups for a domain's apex.
// Automatically converts subdomains to their apex domain before lookup.
// Uses caching to avoid repeated DNS queries for the same apex domain.
func HasRecordsCache(domain string, timeout time.Duration) (bool, error) {
	domain, err := ApexDomain(domain)
	if err != nil {
		return false, err
	}
	if cached, found := dnsCache.get(domain); found {
		return cached, nil
	}
	hasRecords, err := HasRecords(domain, timeout)
	if err == nil {
		dnsCache.set(domain, hasRecords)
	}
	return hasRecords, err
}
