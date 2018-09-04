package status

import (
	"context"
	"net"
	"time"

	"golang.org/x/net/publicsuffix"
	//"github.com/weppos/publicsuffix-go/net/publicsuffix"
)

var (
//psl            publicsuffix.List        = publicsuffix.DefaultList()
//pslFindOptions publicsuffix.FindOptions = &publicsuffix.FindOptions{IgnorePrivate: true}
)

// TLDPlus1 returns TLD+1 of domain
func TLDPlus1(domain string) (string, error) {
	// TODO move from find options to custom list
	//return publicsuffix.DomainFromListWithOptions(psl, domain, pslFindOptions)
	return publicsuffix.EffectiveTLDPlusOne(domain)
}

// HasNameservers returns the NS records for the domain
func HasNameservers(domain string, timeout time.Duration) (bool, error) {
	tldPlus1, err := TLDPlus1(domain)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ns, err := net.DefaultResolver.LookupNS(ctx, tldPlus1)
	if err != nil {
		return false, err
	}
	return len(ns) > 0, nil
}
