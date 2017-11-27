package graph

import (
	"fmt"
	"os"
)

var Verbose = false

func v(a ...interface{}) {
	if Verbose {
		fmt.Fprintln(os.Stderr, a...)
	}
}

// given a domain returns the non-wildcard version of that domain
func directDomain(domain string) string {
	if len(domain) < 3 {
		return domain
	}
	if domain[0:2] == "*." {
		domain = domain[2:]
	}
	return domain
}
