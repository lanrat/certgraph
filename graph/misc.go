package graph

import (
	"strings"
)

// given a domain returns the non-wildcard version of that domain
func nonWildcard(domain string) string {
	return strings.TrimPrefix(domain, "*.")
}
