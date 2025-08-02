package graph

import (
	"strings"
)

// nonWildcard removes the wildcard prefix from a domain name.
// Converts "*.example.com" to "example.com" for consistent domain handling.
func nonWildcard(domain string) string {
	return strings.TrimPrefix(domain, "*.")
}
