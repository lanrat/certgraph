// Package status defines the various status certgraph discovered hosts/certificates may have
package status

import (
	"fmt"
	"net"
	"syscall"
)

// DomainStatus represents the connection status of a domain during certificate discovery.
// Used to track success, failure, and various error conditions encountered.
type DomainStatus int

// Status holds the domain connection status and optional metadata.
// The Meta field provides additional context like redirect targets or error details.
type Status struct {
	Status DomainStatus // The primary status code
	Meta   string       // Additional status information (e.g., redirect target)
}

// New creates a new Status instance with the specified DomainStatus.
func New(domainStatus DomainStatus) Status {
	return Status{
		Status: domainStatus,
	}
}

// NewMeta creates a new Status instance with status and metadata.
// The metadata provides additional context about the status.
func NewMeta(domainStatus DomainStatus, meta string) Status {
	s := New(domainStatus)
	s.Meta = meta
	return s
}

// String returns a formatted string representation of the status.
// Includes metadata in parentheses if present.
func (s *Status) String() string {
	if s.Meta == "" {
		return s.Status.String()
	}
	return fmt.Sprintf("%s(%s)", s.Status.String(), s.Meta)
}

// Map represents a collection of domain names mapped to their connection status.
// Used to track the status of multiple domains discovered during certificate queries.
type Map map[string]Status

// Set adds or updates a domain's status in the map.
func (m Map) Set(domain string, status Status) {
	m[domain] = status
}

// NewMap creates a new status map initialized with a single domain and status.
func NewMap(domain string, status Status) Map {
	m := make(Map)
	m.Set(domain, status)
	return m
}

// DomainStatus states
const (
	UNKNOWN  = iota
	GOOD     = iota
	TIMEOUT  = iota
	NOHOST   = iota
	REFUSED  = iota
	ERROR    = iota
	REDIRECT = iota
	CT       = iota
	MULTI    = iota
)

// String returns the human-readable string representation of the domain status.
func (status DomainStatus) String() string {
	switch status {
	case UNKNOWN:
		return "Unknown"
	case GOOD:
		return "Good"
	case TIMEOUT:
		return "Timeout"
	case NOHOST:
		return "No Host"
	case REFUSED:
		return "Refused"
	case ERROR:
		return "Error"
	case REDIRECT:
		return "Redirect"
	case CT:
		return "CT"
	case MULTI:
		return "MULTI"
	}
	return "?"
}

// CheckNetErr analyzes network errors and returns the appropriate DomainStatus.
// Categorizes errors into specific types like timeouts, connection refused, etc.
func CheckNetErr(err error) DomainStatus {
	if err == nil {
		return GOOD
	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		return TIMEOUT
	} else {
		switch t := err.(type) {
		case *net.OpError:
			switch t.Op {
			case "dial":
				return NOHOST
			case "read":
				return REFUSED
			}
		case syscall.Errno:
			if t == syscall.ECONNREFUSED {
				return REFUSED
			}
		}
	}
	return ERROR
}
