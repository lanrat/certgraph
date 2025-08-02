// Package status defines the various status certgraph discovered hosts/certificates may have
package status

import (
	"fmt"
	"net"
	"syscall"
)

// DomainStatus domain node connection status
type DomainStatus int

// Status holds the domain status and optionally more information
// ex: redirects will have the redirected domain in Meta
type Status struct {
	Status DomainStatus
	Meta   string
}

// New returns a new Status object with the provided DomainStatus
func New(domainStatus DomainStatus) Status {
	return Status{
		Status: domainStatus,
	}
}

// NewMeta returns a new Status with the provied meta
func NewMeta(domainStatus DomainStatus, meta string) Status {
	s := New(domainStatus)
	s.Meta = meta
	return s
}

func (s *Status) String() string {
	if s.Meta == "" {
		return s.Status.String()
	}
	return fmt.Sprintf("%s(%s)", s.Status.String(), s.Meta)
}

// Map is a map of returned domains to their status
type Map map[string]Status

// Set adds the domain and status to the StatusMap
func (m Map) Set(domain string, status Status) {
	m[domain] = status
}

// NewMap returns a new StatusMap containing the domain and status
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

// String returns the domain status for printing
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

// CheckNetErr check for errors, print if network related
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
