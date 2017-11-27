package status

import (
	"net"
	"syscall"
)

// domain node conection status
type DomainStatus int

const (
	UNKNOWN = iota
	GOOD    = iota
	TIMEOUT = iota
	NO_HOST = iota
	REFUSED = iota
	ERROR   = iota
)

// return domain status for printing
func (status DomainStatus) String() string {
	switch status {
	case UNKNOWN:
		return "Unknown"
	case GOOD:
		return "Good"
	case TIMEOUT:
		return "Timeout"
	case NO_HOST:
		return "No Host"
	case REFUSED:
		return "Refused"
	case ERROR:
		return "Error"
	}
	return "?"
}

// Check for errors, print if network related
func CheckNetErr(err error) DomainStatus {
	if err == nil {
		return GOOD
	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		return TIMEOUT
	} else {
		switch t := err.(type) {
		case *net.OpError:
			if t.Op == "dial" {
				return NO_HOST
			} else if t.Op == "read" {
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
