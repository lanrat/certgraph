package status

import (
	"net"
	"syscall"
)

// DomainStatus domain node conection status
type DomainStatus int

// DomainStatus states
const (
	UNKNOWN = iota
	GOOD    = iota
	TIMEOUT = iota
	NOHOST  = iota
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
	case NOHOST:
		return "No Host"
	case REFUSED:
		return "Refused"
	case ERROR:
		return "Error"
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
			if t.Op == "dial" {
				return NOHOST
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
