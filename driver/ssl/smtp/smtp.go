package smtp

import (
	"crypto/tls"
	"net"
	"net/smtp"
	"path"
	"time"

	"github.com/lanrat/certgraph/driver/ssl"
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/status"
)

type smtpDriver struct {
	port     string
	save     bool
	savePath string
	tlsConf  *tls.Config
	timeout  time.Duration
}

// NewSSLDriver creates a new SSL driver for SMTP Connections
func NewSSLDriver(timeout time.Duration, savePath string) (ssl.Driver, error) {
	d := new(smtpDriver)
	d.port = "25"
	if len(savePath) > 0 {
		d.save = true
		d.savePath = savePath
	}
	d.tlsConf = &tls.Config{InsecureSkipVerify: true}
	d.timeout = timeout

	return d, nil
}

// gets the certificates found for a given domain
func (d *smtpDriver) GetCert(host string) (status.DomainStatus, *graph.CertNode, error) {
	addr := net.JoinHostPort(host, d.port)
	dialer := &net.Dialer{Timeout: d.timeout}
	var domainStatus status.DomainStatus = status.ERROR

	conn, err := dialer.Dial("tcp", addr)
	domainStatus = status.CheckNetErr(err)
	if domainStatus != status.GOOD {
		//v(domainStatus, host)
		return domainStatus, nil, err
	}
	defer conn.Close()
	smtp, err := smtp.NewClient(conn, host)
	if err != nil {
		//v(err)
		return domainStatus, nil, err // TODO might want to make these return a nil error
	}
	err = smtp.StartTLS(d.tlsConf)
	if err != nil {
		//v(err)
		return domainStatus, nil, err
	}
	connState, ok := smtp.TLSConnectionState()
	if !ok {
		return domainStatus, nil, err
	}

	if d.save && len(connState.PeerCertificates) > 0 {
		ssl.CertsToPEMFile(connState.PeerCertificates, path.Join(d.savePath, host)+".pem")
	}

	// TODO iterate over all certs, needs to also update graph.GetDomainNeighbors() too
	certNode := graph.NewCertNode(connState.PeerCertificates[0])
	certNode.HTTP = true
	return status.GOOD, certNode, nil
}

// GetMX returns the MX records for the provided domain
func GetMX(domain string) ([]string, error) {
	domains := make([]string, 0, 5)
	mx, err := net.LookupMX(domain)
	if err != nil {
		return domains, err
	}
	for _, v := range mx {
		domains = append(domains, v.Host)
	}
	return domains, nil
}
