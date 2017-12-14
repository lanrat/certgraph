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
	tlsconf  *tls.Config
	timeout  time.Duration
}

func NewSSLDriver(timeout time.Duration, savePath string) (ssl.Driver, error) {
	d := new(smtpDriver)
	d.port = "25"
	if len(savePath) > 0 {
		d.save = true
		d.savePath = savePath
	}
	d.tlsconf = &tls.Config{InsecureSkipVerify: true}
	d.timeout = timeout

	return d, nil
}

// gets the certificats found for a given domain
func (d *smtpDriver) GetCert(host string) (status.DomainStatus, *graph.CertNode, error) {
	addr := net.JoinHostPort(host, d.port)
	dialer := &net.Dialer{Timeout: d.timeout}
	var dStatus status.DomainStatus = status.ERROR

	conn, err := dialer.Dial("tcp", addr)
	dStatus = status.CheckNetErr(err)
	if dStatus != status.GOOD {
		//v(dStatus, host)
		return dStatus, nil, err
	}
	defer conn.Close()
	smtp, err := smtp.NewClient(conn, host)
	if err != nil {
		//v(err)
		return dStatus, nil, err // TODO might want to make these return a nil error
	}
	err = smtp.StartTLS(d.tlsconf)
	if err != nil {
		//v(err)
		return dStatus, nil, err
	}
	connState, ok := smtp.TLSConnectionState()
	if !ok {
		return dStatus, nil, err
	}

	if d.save && len(connState.PeerCertificates) > 0 {
		ssl.CertsToPEMFile(connState.PeerCertificates, path.Join(d.savePath, host)+".pem")
	}

	// TODO iterate over all certs, needs to also update dgraph.GetDomainNeighbors() too
	certnode := graph.NewCertNode(connState.PeerCertificates[0])
	certnode.HTTP = true
	return status.GOOD, certnode, nil
}

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
