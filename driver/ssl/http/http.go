package http

import (
	"crypto/tls"
	"net"
	"path"
	"time"

	"github.com/lanrat/certgraph/driver/ssl"
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/status"
)

/* TODO
follow http redirects
*/

type httpDriver struct {
	port     string
	save     bool
	savePath string
	tlsconf  *tls.Config
	timeout  time.Duration
}

func NewSSLDriver(timeout time.Duration, savePath string) (ssl.Driver, error) {
	d := new(httpDriver)
	d.port = "443"
	if len(savePath) > 0 {
		d.save = true
		d.savePath = savePath
	}
	d.tlsconf = &tls.Config{InsecureSkipVerify: true}
	d.timeout = timeout

	return d, nil
}

// gets the certificats found for a given domain
func (d *httpDriver) GetCert(host string) (status.DomainStatus, *graph.CertNode, error) {
	addr := net.JoinHostPort(host, d.port)
	dialer := &net.Dialer{Timeout: d.timeout}
	var dStatus status.DomainStatus = status.ERROR

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, d.tlsconf)
	dStatus = status.CheckNetErr(err)
	if dStatus != status.GOOD {
		//v(dStatus, host)
		return dStatus, nil, err // TODO might want to make this return a nil error
	}
	conn.Close()
	connState := conn.ConnectionState()

	if d.save && len(connState.PeerCertificates) > 0 {
		ssl.CertsToPEMFile(connState.PeerCertificates, path.Join(d.savePath, host)+".pem")
	}

	// TODO iterate over all certs, needs to also update dgraph.GetDomainNeighbors() too
	certnode := graph.NewCertNode(connState.PeerCertificates[0])
	certnode.HTTP = true
	return status.GOOD, certnode, nil
}
