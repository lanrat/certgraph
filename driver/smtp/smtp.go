package smtp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/smtp"
	"path"
	"strings"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/status"
)

const driverName = "smtp"

func init() {
	driver.AddDriver(driverName)
}

type smtpDriver struct {
	port      string
	save      bool
	savePath  string
	tlsConfig *tls.Config
	timeout   time.Duration
}

type smtpCertDriver struct {
	host         string
	fingerprints []fingerprint.Fingerprint
	status       status.Map
	certs        map[fingerprint.Fingerprint]*graph.CertNode
}

func (c *smtpCertDriver) GetFingerprints() ([]fingerprint.Fingerprint, error) {
	return c.fingerprints, nil
}

func (c *smtpCertDriver) GetStatus() status.Map {
	//return status.NewMap(c.host, status.New(c.status))
	return c.status
}

func (c *smtpCertDriver) QueryCert(fp fingerprint.Fingerprint) (*graph.CertNode, error) {
	cert, found := c.certs[fp]
	if found {
		return cert, nil
	}
	return nil, fmt.Errorf("Certificate with Fingerprint %s not found", fp.HexString())
}

// Driver creates a new SSL driver for SMTP Connections
func Driver(timeout time.Duration, savePath string) (driver.Driver, error) {
	d := new(smtpDriver)
	d.port = "25"
	if len(savePath) > 0 {
		d.save = true
		d.savePath = savePath
	}
	d.tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	d.timeout = timeout

	return d, nil
}

func (d *smtpDriver) GetName() string {
	return driverName
}

func (d *smtpDriver) smtpGetCerts(host string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	addr := net.JoinHostPort(host, d.port)
	dialer := &net.Dialer{Timeout: d.timeout}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return certs, err
	}
	defer conn.Close()
	smtp, err := smtp.NewClient(conn, host)
	if err != nil {
		return certs, err
	}
	err = smtp.StartTLS(d.tlsConfig)
	if err != nil {
		return certs, err
	}
	connState, ok := smtp.TLSConnectionState()
	if !ok {
		return certs, err
	}
	return connState.PeerCertificates, err
}

// QueryDomain gets the certificates found for a given domain
func (d *smtpDriver) QueryDomain(host string) (driver.Result, error) {
	hosts := make([]string, 0, 1)
	hosts = append(hosts, host)
	results := &smtpCertDriver{
		host:         host,
		fingerprints: make([]fingerprint.Fingerprint, 0, 1),
		status:       make(status.Map),
		certs:        make(map[fingerprint.Fingerprint]*graph.CertNode),
	}

	mxHosts, err := GetMX(host)
	if err != nil {
		return results, err
	}
	hosts = append(hosts, mxHosts...)

	for _, host := range hosts {
		certs, err := d.smtpGetCerts(host)
		mxStatus := status.CheckNetErr(err)
		if mxStatus != status.GOOD {
			continue
		}

		// only look at leaf certificate which is valid for domain, rest of cert chain is ignored
		certNode := graph.NewCertNode(certs[0])
		results.status.Set(host, status.NewMeta(status.GOOD, "MX"))
		results.certs[certNode.Fingerprint] = certNode
		results.fingerprints = append(results.fingerprints, certNode.Fingerprint)

		// save
		if d.save && len(certs) > 0 {
			driver.CertsToPEMFile(certs, path.Join(d.savePath, certNode.Fingerprint.HexString())+".pem")
		}
	}

	return results, nil
}

// GetMX returns the MX records for the provided domain
func GetMX(domain string) ([]string, error) {
	// TODO add timeout
	domains := make([]string, 0, 5)
	mx, err := net.LookupMX(domain)
	if err != nil {
		return domains, err
	}
	for _, v := range mx {
		domains = append(domains, strings.TrimSuffix(v.Host, "."))
	}
	return domains, nil
}
