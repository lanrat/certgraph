package smtp

import (
	"context"
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
	fingerprints driver.FingerprintMap
	status       status.Map
	mx           []string
	certs        map[fingerprint.Fingerprint]*driver.CertResult
}

func (c *smtpCertDriver) GetFingerprints() (driver.FingerprintMap, error) {
	return c.fingerprints, nil
}

func (c *smtpCertDriver) GetStatus() status.Map {
	return c.status
}

func (c *smtpCertDriver) GetRelated() ([]string, error) {
	return c.mx, nil
}

func (c *smtpCertDriver) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
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
	results := &smtpCertDriver{
		host:         host,
		status:       make(status.Map),
		fingerprints: make(driver.FingerprintMap),
		certs:        make(map[fingerprint.Fingerprint]*driver.CertResult),
	}

	// get related in different query
	results.mx, _ = d.getMX(host)

	certs, err := d.smtpGetCerts(host)
	smtpStatus := status.CheckNetErr(err)
	metaStatus := ""
	if len(results.mx) > 0 {
		metaStatus = fmt.Sprintf("MX(%s)", strings.Join(results.mx, " "))
	}
	results.status.Set(host, status.NewMeta(smtpStatus, metaStatus))

	if smtpStatus != status.GOOD {
		return results, nil
	}

	// only look at leaf certificate which is valid for domain, rest of cert chain is ignored
	certResult := driver.NewCertResult(certs[0])
	results.certs[certResult.Fingerprint] = certResult
	results.fingerprints.Add(host, certResult.Fingerprint)

	// save
	if d.save && len(certs) > 0 {
		driver.CertsToPEMFile(certs, path.Join(d.savePath, certResult.Fingerprint.HexString())+".pem")
	}

	return results, nil
}

// getMX returns the MX records for the provided domain
func (d *smtpDriver) getMX(domain string) ([]string, error) {
	domains := make([]string, 0, 5)
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	mx, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return domains, err
	}
	for _, v := range mx {
		domains = append(domains, strings.TrimSuffix(v.Host, "."))
	}
	return domains, nil
}
