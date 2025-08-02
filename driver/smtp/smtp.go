// Package smtp implements a certgraph driver for obtaining SSL certificates over smtp with STARTTLS
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

// smtpDriver implements certificate discovery through SMTP STARTTLS connections.
// It connects to mail servers and retrieves their SSL certificates.
type smtpDriver struct {
	port      string        // SMTP port (default: 25)
	save      bool          // Whether to save certificates to disk
	savePath  string        // Directory path for saving certificates
	tlsConfig *tls.Config   // TLS configuration for STARTTLS
	timeout   time.Duration // Connection timeout
}

// smtpCertDriver represents the result of an SMTP certificate query.
// It stores certificates discovered through STARTTLS and related MX record information.
type smtpCertDriver struct {
	host         string                                         // The queried domain
	fingerprints driver.FingerprintMap                          // Certificate fingerprints found
	status       status.Map                                     // Connection status for the domain
	mx           []string                                       // MX records for the domain
	certs        map[fingerprint.Fingerprint]*driver.CertResult // Certificate details
}

// GetFingerprints returns the certificate fingerprints discovered through SMTP.
func (c *smtpCertDriver) GetFingerprints() (driver.FingerprintMap, error) {
	return c.fingerprints, nil
}

// GetStatus returns the connection status for the SMTP query.
func (c *smtpCertDriver) GetStatus() status.Map {
	return c.status
}

// GetRelated returns MX record hostnames as related domains for further exploration.
func (c *smtpCertDriver) GetRelated() ([]string, error) {
	return c.mx, nil
}

// QueryCert retrieves certificate details for a specific fingerprint.
// Returns an error if the certificate was not found in this SMTP query.
func (c *smtpCertDriver) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	cert, found := c.certs[fp]
	if found {
		return cert, nil
	}
	return nil, fmt.Errorf("certificate with Fingerprint %s not found", fp.HexString())
}

// Driver creates a new SMTP certificate discovery driver.
// Uses STARTTLS to establish TLS connections and retrieve certificates from mail servers.
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

// GetName returns the driver name for identification.
func (d *smtpDriver) GetName() string {
	return driverName
}

// smtpGetCerts establishes an SMTP connection and retrieves certificates via STARTTLS.
// Returns the certificate chain presented by the mail server.
func (d *smtpDriver) smtpGetCerts(host string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	addr := net.JoinHostPort(host, d.port)
	dialer := &net.Dialer{Timeout: d.timeout}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return certs, err
	}
	defer func() { _ = conn.Close() }()
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

// QueryDomain discovers certificates for a domain through SMTP STARTTLS.
// Also performs MX record lookups to find related mail server domains.
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
	if len(certs) == 0 {
		return results, fmt.Errorf("no certificates found")
	}
	certResult := driver.NewCertResult(certs[0])
	results.certs[certResult.Fingerprint] = certResult
	results.fingerprints.Add(host, certResult.Fingerprint)

	// save
	if d.save && len(certs) > 0 {
		err = driver.CertsToPEMFile(certs, path.Join(d.savePath, certResult.Fingerprint.HexString())+".pem")
	}

	return results, err
}

// getMX performs DNS MX record lookup for the domain.
// Returns a list of mail server hostnames with trailing dots removed.
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
