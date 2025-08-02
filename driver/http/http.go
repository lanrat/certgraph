// Package http implements a certgraph driver for obtaining SSL certificates over https
package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
)

const driverName = "http"

func init() {
	driver.AddDriver(driverName)
}

// httpDriver implements certificate discovery through HTTPS connections.
// It performs TLS handshakes with web servers to retrieve their SSL certificates.
type httpDriver struct {
	port      string        // HTTPS port (default: 443)
	save      bool          // Whether to save certificates to disk
	savePath  string        // Directory path for saving certificates
	tlsConfig *tls.Config   // TLS configuration with InsecureSkipVerify
	timeout   time.Duration // Connection and request timeout
}

// httpCertDriver represents the result of an HTTP certificate query.
// It handles TLS connections, redirect following, and certificate collection.
type httpCertDriver struct {
	parent       *httpDriver                                    // Reference to parent driver
	client       *http.Client                                   // HTTP client with TLS configuration
	fingerprints driver.FingerprintMap                          // Certificate fingerprints found
	status       status.Map                                     // Connection status for domains
	related      []string                                       // Related domains from redirects
	certs        map[fingerprint.Fingerprint]*driver.CertResult // Certificate details
}

// GetFingerprints returns the certificate fingerprints discovered through HTTPS.
func (c *httpCertDriver) GetFingerprints() (driver.FingerprintMap, error) {
	return c.fingerprints, nil
}

// GetStatus returns the connection status for domains encountered during the query.
func (c *httpCertDriver) GetStatus() status.Map {
	return c.status
}

// GetRelated returns domains discovered through HTTP redirects.
func (c *httpCertDriver) GetRelated() ([]string, error) {
	return c.related, nil
}

// QueryCert retrieves certificate details for a specific fingerprint.
// Returns an error if the certificate was not found in this HTTP query.
func (c *httpCertDriver) QueryCert(ctx context.Context, fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	cert, found := c.certs[fp]
	if found {
		return cert, nil
	}
	return nil, fmt.Errorf("certificate with Fingerprint %s not found", fp.HexString())
}

// Driver creates a new HTTP certificate discovery driver.
// Uses HTTPS connections to retrieve certificates from web servers.
func Driver(timeout time.Duration, savePath string) (driver.Driver, error) {
	d := new(httpDriver)
	d.port = "443"
	if len(savePath) > 0 {
		d.save = true
		d.savePath = savePath
	}
	d.timeout = timeout
	d.tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	return d, nil
}

// GetName returns the driver name for identification.
func (d *httpDriver) GetName() string {
	return driverName
}

// newHTTPCertDriver creates a new HTTP certificate driver instance with optimized connection pooling.
// Configures HTTP client with TLS settings and redirect handling.
func (d *httpDriver) newHTTPCertDriver() *httpCertDriver {
	result := &httpCertDriver{
		parent:       d,
		status:       make(status.Map),
		fingerprints: make(driver.FingerprintMap),
		certs:        make(map[fingerprint.Fingerprint]*driver.CertResult),
	}
	// set client & client.Transport separately so that dialTLS checkRedirect can be referenced
	result.client = &http.Client{
		Timeout:       d.timeout,
		CheckRedirect: result.checkRedirect,
	}
	// Create transport with connection pooling optimizations
	result.client.Transport = &http.Transport{
		TLSClientConfig:       d.tlsConfig,
		TLSHandshakeTimeout:   d.timeout,
		ResponseHeaderTimeout: d.timeout,
		ExpectContinueTimeout: d.timeout,
		DialTLS:               result.dialTLS,
		// Connection pooling settings for better performance
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     10,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return result
}

// QueryDomain discovers certificates for a domain through HTTPS connections.
// Follows redirects and collects certificates from all encountered servers.
func (d *httpDriver) QueryDomain(ctx context.Context, host string) (driver.Result, error) {
	results := d.newHTTPCertDriver()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s", host), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := results.client.Do(req)
	fullStatus := status.CheckNetErr(err)
	if fullStatus != status.GOOD {
		return results, err // in some rare cases this error can be ignored
	}
	defer func() { _ = resp.Body.Close() }()

	// set final domain status
	results.status.Set(resp.Request.URL.Hostname(), status.New(status.GOOD))
	// no need to add certificate to c.certs and c.fingerprints here, handled in dialTLS method
	return results, nil
}

// checkRedirect handles HTTP redirects by tracking status and related domains.
// Called by the HTTP client when a redirect response is received.
// req contains the next request, via contains the previous request chain.
func (c *httpCertDriver) checkRedirect(req *http.Request, via []*http.Request) error {
	//fmt.Printf("Redirect %s -> %s\n", via[0].URL, req.URL)
	// set both domain's status's
	c.status.Set(via[0].URL.Hostname(), status.NewMeta(status.REDIRECT, req.URL.Hostname()))
	c.status.Set(req.URL.Hostname(), status.New(status.UNKNOWN))
	c.related = append(c.related, req.URL.Hostname())
	if len(via) >= 10 { // stop after 10 redirects
		// this stops the redirect
		return http.ErrUseLastResponse
	}
	return nil
}

// dialTLS establishes TLS connections and captures certificates during the handshake.
// Custom dialer that extracts certificate information before returning the connection.
func (c *httpCertDriver) dialTLS(network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.client.Timeout}
	conn, err := tls.DialWithDialer(dialer, network, addr, c.parent.tlsConfig)
	if conn == nil {
		return conn, err
	}
	// get certs passing by
	connState := conn.ConnectionState()

	// only look at leaf certificate which is valid for domain, rest of cert chain is ignored
	if len(connState.PeerCertificates) == 0 {
		return conn, fmt.Errorf("no peer certificates found")
	}
	certResult := driver.NewCertResult(connState.PeerCertificates[0])
	c.certs[certResult.Fingerprint] = certResult
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return conn, err
	}
	c.fingerprints.Add(host, certResult.Fingerprint)

	// save
	if c.parent.save && len(connState.PeerCertificates) > 0 {
		err = driver.CertsToPEMFile(connState.PeerCertificates, path.Join(c.parent.savePath, certResult.Fingerprint.HexString())+".pem")
	}

	return conn, err
}
