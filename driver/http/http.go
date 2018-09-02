package http

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/graph"
	"github.com/lanrat/certgraph/status"
)

const driverName = "http"

func init() {
	driver.AddDriver(driverName)
}

type httpDriver struct {
	port      string
	save      bool
	savePath  string
	tlsConfig *tls.Config
	timeout   time.Duration
}

type httpCertDriver struct {
	parent       *httpDriver
	client       *http.Client
	fingerprints []fingerprint.Fingerprint
	status       status.Map
	certs        map[fingerprint.Fingerprint]*graph.CertNode
}

func (c *httpCertDriver) GetFingerprints() ([]fingerprint.Fingerprint, error) {
	return c.fingerprints, nil
}

func (c *httpCertDriver) GetStatus() status.Map {
	return c.status
}

func (c *httpCertDriver) QueryCert(fp fingerprint.Fingerprint) (*graph.CertNode, error) {
	cert, found := c.certs[fp]
	if found {
		return cert, nil
	}
	return nil, fmt.Errorf("Certificate with Fingerprint %s not found", fp.HexString())
}

// Driver creates a new SSL driver for HTTP Connections
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

func (d *httpDriver) GetName() string {
	return driverName
}

func (d *httpDriver) newHTTPCertDriver() *httpCertDriver {
	result := &httpCertDriver{
		parent:       d,
		fingerprints: make([]fingerprint.Fingerprint, 0, 1),
		status:       make(status.Map),
		certs:        make(map[fingerprint.Fingerprint]*graph.CertNode),
	}
	// set client & client.Transport separately so that dialTLS checkRedirect can be referenced
	result.client = &http.Client{
		Timeout:       d.timeout,
		CheckRedirect: result.checkRedirect,
	}
	result.client.Transport = &http.Transport{
		TLSClientConfig:       d.tlsConfig,
		TLSHandshakeTimeout:   d.timeout,
		ResponseHeaderTimeout: d.timeout,
		ExpectContinueTimeout: d.timeout,
		DialTLS:               result.dialTLS,
	}
	return result
}

// GetCert gets the certificates found for a given domain
func (d *httpDriver) QueryDomain(host string) (driver.Result, error) {
	results := d.newHTTPCertDriver()

	resp, err := results.client.Get(fmt.Sprintf("https://%s", host))
	fullStatus := status.CheckNetErr(err)
	if fullStatus != status.GOOD {
		return results, err // in some cases this error can be ignored
	}
	defer resp.Body.Close()

	// set final domain status
	results.status.Set(resp.Request.URL.Hostname(), status.New(status.GOOD))
	// no need to add certificate to c.certs and c.fingerprints here, handled in dialTLS method
	return results, nil
}

// only called after a redirect is detected
// req has the next request to send, via has the last requests
// not called for the first HTTP request that replied with the initial redirect
func (c *httpCertDriver) checkRedirect(req *http.Request, via []*http.Request) error {
	//fmt.Printf("Redirect %s -> %s\n", via[0].URL, req.URL)
	// set both domain's status's
	c.status.Set(via[0].URL.Hostname(), status.NewMeta(status.REDIRECT, req.URL.Hostname()))
	c.status.Set(req.URL.Hostname(), status.New(status.UNKNOWN))
	if len(via) >= 10 { // stop after 10 redirects
		// this stops the redirect
		return http.ErrUseLastResponse
	}
	return nil
}

func (c *httpCertDriver) dialTLS(network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.client.Timeout}
	conn, err := tls.DialWithDialer(dialer, network, addr, c.parent.tlsConfig)
	if conn == nil {
		return conn, err
	}
	// get certs passing by
	connState := conn.ConnectionState()

	// only look at leaf certificate which is valid for domain, rest of cert chain is ignored
	certNode := graph.NewCertNode(connState.PeerCertificates[0])
	c.certs[certNode.Fingerprint] = certNode
	c.fingerprints = append(c.fingerprints, certNode.Fingerprint)

	// save
	if c.parent.save && len(connState.PeerCertificates) > 0 {
		driver.CertsToPEMFile(connState.PeerCertificates, path.Join(c.parent.savePath, certNode.Fingerprint.HexString())+".pem")
	}

	return conn, err
}
