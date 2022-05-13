// Package google file implements an unofficial API client for Google's
// Certificate Transparency search
// https://transparencyreport.google.com/https/certificates
//
// As the API is unofficial and has been reverse engineered it may stop working
// at any time and comes with no guarantees.
//
package google

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
)

const driverName = "google"

func init() {
	driver.AddDriver(driverName)
}

// Base URLs for Google's CT API
const (
	searchURL1 = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=false&include_subdomains=false&domain=example.com"
	searchURL2 = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?p=DEADBEEF"
	certURL    = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certbyhash?hash=DEADBEEF"
	//summaryURL is not currently used
	//summaryURL = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/summary"
)

type googleCT struct {
	maxPages          float64 // this is a float because that is the type automatically decoded from the JSON response
	jsonClient        *http.Client
	includeExpired    bool
	includeSubdomains bool
}

type googleCertDriver struct {
	host         string
	fingerprints driver.FingerprintMap
	driver       *googleCT
}

func (c *googleCertDriver) GetFingerprints() (driver.FingerprintMap, error) {
	return c.fingerprints, nil
}

func (c *googleCertDriver) GetStatus() status.Map {
	return status.NewMap(c.host, status.New(status.CT))
}

func (c *googleCertDriver) GetRelated() ([]string, error) {
	return make([]string, 0), nil
}

func (c *googleCertDriver) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	return c.driver.QueryCert(fp)
}

// Driver creates a new CT driver for google
func Driver(maxQueryPages int, savePath string, includeSubdomains, includeExpired bool) (driver.Driver, error) {
	d := new(googleCT)
	d.maxPages = float64(maxQueryPages)
	d.jsonClient = &http.Client{Timeout: 10 * time.Second}
	d.includeExpired = includeExpired
	d.includeSubdomains = includeSubdomains

	if len(savePath) > 0 {
		return d, errors.New("google driver does not support saving")

	}

	return d, nil
}

func (d *googleCT) GetName() string {
	return driverName
}

// getJsonP gets JSON from url and parses it into target object
func (d *googleCT) getJSONP(url string, target interface{}) error {
	r, err := d.jsonClient.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return errors.New("Got non OK HTTP status: '" + r.Status + "' on URL: " + url)
	}

	respData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	respData = respData[5:] // this removes the leading ")]}'" from the response

	return json.Unmarshal(respData, target)
}

func (d *googleCT) QueryDomain(domain string) (driver.Result, error) {
	results := &googleCertDriver{
		fingerprints: make(driver.FingerprintMap),
		driver:       d,
		host:         domain,
	}

	u, err := url.Parse(searchURL1)
	if err != nil {
		return results, err
	}

	// get page 1
	q := u.Query()
	q.Set("include_expired", strconv.FormatBool(d.includeExpired))
	q.Set("include_subdomains", strconv.FormatBool(d.includeSubdomains))
	q.Set("domain", domain)
	u.RawQuery = q.Encode()

	var raw [][]interface{}
	nextURL := u.String()
	currentPage := float64(1)

	// TODO allow for selective pagination

	// iterate over results
	for len(nextURL) > 1 && currentPage <= d.maxPages {
		err = d.getJSONP(nextURL, &raw)
		if err != nil {
			return results, err
		}

		// simple corectness checks
		if raw[0][0] != "https.ct.cdsr" {
			return results, errors.New("Got Unexpected Query output: " + raw[0][0].(string))
		}
		if len(raw[0]) != 4 {
			// result not correct length, likely no results
			//fmt.Println(raw[0])
			break
		}
		if len(raw[0][3].([]interface{})) != 5 {
			// pageinfo result not correct length, likely no results
			//fmt.Println(raw[0])
			break
		}

		// pageInfo: [prevToken, nextToken, ? currentPage, totalPages]
		pageInfo := raw[0][3].([]interface{})
		currentPage = pageInfo[3].(float64)

		foundCerts := raw[0][1].([]interface{})
		for _, foundCert := range foundCerts {
			certHash := foundCert.([]interface{})[5].(string)
			certFP := fingerprint.FromB64Hash(certHash)
			results.fingerprints.Add(domain, certFP)
		}
		//fmt.Println("Page:", pageInfo[3])

		// create url or next page
		nextURL = ""
		if pageInfo[1] != nil {
			u, err := url.Parse(searchURL2)
			if err != nil {
				return results, err
			}

			// get page n
			q := u.Query()
			q.Set("p", pageInfo[1].(string))
			u.RawQuery = q.Encode()
			nextURL = u.String()
		}
	}

	return results, nil
}

func (d *googleCT) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	certNode := new(driver.CertResult)
	certNode.Fingerprint = fp
	certNode.Domains = make([]string, 0, 5)

	u, err := url.Parse(certURL)
	if err != nil {
		return certNode, err
	}

	q := u.Query()
	q.Set("hash", fp.B64Encode())
	u.RawQuery = q.Encode()

	var raw [][]interface{}

	err = d.getJSONP(u.String(), &raw)
	if err != nil {
		return certNode, err
	}

	// simple corectness checks
	if raw[0][0] != "https.ct.chr" {
		return certNode, errors.New("Got Unexpected Cert output: " + raw[0][0].(string))
	}
	if len(raw[0]) != 3 {
		// result not correct length, likely no results
		//fmt.Println(raw[0])
		return certNode, errors.New("Cert Does not exist! output: " + raw[0][0].(string))
	}

	certInfo := raw[0][1].([]interface{})
	domains := certInfo[7].([]interface{})

	for _, domain := range domains {
		certNode.Domains = append(certNode.Domains, domain.(string))
	}

	return certNode, nil
}
