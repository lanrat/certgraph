package google

/*
 * This file implements an unofficial API client for Google's
 * Certificate Transparency search
 * https://transparencyreport.google.com/https/certificates
 *
 * As the API is unofficial and has been reverse engineered it may stop working
 * at any time and comes with no guarantees.
 */

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/graph"
)

// BASE URLs for Googl'e CT API
const searchURL1 = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=false&include_subdomains=false&domain=example.com"
const searchURL2 = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?p=DEADBEEF"
const certURL = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certbyhash?hash=DEADBEEF"

type googleCT struct {
	max_pages  float64
	jsonClient *http.Client
}

func NewGoogleCTDriver() (driver.Driver, error) {
	d := new(googleCT)
	d.max_pages = 50 // TODO: make adjustable
	d.jsonClient = &http.Client{Timeout: 10 * time.Second}

	return d, nil
}

// gets JSON from url and parses it into target object
func (d *googleCT) getJsonP(url string, target interface{}) error {
	r, err := d.jsonClient.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return errors.New("Got non OK HTTP status:" + r.Status + "on URL: " + url)
	}

	respData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	respData = respData[5:] // this removes the leading ")]}'" from the response

	return json.Unmarshal(respData, target)
}

func (d *googleCT) QueryDomain(domain string, include_expired bool, include_subdomains bool) ([]graph.Fingerprint, error) {
	results := make([]graph.Fingerprint, 0, 5)

	u, err := url.Parse(searchURL1)
	if err != nil {
		return results, err
	}

	// get page 1
	q := u.Query()
	q.Set("include_expired", strconv.FormatBool(include_expired))
	q.Set("include_subdomains", strconv.FormatBool(include_subdomains))
	q.Set("domain", domain)
	u.RawQuery = q.Encode()

	var raw [][]interface{}
	nextURL := u.String()
	currentPage := float64(1)

	// TODO allow for selective pagnation

	// iterate over results
	for len(nextURL) > 1 && currentPage <= d.max_pages {
		err = d.getJsonP(nextURL, &raw)
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

		// pageInfo: [prevToken, nextToken, ? currPage, totalPages]
		pageInfo := raw[0][3].([]interface{})
		currentPage = pageInfo[3].(float64)

		foundCerts := raw[0][1].([]interface{})
		for _, foundCert := range foundCerts {
			certHash := foundCert.([]interface{})[5].(string)
			certFP := graph.FingerprintFromB64(certHash)
			results = append(results, certFP)
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

func (d *googleCT) QueryCert(fp graph.Fingerprint) (*graph.CertNode, error) {
	certnode := new(graph.CertNode)
	certnode.Fingerprint = fp
	certnode.Domains = make([]string, 0, 5)
	certnode.CT = true

	u, err := url.Parse(certURL)
	if err != nil {
		return certnode, err
	}

	q := u.Query()
	q.Set("hash", fp.B64Encode())
	u.RawQuery = q.Encode()

	var raw [][]interface{}

	err = d.getJsonP(u.String(), &raw)
	if err != nil {
		return certnode, err
	}

	// simple corectness checks
	if raw[0][0] != "https.ct.chr" {
		return certnode, errors.New("Got Unexpected Cert output: " + raw[0][0].(string))
	}
	if len(raw[0]) != 3 {
		// result not correct length, likely no results
		//fmt.Println(raw[0])
		return certnode, errors.New("Cert Does not exist! output: " + raw[0][0].(string))
	}

	certInfo := raw[0][1].([]interface{})
	domains := certInfo[7].([]interface{})

	for _, domain := range domains {
		certnode.Domains = append(certnode.Domains, domain.(string))
	}

	return certnode, nil
}

// example function to use Google's CT API
func (d *googleCT) CTexample(domain string) error {
	s, err := d.QueryDomain(domain, false, false)
	if err != nil {
		return err
	}

	for i := range s {
		fmt.Println(s[i].HexString(), " ", s[i].B64Encode())
		cert, err := d.QueryCert(s[i])
		if err != nil {
			return err
		}
		for j := range cert.Domains {
			fmt.Println("\t", cert.Domains[j])
		}
	}

	return nil
}
