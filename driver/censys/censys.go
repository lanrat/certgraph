// Package censys file implements a client to search Censys's CT database
// Certificate Transparency search
// https://transparencyreport.google.com/https/certificates
//
// As the API is unofficial and has been reverse engineered it may stop working
// at any time and comes with no guarantees.
package censys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"time"

	"github.com/lanrat/certgraph/driver"
	"github.com/lanrat/certgraph/fingerprint"
	"github.com/lanrat/certgraph/status"
)

const driverName = "censys"

var debug = false

// TODO support rate limits & pagination

var (
	defaultHTTPClient = &http.Client{}

	appID  = flag.String("censys-appid", "", "censys API AppID")
	secret = flag.String("censys-secret", "", "censys API Secret")
)

func init() {
	driver.AddDriver(driverName)
}

type censys struct {
	appID             string
	secret            string
	save              bool
	savePath          string
	includeSubdomains bool
	includeExpired    bool
}

type censysCertDriver struct {
	host         string
	fingerprints driver.FingerprintMap
	driver       *censys
}

func (c *censysCertDriver) GetFingerprints() (driver.FingerprintMap, error) {
	return c.fingerprints, nil
}

func (c *censysCertDriver) GetStatus() status.Map {
	return status.NewMap(c.host, status.New(status.CT))
}

func (c *censysCertDriver) GetRelated() ([]string, error) {
	return make([]string, 0), nil
}

func (c *censysCertDriver) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	return c.driver.QueryCert(fp)
}

// TODO support pagination
func domainSearchParam(domain string, includeExpired, includeSubdomain bool) certSearchParam {
	var s certSearchParam
	if includeSubdomain {
		s.Query = fmt.Sprintf("(parsed.names: %s )", domain)
	} else {
		s.Query = fmt.Sprintf("(parsed.names.raw: %s)", domain)
	}
	if !includeExpired {
		dateStr := time.Now().Format("2006-01-02") // YYYY-MM-DD
		expQuery := fmt.Sprintf(" AND ((parsed.validity.end: [%s TO *]) AND (parsed.validity.start: [* TO %s]))", dateStr, dateStr)
		s.Query = s.Query + expQuery
	}
	s.Page = 1
	s.Flatten = true
	s.Fields = []string{"parsed.fingerprint_sha256", "parsed.names"}
	return s
}

// Driver creates a new CT driver for censys
func Driver(savePath string, includeSubdomains, includeExpired bool) (driver.Driver, error) {
	if *appID == "" || *secret == "" {
		return nil, fmt.Errorf("censys requires an appID and secret to run")
	}
	d := new(censys)
	d.appID = *appID
	d.secret = *secret
	d.savePath = savePath
	d.includeSubdomains = includeSubdomains
	d.includeExpired = includeExpired
	return d, nil
}

func (d *censys) GetName() string {
	return driverName
}

func (d *censys) request(method, url string, request io.Reader) (*http.Response, error) {
	totalTrys := 3
	var err error
	var req *http.Request
	var resp *http.Response
	for try := 1; try <= totalTrys; try++ {
		req, err = http.NewRequest(method, url, request)
		if err != nil {
			return nil, err
		}
		if request != nil {
			req.Header.Add("Content-Type", "application/json")
		}
		req.Header.Add("Accept", "application/json")
		req.SetBasicAuth(d.appID, d.secret)

		resp, err = defaultHTTPClient.Do(req)
		if err != nil {
			err = fmt.Errorf("error on request [%d/%d] %s, got error %w: %+v", try, totalTrys, url, err, resp)
		} else {
			return resp, nil
		}

		// sleep only if we will try again
		if try < totalTrys {
			time.Sleep(time.Second * 10)
		}
	}
	return resp, err
}

// jsonRequest performs a request to the API endpoint sending and receiving JSON objects
func (d *censys) jsonRequest(method, url string, request, response interface{}) error {
	var payloadReader io.Reader
	if request != nil {
		jsonPayload, err := json.Marshal(request)
		if err != nil {
			return err
		}
		payloadReader = bytes.NewReader(jsonPayload)
	}

	if debug {
		log.Printf("DEBUG: request to %s %s", method, url)
		if request != nil {
			prettyJSONBytes, _ := json.MarshalIndent(request, "", "\t")
			log.Printf("request payload:\n%s\n", string(prettyJSONBytes))
		}
	}

	resp, err := d.request(method, url, payloadReader)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// got an error, decode it
	if resp.StatusCode != http.StatusOK {
		var errorResp errorResponse
		err := fmt.Errorf("error on request %s, got Status %s %s", url, resp.Status, http.StatusText(resp.StatusCode))
		jsonError := json.NewDecoder(resp.Body).Decode(&errorResp)
		if jsonError != nil {
			return fmt.Errorf("error decoding json %w on error request: %s", jsonError, err.Error())
		}
		return fmt.Errorf("%w, HTTPStatus: %d Message: %q", err, errorResp.ErrorCode, errorResp.Error)
	}

	if response != nil {
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return err
		}
		if debug {
			prettyJSONBytes, _ := json.MarshalIndent(response, "", "\t")
			log.Printf("response payload:\n%s\n", string(prettyJSONBytes))
		}
	}

	return nil
}

func (d *censys) QueryDomain(domain string) (driver.Result, error) {
	results := &censysCertDriver{
		host:         domain,
		fingerprints: make(driver.FingerprintMap),
		driver:       d,
	}
	params := domainSearchParam(domain, d.includeExpired, d.includeSubdomains)
	url := "https://search.censys.io/api/v1/search/certificates"
	var resp certSearchResponse
	err := d.jsonRequest(http.MethodPost, url, params, &resp)
	if err != nil {
		return results, err
	}

	for _, r := range resp.Results {
		fp := fingerprint.FromHexHash(r.Fingerprint)
		results.fingerprints.Add(domain, fp)
	}

	if debug {
		log.Printf("censys: got %d results for %s.", len(resp.Results), domain)
	}

	return results, nil
}

func (d *censys) QueryCert(fp fingerprint.Fingerprint) (*driver.CertResult, error) {
	certNode := new(driver.CertResult)
	certNode.Fingerprint = fp
	certNode.Domains = make([]string, 0, 5)

	url := fmt.Sprintf("https://search.censys.io/api/v1/view/certificates/%s", fp.HexString())
	var resp certViewResponse
	err := d.jsonRequest(http.MethodGet, url, nil, &resp)
	if err != nil {
		return certNode, err
	}

	if debug {
		log.Printf("DEBUG QueryCert(%s): %v", fp.HexString(), resp.Parsed.Names)
	}

	certNode.Domains = append(certNode.Domains, resp.Parsed.Names...)

	if d.save {
		rawCert, err := base64.StdEncoding.DecodeString(resp.Raw)
		if err != nil {
			return certNode, err
		}
		err = driver.RawCertToPEMFile(rawCert, path.Join(d.savePath, fp.HexString())+".pem")
		if err != nil {
			return certNode, err
		}
	}

	return certNode, nil
}
