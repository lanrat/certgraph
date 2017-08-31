package main

/*
 * This file implements an unofficial API client for Google's
 * Certificate Transparency search
 * https://www.google.com/transparencyreport/https/ct/
 *
 * As the API is unofficial and has been reverse engineered it may stop working
 * at any time and comes with no guarantees.
 */

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// BASE URLs for Googl'e CT API
const searchURL = "https://www.google.com/transparencyreport/jsonp/ct/search?incl_exp=false&incl_sub=false&c=jsonp&token=CAA=&domain=example.com"
const certURL = "https://www.google.com/transparencyreport/jsonp/ct/cert?c=jsonp&hash=AAA"

// global vars
var jsonClient = &http.Client{Timeout: 10 * time.Second}
var jsonPattern = regexp.MustCompile(`jsonp\((.*)\)`)

// struct to hold the results of a hash search
type CTHashSearch struct {
	Result    CTCertResult     `json:"result"`
	Refrences []CTCertRefrence `json:"references"`
}

// struct to hold details of a certificate
type CTCertResult struct {
	SerialNumber       string   `json:"serialNumber"`
	Subject            string   `json:"subject"`
	DnsNames           []string `json:"dnsNames"`
	CertificateType    string   `json:"certificateType"`
	Issuer             string   `json:"issuer"`
	ValidFrom          int64    `json:"validFrom"`
	ValidTo            int64    `json:"validTo"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
}

// struct to hold details about refrences to a certificate
type CTCertRefrence struct {
	LogName string `json:"logName"`
	LogId   string `json:"logId"`
	Index   int    `json:"index"`
}

// struct to hold the results of a domain search
type CTDomainSearch struct {
	Results         []CTDomainSearchResult    `json:"results"`
	StartIndex      int                       `json:"startIndex"`
	NumResults      int                       `json:"numResults"`
	NextPageToken   string                    `json:"nextPageToken"`
	IssuanceSummary []CTDomainIssuanceSummary `json:"issuanceSummary"`
	Expired         bool                      // not part of the json API but added as part of the query
	Subdomains      bool                      // not part of the json API but added as part of the query
}

// struct to hold a single certifiacate result from a domain search
type CTDomainSearchResult struct {
	SerialNumber string `json:"serialNumber"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	ValidFrom    int64  `json:"validFrom"`
	ValidTo      int64  `json:"validTo"`
	NumLogs      int    `json:"numLogs"`
	Hash         string `json:"hash"`
	FirstDnsName string `json:"firstDnsName"`
	NumDnsNames  int    `json:"numDnsNames"`
}

func (sr *CTDomainSearchResult) GetFingerprint() fingerprint {
	var fp fingerprint
	data, err := base64.StdEncoding.DecodeString(sr.Hash)
	if err != nil {
		v(err)
	}
	if len(data) != sha256.Size {
		v("Hash is not correct SHA256 size", sr.Hash)
	}
	for i := 0; i < len(data) && i < len(fp); i++ {
		fp[i] = data[i]
	}
	return fp
}

// struct to hold CA information about a domain search
type CTDomainIssuanceSummary struct {
	IssuerUid    string `json:"issuerUid"`
	IssuerPkHash string `json:"issuerPkHash"`
	Subject      string `json:"subject"`
	numIssued    string `json:"numIssued"`
}

// gets JSON from url and parses it into target object
func getJsonP(url string, target interface{}) error {
	r, err := jsonClient.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return errors.New("Got non OK HTTP status:" + r.Status)
	}

	respData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	obj := jsonPattern.FindSubmatch(respData)
	if len(obj) < 2 {
		return errors.New("Unable to find JSONP in response")
	}

	return json.Unmarshal(obj[1], target)
}

// queries the CT logs for domain, gets all pages of results
func QueryDomain(domain string, include_expired bool, include_subdomains bool) ([]CTDomainSearchResult, error) {
	results := make([]CTDomainSearchResult, 0, 5)

	u, err := url.Parse(searchURL)
	if err != nil {
		return results, err
	}

	token := "CAA="
	// get every page
	for token != "" {
		q := u.Query()
		q.Set("incl_exp", strconv.FormatBool(include_expired))
		q.Set("incl_sub", strconv.FormatBool(include_subdomains))
		q.Set("domain", domain)
		q.Set("token", token)
		u.RawQuery = q.Encode()

		search := new(CTDomainSearch)
		search.Expired = include_expired
		search.Subdomains = include_subdomains
		err := getJsonP(u.String(), search)
		if err != nil {
			return results, err
		}
		token = search.NextPageToken

		results = append(results, search.Results...)
	}

	return results, nil
}

// queries the CT logs for the hash to get the cert details
func QueryHash(hash string) (CTCertResult, error) {
	search := new(CTHashSearch)

	u, err := url.Parse(certURL)
	if err != nil {
		return search.Result, err
	}

	q := u.Query()
	q.Set("hash", hash)
	u.RawQuery = q.Encode()

	err = getJsonP(u.String(), search)
	return search.Result, err
}

// example function to use Google's CT API
func ct_example(domain string) error {
	s, err := QueryDomain(domain, false, false)
	if err != nil {
		return err
	}

	for i := range s {
		fmt.Print(s[i].Hash, " ")
		h, err := QueryHash(s[i].Hash)
		if err != nil {
			return err
		}
		fmt.Println(h.SerialNumber)
		for j := range h.DnsNames {
			fmt.Println("\t", h.DnsNames[j])
		}
	}

	return nil
}
