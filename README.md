# CertGraph
### A tool to crawl the graph of certificate Alternate Names

CertGraph crawls SSL certificates creating a directed graph where each domain is a node and the certificate alternative names for that domain's certificate are the edges to other domain nodes. New domains are printed as they are found. In Detailed mode upon completion the Graph's adjacency list is printed.

Crawling defaults to collectng certificate by connecting over TCP, however there are multiple drivers that can search [Certificate Transparency](https://www.certificate-transparency.org/) logs.

This tool was designed to be used for host name enumeration via SSL certificates, but it can also show you a "chain" of trust between domains and the certificates that re-used between them.

## Usage
```
Usage of ./certgraph: [OPTION]... HOST...
        https://github.com/lanrat/certgraph
OPTIONS:
  -cdn
        include certificates from CDNs
  -ct-subdomains
        include sub-domains in certificate transparancy search
  -depth uint
        maximum BFS depth to go (default 5)
  -details
        print details about the domains crawled
  -driver string
        driver to use [http, smtp, google, crtsh] (default "http")
  -json
        print the graph as json, can be used for graph in web UI
  -parallel uint
        number of certificates to retrieve in parallel (default 10)
  -save string
        save certs to folder in PEM formate
  -timeout uint
        tcp timeout in seconds (default 10)
  -verbose
        verbose logging
  -version
        print version and exit

```

## Drivers

CertGraph has multiple options for querying SSL certificates. The driver is responsible for retrieving the certificates for a given domain. Currently there are the following drivers:

 * **http** this is the default driver which works by connecting to the hosts over HTTPS and retrieving the certificates from the SSL connection
 
 * **smtp** like the *http* driver, but connects over port 25 and issues the *starttls* command to retrieve the certificates from the SSL connection

 * **crtsh** this driver searches Certificate Transparency logs via [crt.sh](https://crt.sh/). No packets are sent to any of the domains when using this driver

 * **google** this is another Certificate Transparency driver that behaves like *crtsh* but uses the [Googe Certificate Transparency Lookup Tool](https://transparencyreport.google.com/https/certificates)


## Example
```
$ ./certgraph -details eff.org
eff.org 0       Good    42E3E4605D8BB4608EB64936E2176A98B97EBF2E0F8F93A64A6640713C7D4325
maps.eff.org    1       Good    42E3E4605D8BB4608EB64936E2176A98B97EBF2E0F8F93A64A6640713C7D4325
https-everywhere-atlas.eff.org  1       Good    42E3E4605D8BB4608EB64936E2176A98B97EBF2E0F8F93A64A6640713C7D4325
httpse-atlas.eff.org    1       Good    42E3E4605D8BB4608EB64936E2176A98B97EBF2E0F8F93A64A6640713C7D4325
atlas.eff.org   1       Good    42E3E4605D8BB4608EB64936E2176A98B97EBF2E0F8F93A64A6640713C7D4325
kittens.eff.org 1       Good    42E3E4605D8BB4608EB64936E2176A98B97EBF2E0F8F93A64A6640713C7D4325
```
The above output represents the adjacency list for the graph for the root domain `eff.org`. The adjacency list is in the form:
`Node    Depth    Status    Cert-Fingerprint`

## [Releases](https://github.com/lanrat/certgraph/releases)

Precompiled releases will occasionally be uploaded to the [releases github page](https://github.com/lanrat/certgraph/releases). https://github.com/lanrat/certgraph/releases

## Compiling

To compile certgraph you must have a working go 1.9 or newer compiler on your system, as well as the golang [dep](https://github.com/golang/dep) dependency management tool.
To compile for the running system compilation is as easy as running make
```
certgraph$ make dep
dep ensure
certgraph$ make
go build -o certgraph certgraph.go
```

## [Web UI](https://lanrat.github.io/certgraph/)

A web UI is provided in the docs folder and is accessable at the github pages url [https://lanrat.github.io/certgraph/](https://lanrat.github.io/certgraph/).

The web UI takes the output provided with the `-json` flag.
The JSON graph can be sent to the web interface as an uploaded file, remote URL, or as the query string using the data variable.

### [Example 1: eff.org](https://lanrat.github.io/certgraph/?data=https://gist.githubusercontent.com/lanrat/8187d01793bf3e578d76495182654206/raw/c49741b5206d81935febdf563452cc4346381e52/eff.json)

[![eff.org graph](https://cloud.githubusercontent.com/assets/164192/20861413/6ba0fcca-b944-11e6-857f-ddd613130ea3.png)](https://lanrat.github.io/certgraph/?data=https://gist.githubusercontent.com/lanrat/8187d01793bf3e578d76495182654206/raw/c49741b5206d81935febdf563452cc4346381e52/eff.json)

### [Example 2: google.com](https://lanrat.github.io/certgraph/?data=https://gist.githubusercontent.com/lanrat/1ab1e78aaf5798049650d8d8ad7b58a1/raw/426d3a2498626014cb5ba2856ad0899787e4103f/google.json)

[![google.com graph](https://cloud.githubusercontent.com/assets/164192/19752837/16cb8302-9bb5-11e6-810d-ea34594a63ef.png)](https://lanrat.github.io/certgraph/?data=https://gist.githubusercontent.com/lanrat/1ab1e78aaf5798049650d8d8ad7b58a1/raw/426d3a2498626014cb5ba2856ad0899787e4103f/google.json)

### [Example 3: whitehouse.gov](https://lanrat.github.io/certgraph/?data=https://gist.githubusercontent.com/lanrat/96c47dfee0faaaad633cc830b7e3b997/raw/3c79fed837cb3202e220de21d2a8eb128f4bbd9f/whitehouse.json)

[![whitehouse.gov graph](https://cloud.githubusercontent.com/assets/164192/20861407/4775ff26-b944-11e6-888c-4d93e3333494.png)](https://lanrat.github.io/certgraph/?data=https://gist.githubusercontent.com/lanrat/96c47dfee0faaaad633cc830b7e3b997/raw/3c79fed837cb3202e220de21d2a8eb128f4bbd9f/whitehouse.json)

