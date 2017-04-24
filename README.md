# CertGraph
### A tool to crawl the graph of certificate Alternate Names

CertGraph crawls SSL certificates creating a directed graph where each domain is a node and the certificate alternative names for that domain's certificate are the edges to other domain nodes. Upon completion the Graph's adjacency list is printed.

This tool was designed to be used for host name enumeration via SSL certificates, but it can also show you a "chain" of trust between domains and the certificates that re used between them.

## Usage
```
Usage of ./certgraph: [OPTION]... HOST...
  -depth uint
        maximum BFS depth to go (default 20)
  -json
        print the graph as json
  -list
        only print the domains found and not the entire graph
  -parallel uint
        number of certificates to retrieve in parallel (default 10)
  -port uint
        tcp port to connect to (default 443)
  -save string
        save certs to folder in PEM formate
  -sort
        visit and print domains in sorted order
  -starttls
        connect without TLS and then upgrade with STARTTLS for SMTP, useful with -port 25
  -timeout uint
        tcp timeout in seconds (default 5)
  -verbose
        verbose logging
```

## Example
```
$ ./certgraph eff.org
eff.org 0       Good    5C699512FD8763FC50A105A14DB2526A10AE6EAC3E79F5F44A7F99E90189FBE5        [maps.eff.org web6.eff.org eff.org atlas.eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org]
web6.eff.org    1       Good    AF842FA69A720E9FB2F37BAF723A20F80B8C2072693E55D0A1EA78C7BABE2699        [*.eff.org *.dev.eff.org *.s.eff.org *.staging.eff.org]
https-everywhere-atlas.eff.org  1       Good    5C699512FD8763FC50A105A14DB2526A10AE6EAC3E79F5F44A7F99E90189FBE5        [kittens.eff.org maps.eff.org web6.eff.org eff.org atlas.eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org]
maps.eff.org    1       Good    5C699512FD8763FC50A105A14DB2526A10AE6EAC3E79F5F44A7F99E90189FBE5        [maps.eff.org web6.eff.org eff.org atlas.eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org]
atlas.eff.org   1       Good    5C699512FD8763FC50A105A14DB2526A10AE6EAC3E79F5F44A7F99E90189FBE5        [eff.org atlas.eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
httpse-atlas.eff.org    1       Good    5C699512FD8763FC50A105A14DB2526A10AE6EAC3E79F5F44A7F99E90189FBE5        [eff.org atlas.eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
kittens.eff.org 1       Good    5C699512FD8763FC50A105A14DB2526A10AE6EAC3E79F5F44A7F99E90189FBE5        [eff.org atlas.eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
dev.eff.org     2       No Host         []
s.eff.org       2       Good    AF842FA69A720E9FB2F37BAF723A20F80B8C2072693E55D0A1EA78C7BABE2699        [*.eff.org *.dev.eff.org *.s.eff.org *.staging.eff.org]
staging.eff.org 2       Good    AC3933B1B95BA5254F43ADBE5E3E38E539C74456EE2D00493F0B2F38F991D54F        [max-dev-supporters.eff.org leez-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org]
leez-dev-supporters.eff.org     3       Good    AC3933B1B95BA5254F43ADBE5E3E38E539C74456EE2D00493F0B2F38F991D54F        [staging.eff.org max-dev-supporters.eff.org leez-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org]
micah-dev2-supporters.eff.org   3       Good    AC3933B1B95BA5254F43ADBE5E3E38E539C74456EE2D00493F0B2F38F991D54F        [max-dev-supporters.eff.org leez-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org]
max-dev-supporters.eff.org      3       Good    AC3933B1B95BA5254F43ADBE5E3E38E539C74456EE2D00493F0B2F38F991D54F        [max-dev-supporters.eff.org leez-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org]
max-dev-www.eff.org     3       Good    AC3933B1B95BA5254F43ADBE5E3E38E539C74456EE2D00493F0B2F38F991D54F        [max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org max-dev-supporters.eff.org leez-dev-supporters.eff.org]
```
The above output represents the adjacency list for the graph for the root domain `eff.org`. The adjacency list is in the form:
`Node    Depth    Status    Cert-Fingerprint    [Edge1 Edge2 ... EdgeN]`

## [Releases](https://github.com/lanrat/certgraph/releases)

Precompiled releases will occasionally be uploaded to the [releases github page](https://github.com/lanrat/certgraph/releases). https://github.com/lanrat/certgraph/releases

## Compiling

To compile certgraph you must have a working go 1.5 or newer compiler on your system.
To compile for the running system compilation is as easy as running make
```
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

