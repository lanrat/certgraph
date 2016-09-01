# CertScan
### A tool to crawl the graph of certificate Alternate Names

CertScan crawls SSL certificates creating a directed graph where each domain is a node and the certificate alternative names for that domain's certificate are the edges to other domain nodes. Upon completion the Graph's adjacency list is printed.

This tool was designed to be used for host name enumeration via SSL certificates, but it can also show you a "chain" of trust between domains and the certificates that re used between them.

## Usage
```
Usage of ./certscan: [OPTION]... HOST...
  -depth uint
        maximum BFS depth to go (default 20)
  -parallel uint
        number of certificates to retrieve in parallel (default 10)
  -port uint
        tcp port to connect to (default 443)
  -save string
        save certs to folder
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
$ ./certscan eff.org
atlas.eff.org 1 [atlas.eff.org eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
dev.eff.org 2 []
eff.org 0 [atlas.eff.org eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
https-everywhere-atlas.eff.org 1 [atlas.eff.org eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
httpse-atlas.eff.org 1 [atlas.eff.org eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
kittens.eff.org 1 [atlas.eff.org eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
leez-dev-supporters.eff.org 3 [leez-dev-supporters.eff.org max-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org]
maps.eff.org 1 [atlas.eff.org eff.org https-everywhere-atlas.eff.org httpse-atlas.eff.org kittens.eff.org maps.eff.org web6.eff.org]
max-dev-supporters.eff.org 3 [leez-dev-supporters.eff.org max-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org]
max-dev-www.eff.org 3 [leez-dev-supporters.eff.org max-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org]
micah-dev2-supporters.eff.org 3 [leez-dev-supporters.eff.org max-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org]
s.eff.org 2 [*.dev.eff.org *.eff.org *.s.eff.org *.staging.eff.org]
staging.eff.org 2 [leez-dev-supporters.eff.org max-dev-supporters.eff.org max-dev-www.eff.org micah-dev2-supporters.eff.org staging.eff.org]
web6.eff.org 1 [*.dev.eff.org *.eff.org *.s.eff.org *.staging.eff.org]
```
The above output represents the adjacency list for the graph for the root domain `eff.org`. The adjacency list is in the form:
`node depth [edge1  edge2 ... edgeN]`