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
$ ./certscan eff.org
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