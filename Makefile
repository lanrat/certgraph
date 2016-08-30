all: certscan

certscan: certscan.go
	go build -o $@ $^

fmt:
	gofmt -s -w -l .
