all: certgraph

certgraph: certgraph.go
	go build -o $@ $^

fmt:
	gofmt -s -w -l .
