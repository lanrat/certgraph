all: certgraph

certgraph: certgraph.go
	go build -o $@ $^

certgraph.mac: certgraph.go
	GOOS=darwin go build -o $@ $^

fmt:
	gofmt -s -w -l .
