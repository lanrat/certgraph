default: certgraph

RELEASE_DEPS = fmt lint
include release.mk

BUILD_FLAGS := -trimpath -ldflags "-w -s -X main.version=${VERSION}"

SOURCES := $(shell find . -maxdepth 1 -type f -name "*.go")
ALL_SOURCES = $(shell find . -type f -name '*.go') go.mod docs/*

.PHONY: release fmt clean serv docker lint deps update-deps

certgraph: $(SOURCES) $(ALL_SOURCES)
	go build $(BUILD_FLAGS) -o $@ .

docker: Dockerfile $(ALL_SOURCES)
	docker build --build-arg VERSION=${VERSION} -t lanrat/certgraph .

deps: go.mod
	GOPROXY=direct go mod download
	GOPROXY=direct go get -u all

update-deps:
	go get -u
	go mod tidy

fmt:
	go fmt ./...

clean:
	rm -rf certgraph dist/

lint:
	golangci-lint run

serv: certgraph
	./certgraph --serve 127.0.0.1:8080

test:
	go test -v ./... | grep -v "\[no test files\]"

.PHONY: goreleaser
goreleaser:
	goreleaser release --snapshot --clean
