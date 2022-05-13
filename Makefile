GIT_DATE := $(shell git log -1 --date=short --pretty='%cd' | tr -d -)
GIT_HASH := $(shell git rev-parse HEAD)

BUILD_FLAGS := -trimpath -ldflags "-w -s -X main.gitDate=$(GIT_DATE) -X main.gitHash=$(GIT_HASH)"

PLATFORMS := linux/amd64 linux/386 linux/arm linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/386 openbsd/amd64
SOURCES := $(shell find . -maxdepth 1 -type f -name "*.go")
ALL_SOURCES = $(shell find . -type f -name '*.go') go.mod docs/*

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
ext = $(shell if [ "$(os)" = "windows" ]; then echo ".exe"; fi)

.PHONY: all release fmt clean serv $(PLATFORMS) docker check deps update-deps

all: certgraph

release: $(PLATFORMS)
	rm -r build/bin/

certgraph: $(SOURCES) $(ALL_SOURCES)
	go build $(BUILD_FLAGS) -o $@ $(SOURCES)

$(PLATFORMS): $(SOURCES)
	CGO_ENABLED=0 GOOS=$(os) GOARCH=$(arch) go build $(BUILD_FLAGS) -o 'build/bin/$(os)/$(arch)/certgraph$(ext)' $(SOURCES)
	mkdir -p build/$(GIT_DATE)/; cd build/bin/$(os)/$(arch)/; zip -r ../../../$(GIT_DATE)/certgraph-$(os)-$(arch)-$(GIT_DATE).zip .; cd ../../../

docker: Dockerfile $(ALL_SOURCES)
	docker build -t lanrat/certgraph .

deps: go.mod
	GOPROXY=direct go mod download
	GOPROXY=direct go get -u all

fmt:
	gofmt -s -w -l .

install: $(SOURCES) $(ALL_SOURCES)
	go install $(BUILD_FLAGS)

clean:
	rm -rf certgraph build/

check: | lint check1 check2

check1:
	golangci-lint run

check2:
	staticcheck -f stylish -checks all ./...

lint:
	golint ./...

serv: certgraph
	./certgraph --serve 127.0.0.1:8080

update-deps:
	go get -u
	go mod tidy

test:
	go test -v ./... | grep -v "\[no test files\]"