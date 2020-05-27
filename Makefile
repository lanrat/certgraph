GIT_DATE := $(shell git log -1 --date=short --pretty='%cd' | tr -d -)
GIT_HASH := $(shell git rev-parse HEAD)

BUILD_FLAGS := -trimpath -ldflags "-w -s -X main.gitDate=$(GIT_DATE) -X main.gitHash=$(GIT_HASH)"

PLATFORMS := linux/amd64 linux/386 linux/arm darwin/amd64 windows/amd64 windows/386 openbsd/amd64
SOURCES := $(shell find . -maxdepth 1 -type f -name "*.go")
ALL_SOURCES = $(shell find . -type f -name '*.go') go.mod

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
ext = $(shell if [ "$(os)" = "windows" ]; then echo ".exe"; fi)

.PHONY: all release fmt clean serv $(PLATFORMS) docker check

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

fmt:
	gofmt -s -w -l .

install: $(SOURCES) $(ALL_SOURCES)
	go install $(BUILD_FLAGS)

clean:
	rm -r certgraph build/

check:
	golangci-lint run --exclude-use-default || true
	staticcheck -unused.whole-program -checks all ./...

serv:
	(cd docs; python -m SimpleHTTPServer)

updateMod:
	go get -u
