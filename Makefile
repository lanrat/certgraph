GIT_DATE := $(shell git log -1 --date=short --pretty='%cd' | tr -d -)
GIT_HASH := $(shell git rev-parse HEAD)

BUILD_FLAGS := -ldflags "-X main.git_date=$(GIT_DATE) -X main.git_hash=$(GIT_HASH)"

all: certgraph

fmt:
	gofmt -s -w -l .

certgraph: certgraph.go
	go build $(BUILD_FLAGS) -o $@ $^

certgraph.linux: certgraph.go
	GOOS=linux go build $(BUILD_FLAGS) -o $@ $^

certgraph.mac: certgraph.go
	GOOS=darwin go build $(BUILD_FLAGS) -o $@ $^

certgraph.exe: certgraph.go
	GOOS=windows GOARCH=386 go build $(BUILD_FLAGS) -o certgraph.exe $^

certgraph.openbsd: certgraph.go
	GOOS=openbsd go build $(BUILD_FLAGS) -o $@ $^

certgraph.linux.$(GIT_DATE).zip: certgraph.linux
	zip $@ $^
	
certgraph.mac.$(GIT_DATE).zip: certgraph.mac
	zip $@ $^

certgraph.win.$(GIT_DATE).zip: certgraph.exe
	zip $@ $^

certgraph.openbsd.$(GIT_DATE).zip: certgraph.openbsd
	zip $@ $^

release: certgraph.linux.$(GIT_DATE).zip certgraph.mac.$(GIT_DATE).zip certgraph.win.$(GIT_DATE).zip certgraph.openbsd.$(GIT_DATE).zip

clean:
	rm certgraph certgraph.linux certgraph.mac certgraph.exe certgraph.openbsd certgraph.*.zip