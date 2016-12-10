GIT_DATE := $(shell git log -1 --date=short --pretty='%cd' | tr -d -)

all: certgraph

fmt:
	gofmt -s -w -l .

certgraph: certgraph.go
	go build -o $@ $^

certgraph.linux: certgraph.go
	GOOS=linux go build -o $@ $^

certgraph.mac: certgraph.go
	GOOS=darwin go build -o $@ $^

certgraph.exe: certgraph.go
	GOOS=windows GOARCH=386 go build -o certgraph.exe $^

certgraph.linux.$(GIT_DATE).zip: certgraph.linux
	zip $@ $^
	
certgraph.mac.$(GIT_DATE).zip: certgraph.mac
	zip $@ $^

certgraph.win.$(GIT_DATE).zip: certgraph.exe
	zip $@ $^

release: certgraph.linux.$(GIT_DATE).zip certgraph.mac.$(GIT_DATE).zip certgraph.win.$(GIT_DATE).zip