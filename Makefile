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

release.linux: certgraph.linux
	zip certgraph.linux.$(GIT_DATE).zip $^
	
release.mac: certgraph.mac
	zip certgraph.mac.$(GIT_DATE).zip $^

release.win: certgraph.exe
	zip certgraph.win.$(GIT_DATE).zip $^

release: release.mac release.linux release.win
