SOURCES := $(shell find . -maxdepth 1 -type f -name "*.go")
ALL_SOURCES = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

all: ct

ct: $(SOURCES) $(ALL_SOURCES)
	go build -o $@ $(SOURCES)

fmt:
	gofmt -s -w -l .

clean:
	rm ct

.PHONY: all fmt clean 
