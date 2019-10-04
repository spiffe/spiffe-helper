export GO111MODULE=on

.PHONY: all utils build test clean distclean

build:
	go build

all: utils build test

utils:
	go get github.com/goreleaser/goreleaser

vendor:
	go mod vendor

test:
	go test

clean:
	go clean

distclean:
	go clean -i
	rm -rf vendor dist

release:
	goreleaser || true
