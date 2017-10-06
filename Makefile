.PHONY: all utils build test clean distclean

build:
	go build

all: utils vendor build test

utils:
	go get github.com/Masterminds/glide
	go get github.com/goreleaser/goreleaser

vendor: glide.yaml glide.lock
	glide install

test:
	go test

clean:
	go clean

distclean:
	go clean -i
	rm -rf vendor dist

release:
	goreleaser || true
