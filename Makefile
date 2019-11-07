export GO111MODULE=on

.PHONY: all build test clean distclean

##@ Building
all: build test ## Builds and run unit tests

build: ## Builds spiffe-helper
	go build

test: ## Run spiffe-helper unit tests
	go test

vendor: ## Creates a vendored copy of dependencies
	go mod vendor

clean: ## Removes object files from package source directories
	go clean

distclean: ## Removes installed binary, vendored dependencies and dist directory
	go clean -i
	rm -rf vendor dist


##@ Releasing
release: ## Runs goreleaser (expected to be run on CI)
	./goreleaser

release-skip-publish: ## Runs goreleaser without publishing (expected to be run locally)
	./goreleaser --snapshot --skip-publish --rm-dist

goreleaser: ## Downloads goreleaser
	curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | bash -s -- -b .

##@ Help

# Help message settings
cyan := $(shell which tput > /dev/null && tput setaf 6 || echo "")
reset := $(shell which tput > /dev/null && tput sgr0 || echo "")
bold  := $(shell which tput > /dev/null && tput bold || echo "")
target_max_char=25

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\n$(bold)Usage:$(reset) make $(cyan)<target>$(reset)\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(cyan)%-$(target_max_char)s$(reset) %s\n", $$1, $$2 } /^##@/ { printf "\n $(bold)%s$(reset) \n", substr($$0, 5) } ' $(MAKEFILE_LIST)
