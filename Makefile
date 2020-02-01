export GO111MODULE=on
DIR := ${CURDIR}

E:=@
ifeq ($(V),1)
	E=
endif

cyan := $(shell which tput > /dev/null && tput setaf 6 2>/dev/null || echo "")
reset := $(shell which tput > /dev/null && tput sgr0 2>/dev/null || echo "")
bold  := $(shell which tput > /dev/null && tput bold 2>/dev/null || echo "")

.PHONY: default all help

default: build

all: build lint test

help:
	@echo "$(bold)Usage:$(reset) make $(cyan)<target>$(reset)"
	@echo
	@echo "$(bold)Build:$(reset)"
	@echo "  $(cyan)build$(reset)                         - build SPIFFE Helper binary (default)"
	@echo "  $(cyan)artifact$(reset)                      - build SPIFFE Helper tarball artifact"
	@echo
	@echo "$(bold)Test:$(reset)"
	@echo "  $(cyan)test$(reset)                          - run unit tests"
	@echo
	@echo "$(bold)Build and test:$(reset)"
	@echo "  $(cyan)all$(reset)                           - build all SPIFFE Helper binary, lint the code, and run unit tests"
	@echo
	@echo "$(bold)Clean:$(reset)"
	@echo "  $(cyan)clean$(reset)                         - remove object files from package source directories"
	@echo
	@echo "For verbose output set V=1"
	@echo "  for example: $(cyan)make V=1 build$(reset)"


############################################################################
# OS/ARCH detection
############################################################################
os1=$(shell uname -s)
os2=
ifeq ($(os1),Darwin)
os1=darwin
os2=osx
else ifeq ($(os1),Linux)
os1=linux
os2=linux
else
$(error unsupported OS: $(os1))
endif

arch1=$(shell uname -m)
ifeq ($(arch1),x86_64)
arch2=amd64
else
$(error unsupported ARCH: $(arch1))
endif

############################################################################
# Vars
############################################################################

build_dir := $(DIR)/.build/$(os1)-$(arch1)

go_version := $(shell cat .go-version)
go_dir := $(build_dir)/go/$(go_version)
go_bin_dir := $(go_dir)/bin
go_url = https://storage.googleapis.com/golang/go$(go_version).$(os1)-$(arch2).tar.gz
go := PATH="$(go_bin_dir):$(PATH)" go

golangci_lint_version = v1.21.0
golangci_lint_dir = $(build_dir)/golangci_lint/$(golangci_lint_version)
golangci_lint_bin = $(golangci_lint_dir)/golangci-lint

############################################################################
# Install toolchain
############################################################################

go-check:
ifneq (go$(go_version), $(shell $(go) version 2>/dev/null | cut -f3 -d' '))
	@echo "Installing go$(go_version)..."
	$(E)rm -rf $(dir $(go_dir))
	$(E)mkdir -p $(go_dir)
	$(E)curl -sSfL $(go_url) | tar xz -C $(go_dir) --strip-components=1
endif

install-toolchain: install-golangci-lint | go-check

install-golangci-lint: $(golangci_lint_bin)

$(golangci_lint_bin):
	@echo "Installing golangci-lint $(golangci_lint_version)..."
	$(E)rm -rf $(dir $(golangci_lint_dir))
	$(E)mkdir -p $(golangci_lint_dir)
	$(E)curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(golangci_lint_dir) $(golangci_lint_version)

#############################################################################
# Utility functions and targets
#############################################################################

.PHONY: git-clean-check

git-clean-check:
ifneq ($(git_dirty),)
	git diff
	@echo "Git repository is dirty!"
	@false
else
	@echo "Git repository is clean."
endif


#############################################################################
# Code cleanliness
#############################################################################

.PHONY: tidy tidy-check lint lint-code
tidy: | go-check
	$(E)$(go) mod tidy

tidy-check:
ifneq ($(git_dirty),)
	$(error tidy-check must be invoked on a clean repository)
endif
	@echo "Running go tidy..."
	$(E)$(MAKE) tidy
	@echo "Ensuring git repository is clean..."
	$(E)$(MAKE) git-clean-check

lint: lint-code

lint-code: $(golangci_lint_bin) | go-check
	$(E)PATH="$(PATH):$(go_bin_dir)" $(golangci_lint_bin) run ./...

############################################################################
# Build targets
############################################################################

.PHONY: build test clean distclean artifact

build: | go-check
	go build -o spiffe-helper ./cmd/spiffe-helper

artifact: build
	@OUTDIR="$(OUTDIR)" TAG="$(TAG)" ./script/build-artifact.sh

test: | go-check
	go test ./...

clean: | go-check
	go clean ./cmd/spiffe-helper
