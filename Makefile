export GO111MODULE=on

# Help message settings
cyan := $(shell which tput > /dev/null && tput setaf 6 || echo "")
reset := $(shell which tput > /dev/null && tput sgr0 || echo "")
bold  := $(shell which tput > /dev/null && tput bold || echo "")
target_max_char=25

# RPM builder constants
rpm_container_name = centos_rpm_builder
rpm_image_name = centos_rpm_builder_img

# Use the git tag as version
version_number := $(shell git tag --points-at HEAD)

# If it is not a tagged build, use the git commit
ifneq ($(gittag),)
	version_number := $(shell git rev-list -1 HEAD)
endif

# don't provide the git tag or commit if the git status is dirty.
gitdirty := $(shell git status -s)
ifneq ($(gitdirty),)
	version_number :=unknown
endif

# Get build number from travis env variable
build_number := $(TRAVIS_BUILD_NUMBER)
ifeq ($(build_number),)
	build_number :=unknown
endif

.PHONY: all build test clean distclean help rpm rpm-container-create rpm-build rpm-container-clean

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

distclean: ## Removes installed binary, vendored dependencies and dist
	go clean -i
	rm -rf vendor dist

release: ## Downloads and run goreleaser
	curl -sL https://git.io/goreleaser | bash || true

##@ RPM

rpm: rpm-container-create rpm-build rpm-container-clean ## Builds a RPM package for spiffe-helper in the 'rpm/' directory

rpm-container-create: ## Creates a container image for building spiffe-helper RPM package
	docker build --tag $(rpm_image_name) rpm/

rpm-build: ## Builds spiffe-helper RPM using the rpm-container
	# Start container
	docker run -t -d --name $(rpm_container_name) $(rpm_image_name)

	# Create RPM build structure
	docker exec $(rpm_container_name) sh -c "mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}"

	# Copy sources into container
	docker cp . $(rpm_container_name):/root/spiffe-helper

	# Copy RPM spec to RPM build structure
	docker exec $(rpm_container_name) sh -c "cp -p /root/spiffe-helper/rpm/spiffe-helper.spec /root/rpmbuild/SPECS/."

	# Create tarball of spiffe-helper and copy to RPM build structure
	docker exec $(rpm_container_name) sh -c "tar -zcvf ~/rpmbuild/SOURCES/spiffe-helper.tar.gz -C /root spiffe-helper"

	# Build RPM package (version: build version of the RPM, build_number: build / patch level number of RPM)
	docker exec $(rpm_container_name) sh -c "rpmbuild --define='version $(version_number)' --define='build_number $(build_number)' -bb ~/rpmbuild/SPECS/spiffe-helper.spec"

	# Copy the RPM out of the container
	docker cp $(rpm_container_name):/root/rpmbuild/RPMS/x86_64/spiffe-helper-$(version_number)-$(build_number).el7.x86_64.rpm rpm/

rpm-container-clean: ## Stop and removes the container used for building the RPM package
	docker container stop $(rpm_container_name)
	docker container rm $(rpm_container_name)

##@ Help

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\n$(bold)Usage:$(reset) make $(cyan)<target>$(reset)\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(cyan)%-$(target_max_char)s$(reset) %s\n", $$1, $$2 } /^##@/ { printf "\n $(bold)%s$(reset) \n", substr($$0, 5) } ' $(MAKEFILE_LIST)