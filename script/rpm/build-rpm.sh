#!/bin/bash

set -e

# Version related variables
TAG="${TAG:-$(git log -n1 --pretty=%h)}"
BUILD="${BUILD:-0}"

# Path related variables
REPODIR=$(git rev-parse --show-toplevel)
OUTDIR=${OUTDIR:-"${REPODIR}/artifacts"}
RPM_NAME="spiffe-helper-${TAG}-${BUILD}.el7.x86_64.rpm"
RPM_FULLPATH="${OUTDIR}/$RPM_NAME"
CHECKSUM_FULLPATH="${OUTDIR}/spiffe-helper-${TAG}-${BUILD}.el7.x86_64_checksums.txt"

# Container related variables
CONTAINER="centos_rpm_builder"
IMAGE="centos_rpm_builder_img"

echo "Creating \"${RPM_FULLPATH}\""

# Build image
docker build -t "${IMAGE}" "${REPODIR}/script/rpm/"

# Start container
docker run -t -d --name "${CONTAINER}" "${IMAGE}"

# Create RPM build structure
docker exec "${CONTAINER}" sh -c "mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}"

# Copy sources into container
docker cp . "${CONTAINER}":/root/spiffe-helper

# Copy RPM spec to RPM build structure
docker exec "${CONTAINER}" sh -c "cp -p /root/spiffe-helper/script/rpm/spiffe-helper.spec /root/rpmbuild/SPECS/."

# Create tarball of spiffe-helper and copy to RPM build structure
docker exec "${CONTAINER}" sh -c "tar -zcvf ~/rpmbuild/SOURCES/spiffe-helper.tar.gz -C /root spiffe-helper"

# Build RPM package (version: build version of the RPM, build_number: build / patch level number of RPM)
docker exec "${CONTAINER}" sh -c "rpmbuild --define='version ${TAG}' --define='build_number ${BUILD}' -bb ~/rpmbuild/SPECS/spiffe-helper.spec"

# Create artifacts folder
mkdir -p "${OUTDIR}"

# Copy the RPM out of the container
docker cp "${CONTAINER}:/root/rpmbuild/RPMS/x86_64/${RPM_NAME}" "${RPM_FULLPATH}"

# Stop and remove the container
docker container stop "${CONTAINER}"
docker container rm "${CONTAINER}"

# Calculate and create checksum
echo "$(shasum -a 256 "${RPM_FULLPATH}" | cut -d' ' -f1) $(basename "${RPM_FULLPATH}")" > "${CHECKSUM_FULLPATH}"
