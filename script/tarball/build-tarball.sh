#!/bin/bash

set -e

REPODIR=$(git rev-parse --show-toplevel)

TAG=${TAG:-$(git log -n1 --pretty=%h)}
OUTDIR=${OUTDIR:-"${REPODIR}/artifacts"}

OS=$(uname -s)
ARCH=$(uname -m)

TARBALL="${OUTDIR}/spiffe-helper-${TAG}-${OS}-${ARCH}.tar.gz"
CHECKSUM="${OUTDIR}/spiffe-helper-${TAG}-${OS}-${ARCH}_checksums.txt"

STAGING=$(mktemp -d)
cleanup() {
    rm -rf "${STAGING}"
}
trap cleanup EXIT

echo "Creating \"${TARBALL}\""

# Copy in the LICENSE
cp "${REPODIR}"/LICENSE "${STAGING}"

# Copy in the README.md
cp "${REPODIR}"/README.md "${STAGING}"

# Copy in the SPIFFE Helper binary
cp "${REPODIR}"/spiffe-helper "${STAGING}"

# Create the tarball and checksum
mkdir -p "${OUTDIR}"
tar -cvzf "${TARBALL}" --directory "${STAGING}" .
echo "$(shasum -a 256 "${TARBALL}" | cut -d' ' -f1) $(basename "${TARBALL}")" > "$CHECKSUM"
