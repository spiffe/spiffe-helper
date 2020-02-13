#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
ALWAYS="$(git describe --tags --always || true)"

# Get build number from travis env variable or use "0"
BUILD="${TRAVIS_BUILD_NUMBER:-0}"

if [ "$TAG" == "$ALWAYS" ]; then
    make -C "${DIR}/.." TAG="${TAG}" OUTDIR=./releases tarball
    make -C "${DIR}/.." TAG="${TAG}" OUTDIR=./releases BUILD="${BUILD}" rpm
fi
