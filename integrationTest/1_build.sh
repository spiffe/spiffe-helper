#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

goVersion=$(grep '^go ' ../go.mod | awk '{print $2}')
spireVersion=$(cat spire.version)

cd ..
docker build --build-arg go_version="${goVersion}" -t spiffe-helper:local .
cd integrationTest
docker build --build-arg spire_version="${spireVersion}" -t spiffe-helper-it:latest .
