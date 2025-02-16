#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

docker run --detach --name spiffe-helper-it \
  --volume "${PWD}/conf/server":/opt/spire/conf/server \
  --volume "${PWD}/conf/agent":/opt/spire/conf/agent \
  --volume "${PWD}/conf/spiffe-helper":/opt/spiffe-helper/conf \
  --volume "${PWD}/bin":/opt/init
   spiffe-helper-it:latest
