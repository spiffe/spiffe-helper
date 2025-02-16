ARG spire_version
FROM ghcr.io/spiffe/spire-server:${spire_version} AS spire-server
FROM ghcr.io/spiffe/spire-agent:${spire_version} AS spire-agent

FROM ubuntu:latest
USER root
RUN set -o errexit -o nounset \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        curl \
        jq \
    && rm --recursive --force /var/lib/apt/lists/*

ENTRYPOINT ["/opt/init/init.sh"]

COPY --from=spire-server /opt/spire/bin/spire-server /opt/spire/bin/spire-server

COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent

COPY --from=spiffe-helper:local /spiffe-helper /opt/spiffe-helper/bin/spiffe-helper
