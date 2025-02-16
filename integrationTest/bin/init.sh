#!/usr/bin/env bash

echo "Starting SPIRE server ..."
/opt/spire/bin/spire-server run -config /opt/spire/conf/server/server.conf &
while ! /opt/spire/bin/spire-server healthcheck --verbose; do
    sleep 3
done

echo "Starting SPIRE agent ..."
/opt/spire/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf &
while ! /opt/spire/bin/spire-agent healthcheck --verbose; do
    sleep 3
done

echo "Creating workload entry ..."
/opt/spire/bin/spire-server entry create \
    -selector unix:uid:0 \
    -selector unix:user:root \
    -selector unix:gid:0 \
    -selector unix:group:root \
    -selector unix:supplementary_gid:0 \
    -selector unix:supplementary_group:root \
    -selector unix:path:/opt/spiffe-helper/bin/spiffe-helper \
    -spiffeID spiffe://example.org/workload/spiffe-helper \
    -parentID spiffe://example.org/spire/agent/x509pop/02b8e7713492fdf93d43369e9c6f50d28bef9fa8

sleep 3

echo "Starting SPIFFE Helper ..."
/opt/spiffe-helper/bin/spiffe-helper -config /opt/spiffe-helper/conf/helper.conf &

wait -n
exit $?
