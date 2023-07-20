#!/usr/bin/env bash

# Directory to store the certificate, key and bundle fetched from the Workload API
declare -r SVIDS_DIR=/tmp/mosquitto/svids

# Fetch SVIDs from SPIRE agent
/opt/spire/spire-agent api fetch -write ${SVIDS_DIR}

# Connect to mosquitto broker using the certificates fetched
mosquitto_pub --cafile $SVIDS_DIR/bundle.0.pem \
              --cert $SVIDS_DIR/svid.0.pem \
              --key $SVIDS_DIR/svid.0.key \
              --tls-version tlsv1.3 \
              --host node1 \
              --port 8883 \
              --username jdoe \
              --id jdoe \
              -t test/hello \
              --stdin-line \
              -d
