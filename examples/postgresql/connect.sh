#!/usr/bin/env bash

# Directory to store the certificate, key and bundle fetched from the Workload API
declare -r SVIDS_DIR=examples/postgresql/svids

# Fetch SVIDs from SPIRE agent
/opt/spire/spire-agent api fetch -write ${SVIDS_DIR}

# Change key permissions (required by psql)
chmod 600 $SVIDS_DIR/svid.0.key

# Connecto to postgres using the certificates fetched
psql "port=5432 host=localhost user=postgres-user dbname=testdb sslcert=$SVIDS_DIR/svid.0.pem sslkey=$SVIDS_DIR/svid.0.key sslrootcert=$SVIDS_DIR/bundle.0.pem sslmode=verify-ca"

