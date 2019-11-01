#!/usr/bin/env bash

# Create a directory to store the certificate, key and bundle
declare -r SVIDS_DIR=examples/mysql/svids
mkdir -p $SVIDS_DIR

# Fetch the credentials from SPIRE agent
/opt/spire/spire-agent api fetch -write ${SVIDS_DIR}

# Connecto to mysql using the certificates fetched
mysql -u mysql-user --protocol tcp --ssl-key $SVIDS_DIR/svid.0.key --ssl-cert $SVIDS_DIR/svid.0.pem --ssl-ca $SVIDS_DIR/bundle.0.pem
