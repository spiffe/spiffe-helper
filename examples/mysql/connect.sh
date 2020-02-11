#!/usr/bin/env bash

# Directory to store the certificate, key and bundle fetched from the Workload API
declare -r SVIDS_DIR=examples/mysql/svids

# Fetch the credentials from SPIRE agent and write it into $SVIDS_DIR
/opt/spire/spire-agent api fetch -write ${SVIDS_DIR}

# Connecto to mysql using the certificates fetched
mysql -u mysql-user --protocol tcp --ssl-key $SVIDS_DIR/svid.0.key --ssl-cert $SVIDS_DIR/svid.0.pem --ssl-ca $SVIDS_DIR/bundle.0.pem
