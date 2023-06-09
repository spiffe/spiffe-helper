#!/bin/bash

query () {
    # Directory to store the certificate, key and bundle fetched from the Workload API
    SVIDS_DIR=/run/client/certs

    # Connect to postgres using the certificates fetched
    psql "port=5432 host=postgres-db user=client dbname=test_db sslcert=$SVIDS_DIR/svid.crt sslkey=$SVIDS_DIR/svid.key sslrootcert=$SVIDS_DIR/root.crt sslmode=verify-ca" -c "SELECT * FROM mail;"
}

exit $(query | grep -q "test@user.com" && echo 0 || echo 1)
