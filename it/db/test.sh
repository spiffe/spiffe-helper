#!/bin/bash

fingerprint () {
	# calculate the SHA1 digest of the DER bytes of the certificate using the
	# "coreutils" output format (`-r`) to provide uniform output from
	# `openssl sha1` on macOS and linux.
	openssl x509 -in "$1" -outform DER | openssl sha1 -r | awk '{print $1}'
}

wait () {
	max_attempts=30

	for ((attempt = 1; attempt <= max_attempts; attempt++)); do
		if docker compose exec "$1" test -s "$2"; then
			break
		fi
	done
}

docker compose up spire-server -d

docker compose exec -it spire-server ./bin/spire-server bundle show > ./spire/agent/bootstrap.crt

FINGERPRINT="$(fingerprint ./spire/agent/agent.crt.pem)"

docker compose exec spire-server ./bin/spire-server entry create \
    -parentID "spiffe://example.org/spire/agent/x509pop/${FINGERPRINT}" \
    -spiffeID spiffe://example.org/postgres-db \
    -selector unix:uid:70 \
	-ttl 60

docker compose exec spire-server ./bin/spire-server entry create \
	-parentID "spiffe://example.org/spire/agent/x509pop/${FINGERPRINT}" \
    -spiffeID spiffe://example.org/mysql-db \
    -selector unix:uid:0 \
    -ttl 60

docker compose exec spire-server ./bin/spire-server entry create \
    -parentID "spiffe://example.org/spire/agent/x509pop/${FINGERPRINT}" \
    -spiffeID spiffe://example.org/client \
    -selector unix:uid:72 \
	-dns client \
	-ttl 60
    
docker compose up spire-agent -d

docker compose build spiffe-helper

docker compose up postgres-db -d
wait postgres-db /run/postgresql/certs/svid.crt
docker compose exec postgres-db su postgres -c "pg_ctl start -D /var/lib/postgresql/data"
docker compose exec postgres-db su postgres -c "psql -U postgres -f /var/lib/postgresql/data/init.sql"

docker compose up mysql-db -d
docker compose exec mysql-db /etc/init.d/mysql start
docker compose exec mysql-db su root -c "mysql < /var/lib/mysql/data/init.sql"

docker compose up client -d
wait client /run/client/certs/svid.crt

bash run-postgres-test.sh
ec_postgres_test=$?

bash run-postgres-test.sh fail
ec_postgres_test_fail=$?

bash run-mysql-test.sh
ec_mysql_test=$?

bash run-mysql-test.sh fail
ec_mysql_test_fail=$?

bash change-entry-client-test.sh 1
ec_change_entry_postgres=$?
bash change-entry-client-test.sh
ec_restore_entry_postgres=$?


#All of these values should be 0
echo "Exit value of Postgres test script: $ec_postgres_test"
echo "Exit value of Postgres test fail script: $ec_postgres_test_fail"

echo "Exit value of MySQL test script: $ec_mysql_test"
echo "Exit value of MySQL test fail script: $ec_mysql_test_fail"

echo "Exit value change entry Postgres: $ec_change_entry_postgres"
echo "Exit value restore entry Postgres: $ec_restore_entry_postgres"
