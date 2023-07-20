#!/bin/bash

fingerprint () {
	# calculate the SHA1 digest of the DER bytes of the certificate using the
	# "coreutils" output format (`-r`) to provide uniform output from
	# `openssl sha1` on macOS and linux.
	openssl x509 -in "$1" -outform DER | openssl sha1 -r | awk '{print $1}'
}

wait () {
	max_attempts=40

	for ((attempt = 1; attempt <= max_attempts; attempt++)); do
		if docker compose exec "$1" test -s "$2"; then
			break
		else
			sleep 1
		fi
	done
}

# set ups spire server and create postgres, mysql and go entries 
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
	-ttl 100

docker compose exec spire-server ./bin/spire-server entry create \
    -parentID "spiffe://example.org/spire/agent/x509pop/${FINGERPRINT}" \
    -spiffeID spiffe://example.org/go-server \
    -selector unix:uid:73 \
	-dns go-server \
	-ttl 3600

# set ups spire agent
docker compose up spire-agent -d

docker compose build spiffe-helper

# set ups and postgres-db
docker compose up postgres-db -d
wait postgres-db /run/postgresql/certs/svid.crt
docker compose exec postgres-db su postgres -c "pg_ctl start -D /var/lib/postgresql/data"
docker compose exec postgres-db su postgres -c "psql -U postgres -f /var/lib/postgresql/data/init.sql"

# set ups and mysql-db
docker compose up mysql-db -d
docker compose exec mysql-db /etc/init.d/mysql start
docker compose exec mysql-db su root -c "mysql < /var/lib/mysql/data/init.sql"

# set ups go-server
docker compose up go-server -d
wait go-server /run/go-server/certs/svid.crt
docker compose exec go-server su go-server -c "/opt/go-server/server &"

#set ups client
docker compose up client -d
wait client /run/client/certs/svid.crt
