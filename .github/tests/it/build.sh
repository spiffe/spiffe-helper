#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MAX_ATTEMPTS=60

cd "$SCRIPT_DIR"

compose() {
	docker compose "$@"
}

wait_for_command() {
	description=$1
	shift

	for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)); do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done

	echo "Timed out waiting for ${description}" >&2
	return 1
}

fingerprint() {
	openssl x509 -in "$1" -outform DER |
		openssl sha1 -r |
		awk '{print $1}'
}

ensure_entry() {
	spiffe_id=$1
	uid=$2
	ttl=$3
	dns_name=${4:-}

	entry="$(compose exec -T spire-server ./bin/spire-server entry show -spiffeID "$spiffe_id")"
	entry_id="$(awk '/Entry ID/{print $4; exit}' <<<"$entry")"
	parent_id="spiffe://example.org/spire/agent/x509pop/${agent_fingerprint}"

	args=(
		-parentID "$parent_id"
		-spiffeID "$spiffe_id"
		-selector "unix:uid:${uid}"
		-ttl "$ttl"
	)
	if [[ -n "$dns_name" ]]; then
		args+=(-dns "$dns_name")
	fi

	if [[ -n "$entry_id" ]]; then
		compose exec -T spire-server ./bin/spire-server entry update \
			-entryID "$entry_id" "${args[@]}" >/dev/null
	else
		compose exec -T spire-server ./bin/spire-server entry create \
			"${args[@]}" >/dev/null
	fi
}

ensure_postgres() {
	compose up -d postgres-db
	wait_for_command "PostgreSQL SVID" \
		compose exec -T postgres-db test -s /run/postgresql/certs/svid.crt

	if ! compose exec -T postgres-db su postgres -c "pg_isready -q"; then
		compose exec -T postgres-db su postgres -c \
			"pg_ctl start -D /var/lib/postgresql/data"
	fi
	wait_for_command "PostgreSQL" \
		compose exec -T postgres-db su postgres -c "pg_isready -q"

	if ! compose exec -T postgres-db su postgres -c \
		"psql -U postgres -tAc \"SELECT 1 FROM pg_database WHERE datname='test_db'\"" |
		grep -q 1; then
		compose exec -T postgres-db su postgres -c \
			"psql -U postgres -f /var/lib/postgresql/data/init.sql"
	fi
}

ensure_mysql() {
	compose up -d mysql-db
	wait_for_command "MySQL SVID" \
		compose exec -T mysql-db test -s /var/lib/mysql/server-cert.pem

	if ! compose exec -T mysql-db mysqladmin ping --silent; then
		compose exec -T mysql-db /etc/init.d/mysql start
	fi
	wait_for_command "MySQL" \
		compose exec -T mysql-db mysqladmin ping --silent

	if ! compose exec -T mysql-db mysql -NBe "SHOW DATABASES LIKE 'test_db'" |
		grep -q test_db; then
		compose exec -T mysql-db mysql \
			-e "source /var/lib/mysql/data/init.sql"
	fi
}

ensure_go_server() {
	compose up -d go-server
	wait_for_command "Go server SVID" \
		compose exec -T go-server test -s /run/go-server/certs/svid.crt

	if ! compose exec -T go-server pgrep -f /opt/go-server/server >/dev/null; then
		compose exec -T -d go-server su go-server -c /opt/go-server/server
	fi
}

if (($# == 0)); then
	echo "Usage: $0 <go|postgres|mysql|entry> [...]" >&2
	exit 2
fi

need_go=false
need_postgres=false
need_mysql=false

for suite in "$@"; do
	case "$suite" in
	go)
		need_go=true
		;;
	postgres)
		need_postgres=true
		;;
	mysql)
		need_mysql=true
		;;
	entry)
		need_postgres=true
		need_mysql=true
		;;
	*)
		echo "Unknown integration suite: ${suite}" >&2
		exit 2
		;;
	esac
done

compose up -d spire-server
wait_for_command "SPIRE server" \
	compose exec -T spire-server ./bin/spire-server healthcheck

compose exec -T spire-server ./bin/spire-server bundle show \
	>spire/agent/bootstrap.crt
agent_fingerprint="$(fingerprint spire/agent/agent.crt.pem)"

ensure_entry spiffe://example.org/client 72 100 client
if [[ "$need_go" == true ]]; then
	ensure_entry spiffe://example.org/go-server 73 3600 go-server
fi
if [[ "$need_postgres" == true ]]; then
	ensure_entry spiffe://example.org/postgres-db 70 60
fi
if [[ "$need_mysql" == true ]]; then
	ensure_entry spiffe://example.org/mysql-db 0 60
fi

compose up -d spire-agent
wait_for_command "SPIRE agent" \
	compose exec -T spire-agent ./bin/spire-agent healthcheck \
	-socketPath /run/spire/api.sock

go_version="$(sed -En 's/^go[ ]+([0-9.]+).*/\1/p' ../../../go.mod)"
compose build --build-arg "go_version=${go_version}" spiffe-helper

services=(client)
if [[ "$need_go" == true ]]; then
	services+=(go-server)
fi
if [[ "$need_postgres" == true ]]; then
	services+=(postgres-db)
fi
if [[ "$need_mysql" == true ]]; then
	services+=(mysql-db)
fi
compose build --build-arg "go_version=${go_version}" "${services[@]}"

if [[ "$need_postgres" == true ]]; then
	ensure_postgres
fi
if [[ "$need_mysql" == true ]]; then
	ensure_mysql
fi
if [[ "$need_go" == true ]]; then
	ensure_go_server
fi

compose up -d client
wait_for_command "client SVID" \
	compose exec -T client test -s /run/client/certs/svid.crt
