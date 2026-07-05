#!/bin/bash

set -euo pipefail

readonly MAX_ATTEMPTS=120

compose() {
	docker compose "$@"
}

wait_for_dns_name() {
	dns_name=$1

	for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)); do
		if compose exec -T client openssl x509 \
			-in /run/client/certs/svid.crt \
			-noout \
			-ext subjectAltName 2>/dev/null |
			grep -q "DNS:${dns_name}"; then
			return 0
		fi
		sleep 1
	done

	echo "Timed out waiting for client SVID DNS name ${dns_name}" >&2
	return 1
}

mode=${1:-}
case "$mode" in
bad)
	dns_name=testuser1
	;;
restore)
	dns_name=client
	;;
*)
	echo "Usage: $0 <bad|restore>" >&2
	exit 2
	;;
esac

entry="$(compose exec -T spire-server ./bin/spire-server entry show \
	-spiffeID spiffe://example.org/client)"
entry_id="$(awk '/Entry ID/{print $4; exit}' <<<"$entry")"
parent_id="$(awk '/Parent ID/{print $4; exit}' <<<"$entry")"

compose exec -T spire-server ./bin/spire-server entry update \
	-entryID "$entry_id" \
	-parentID "$parent_id" \
	-spiffeID spiffe://example.org/client \
	-selector unix:uid:72 \
	-ttl 100 \
	-dns "$dns_name" >/dev/null

wait_for_dns_name "$dns_name"
echo "Client entry now issues SVIDs with DNS name ${dns_name}"
