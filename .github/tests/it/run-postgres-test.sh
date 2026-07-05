#!/usr/bin/env bash

set -euo pipefail

compose() {
	docker compose "$@"
}

assert_query() {
	user=$1
	expected=$2

	if output="$(compose exec -T client su client -c \
		"/run/client/postgres-connect.sh \"${user}\"")"; then
		actual=0
	else
		actual=$?
	fi

	if [[ "$output" != *test@user.com* ]]; then
		actual=1
	fi

	if ((actual != expected)); then
		echo "PostgreSQL user ${user}: expected exit ${expected}, got ${actual}" >&2
		return 1
	fi

	echo "PostgreSQL user ${user}: received expected exit ${expected}"
}

if (($# == 2)); then
	assert_query "$1" "$2"
	exit
fi

assert_query client 0
assert_query fail 1
