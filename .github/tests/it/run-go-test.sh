#!/usr/bin/env bash

set -euo pipefail

compose() {
	docker compose "$@"
}

assert_exit_code() {
	parameter=$1
	expected=$2

	if compose exec -T client /opt/go-client/client "$parameter"; then
		actual=0
	else
		actual=$?
	fi

	if ((actual != expected)); then
		echo "Go client parameter ${parameter}: expected exit ${expected}, got ${actual}" >&2
		return 1
	fi

	echo "Go client parameter ${parameter}: received expected exit ${expected}"
}

if (($# == 2)); then
	assert_exit_code "$1" "$2"
	exit
fi

assert_exit_code 0 0
assert_exit_code 1 1
