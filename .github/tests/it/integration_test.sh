#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"
export COMPOSE_PROJECT_NAME=spiffe-helper-integration

compose() {
	docker compose "$@"
}

cleanup() {
	status=$?
	trap - EXIT INT TERM

	if ((status != 0)); then
		compose ps --all || true
		compose logs --no-color || true
	fi

	compose down --volumes --remove-orphans || true
	rm -f spire/agent/bootstrap.crt
	exit "$status"
}

run_test() {
	name=$1
	shift

	echo "==> ${name}"
	if "$@"; then
		echo "PASS: ${name}"
	else
		echo "FAIL: ${name}" >&2
		failures=$((failures + 1))
	fi
}

if (($# == 0)); then
	set -- go postgres mysql entry
fi

suites=()
for suite in "$@"; do
	case "$suite" in
	go | postgres | mysql | entry)
		if [[ " ${suites[*]} " != *" ${suite} "* ]]; then
			suites+=("$suite")
		fi
		;;
	*)
		echo "Unknown integration suite: ${suite}" >&2
		exit 2
		;;
	esac
done

trap cleanup EXIT INT TERM

command -v docker >/dev/null
command -v openssl >/dev/null
docker info >/dev/null
compose version >/dev/null

compose down --volumes --remove-orphans
bash build.sh "${suites[@]}"

failures=0
for suite in "${suites[@]}"; do
	case "$suite" in
	go)
		run_test "Go mTLS" bash run-go-test.sh
		;;
	postgres)
		run_test "PostgreSQL mTLS" bash run-postgres-test.sh
		;;
	mysql)
		run_test "MySQL mTLS" bash run-mysql-test.sh
		;;
	entry)
		run_test "Invalidate client entry" bash change-entry-client-test.sh bad
		run_test "PostgreSQL rejects invalid client entry" \
			bash run-postgres-test.sh client 1
		run_test "MySQL rejects invalid client entry" \
			bash run-mysql-test.sh client 1
		run_test "Restore client entry" bash change-entry-client-test.sh restore
		run_test "PostgreSQL accepts restored client entry" \
			bash run-postgres-test.sh client 0
		run_test "MySQL accepts restored client entry" \
			bash run-mysql-test.sh client 0
		;;
	esac
done

if ((failures > 0)); then
	echo "${failures} integration test(s) failed" >&2
	exit 1
fi

echo "All requested integration tests passed: ${suites[*]}"
