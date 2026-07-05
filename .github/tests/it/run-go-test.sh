#!/bin/bash

set -euo pipefail

compose() {
	docker compose "$@"
}

assert_authenticated_request() {
	if ! output="$(compose exec -T client \
		/opt/go-client/client with-client-svid)"; then
		echo "Authenticated Go client request failed" >&2
		return 1
	fi

	if [[ "$output" != *test@user.com* ]]; then
		echo "Authenticated Go client returned an unexpected response: ${output}" >&2
		return 1
	fi

	echo "Authenticated Go client request succeeded"
}

assert_missing_client_svid_rejected() {
	if output="$(compose exec -T client \
		/opt/go-client/client without-client-svid 2>&1)"; then
		echo "Go server accepted a request without a client SVID: ${output}" >&2
		return 1
	fi

	if [[ "$output" == *"unknown authority"* ]]; then
		echo "Unauthenticated request failed because the server was not trusted, not because the client SVID was missing" >&2
		return 1
	fi

	echo "Go server rejected a request without a client SVID"
}

assert_authenticated_request
assert_missing_client_svid_rejected
