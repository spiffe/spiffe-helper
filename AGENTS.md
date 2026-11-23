# AGENTS.md

## Project Overview

SPIFFE Helper is a Go command-line application that retrieves and writes SPIFFE
X.509 and JWT-SVIDs. Configuration can come from HCL, YAML, JSON, and
environment variables.

## Development Checks

- Run `go test ./...` for unit tests.
- Run `make lint-code` for Go linting.
- Run `make integration-test` for Docker-based integration tests.
- Run `make integration-test-verbose` when Docker logs are needed.

The integration tests require a working Docker daemon. They are separate from
the regular unit-test target because they start Compose services and SPIRE.

## Release Process

Releases currently use a `release/<version>` branch created from the latest
`main`, followed by a matching `v<version>` tag on the same commit. The tag
starts the release workflow, which runs integration tests, builds the Linux
artifacts and container, and creates the GitHub Release.

## Contribution Guidance

- Keep changes focused and preserve the existing configuration behavior unless
  a change is explicitly intended.
- Add or update tests with behavior changes.
- Use signed commits when pushing changes to this repository.
- Do not force-push shared branches unless the repository owner explicitly asks
  for it.
