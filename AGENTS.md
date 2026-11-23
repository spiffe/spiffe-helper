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

The release workflow runs after changes merge to `main`. The merged PR's
`semver:major`, `semver:minor`, or `semver:patch` label determines the next
version. If no SemVer label is present, the workflow defaults to a patch
release. Multiple SemVer labels are rejected.

The workflow uses `faisal-memon/pr-label-semver@v0.2.2` to calculate the tag,
then runs the integration tests, builds the Linux artifacts and container, and
creates the GitHub Release. The action calculates the tag; the release step
creates it after the artifacts are ready.

Release jobs use workflow concurrency so two merges cannot calculate and
publish the same version at the same time. Manual releases can be started with
`workflow_dispatch` and an explicit version bump.

## Contribution Guidance

- Keep changes focused and preserve the existing configuration behavior unless
  a change is explicitly intended.
- Add or update tests with behavior changes.
- Use signed commits when pushing changes to this repository.
- Do not force-push shared branches unless the repository owner explicitly asks
  for it.
