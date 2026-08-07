# Build the spiffe-helper binary
ARG go_version
FROM --platform=$BUILDPLATFORM golang:${go_version}-alpine AS base
WORKDIR /workspace

# Cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Copy the go source
COPY cmd/spiffe-helper/ cmd/spiffe-helper/
COPY pkg/ pkg/

# xx is a helper for cross-compilation
# when bumping to a new version analyze the new version for security issues
# then use crane to lookup the digest of that version so we are immutable
# crane digest tonistiigi/xx:1.3.0
FROM --platform=${BUILDPLATFORM} tonistiigi/xx@sha256:c64defb9ed5a91eacb37f96ccc3d4cd72521c4bd18d5442905b95e2226b0e707 AS xx

FROM --platform=${BUILDPLATFORM} base AS builder
ARG TARGETPLATFORM
ARG TARGETARCH

ENV CGO_ENABLED=0
COPY --link --from=xx / /
RUN xx-go --wrap
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -o bin/spiffe-helper cmd/spiffe-helper/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
#FROM gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static AS spiffe-helper
WORKDIR /
COPY --link --from=builder /workspace/bin/spiffe-helper /spiffe-helper

ENTRYPOINT ["/spiffe-helper"]
CMD []
