ARG go_version
FROM --platform=$BUILDPLATFORM golang:${go_version}-alpine AS helper-builder
WORKDIR /workspace

COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd/spiffe-helper/ cmd/spiffe-helper/
COPY pkg/ pkg/
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -o /spiffe-helper ./cmd/spiffe-helper

FROM alpine:3.22

ARG postgres_uid
RUN addgroup -g "${postgres_uid}" postgres \
    && adduser -G postgres -u "${postgres_uid}" -D postgres \
    && apk add --no-cache openssl postgresql16 postgresql16-client

COPY --from=helper-builder /spiffe-helper /opt/helper/spiffe-helper
COPY test/integration/postgres/conf/helper.conf /opt/spire/conf/postgres/helper.conf

RUN mkdir -p /run/postgresql/certs /var/lib/postgresql/data \
    && chown -R postgres:postgres /run/postgresql /var/lib/postgresql \
    && chmod 700 /var/lib/postgresql/data \
    && su postgres -c "/usr/libexec/postgresql16/initdb -D /var/lib/postgresql/data"

COPY --chown=postgres:postgres test/integration/postgres/conf/postgresql.conf /var/lib/postgresql/data/postgresql.conf
COPY --chown=postgres:postgres test/integration/postgres/conf/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf

USER postgres
