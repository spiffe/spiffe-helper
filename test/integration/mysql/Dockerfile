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

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends mysql-server openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=helper-builder /spiffe-helper /opt/helper/spiffe-helper
COPY test/integration/mysql/conf/helper.conf /opt/spire/conf/mysql/helper.conf
COPY test/integration/mysql/conf/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf

RUN mkdir -p /run/mysqld /var/lib/mysql/certs \
    && openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /var/lib/mysql/certs/server-key.pem \
        -out /var/lib/mysql/certs/server-cert.pem \
        -subj /CN=mysql-db \
        -days 1 \
    && cp /var/lib/mysql/certs/server-cert.pem /var/lib/mysql/certs/ca.pem \
    && chown -R mysql:mysql /run/mysqld /var/lib/mysql \
    && chmod 0644 /var/lib/mysql/certs/server-cert.pem /var/lib/mysql/certs/ca.pem \
    && chmod 0644 /var/lib/mysql/certs/server-key.pem
