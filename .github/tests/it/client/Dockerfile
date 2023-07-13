FROM golang:1.17-alpine AS builder
COPY ./client.go /service/client.go
WORKDIR /service
RUN go build -tags netgo -a -v -o /service/client ./client.go

FROM ubuntu:22.04 AS mysql
RUN addgroup -gid 72 client
RUN useradd -u 72 -g client client

ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install postgresql mysql-client -y

RUN mkdir -p /run/client/certs
COPY ./postgres-connect.sh /run/client/postgres-connect.sh
COPY ./mysql-connect.sh /run/client/mysql-connect.sh
COPY ./assert.sh /run/client/assert.sh

RUN touch /run/client/certs/svid.crt /run/client/certs/svid.key /run/client/certs/root.crt
RUN chmod +x /run/client/postgres-connect.sh /run/client/mysql-connect.sh /run/client/assert.sh
RUN chmod 600 /run/client/certs/svid.crt /run/client/certs/svid.key /run/client/certs/root.crt
RUN chown client:client \
    /run/client/postgres-connect.sh \
    /run/client/mysql-connect.sh \
    /run/client/assert.sh \
    /run/client/certs/svid.crt \
    /run/client/certs/svid.key \
    /run/client/certs/root.crt

USER root
COPY --from=it-spiffe-helper /service/spiffe-helper /opt/helper/spiffe-helper
COPY --from=builder /service/client /opt/go-client/client
