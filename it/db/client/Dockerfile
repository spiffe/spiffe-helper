FROM golang:1.17-alpine AS helper-builder
RUN apk add build-base git
WORKDIR /service
RUN git clone -b upgrade-helper https://github.com/marcosdy/spiffe-helper.git .
RUN go build -tags netgo -a -v -o /service/spiffe-helper ./cmd/spiffe-helper

FROM ubuntu:22.04 AS client
RUN addgroup -gid 72 client
RUN useradd -u 72 -g client client

ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install postgresql mysql-client -y

RUN mkdir -p /run/client/certs
COPY ./postgres-connect.sh /run/client/postgres-connect.sh
COPY ./mysql-connect.sh /run/client/mysql-connect.sh
RUN touch /run/client/certs/svid.crt /run/client/certs/svid.key /run/client/certs/root.crt
RUN chmod +x /run/client/postgres-connect.sh /run/client/mysql-connect.sh 
RUN chmod 600 /run/client/certs/svid.crt /run/client/certs/svid.key /run/client/certs/root.crt
RUN chown client:client \
    /run/client/postgres-connect.sh \
    /run/client/mysql-connect.sh \
    /run/client/certs/svid.crt \
    /run/client/certs/svid.key \
    /run/client/certs/root.crt

USER root
COPY --from=helper-builder /service/spiffe-helper /opt/helper/spiffe-helper
