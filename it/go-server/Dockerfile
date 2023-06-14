FROM golang:1.17-alpine AS builder
COPY ./server.go /service/server.go
WORKDIR /service
RUN go build -tags netgo -a -v -o /service/server ./server.go

FROM ubuntu:22.04 AS go-server
RUN addgroup -gid 73 go-server
RUN useradd -u 73 -g go-server go-server

RUN mkdir -p /run/go-server/certs/
RUN touch /run/go-server/certs/svid.crt /run/go-server/certs/svid.key /run/go-server/certs/root.crt
RUN chmod 600 /run/go-server/certs/svid.crt /run/go-server/certs/svid.key /run/go-server/certs/root.crt
RUN chown go-server:go-server \ 
    /run/go-server/certs/svid.crt \
    /run/go-server/certs/svid.key \
    /run/go-server/certs/root.crt

USER root
COPY --from=it-spiffe-helper /service/spiffe-helper /opt/helper/spiffe-helper
COPY --from=builder /service/server /opt/go-server/server
