FROM golang:1.17-alpine AS helper-builder
RUN apk add build-base git
WORKDIR /service
RUN git clone -b upgrade-helper https://github.com/marcosdy/spiffe-helper.git .
RUN go build -o /service/spiffe-helper ./cmd/spiffe-helper

FROM alpine:3.17 AS postgres
RUN addgroup -g 70 postgres
RUN adduser -G postgres -u 70 -D postgres

RUN apk update && apk add postgresql

RUN mkdir -p /run/postgresql/certs
COPY ./reload_certificates.sh /run/postgresql/reload_certificates.sh
RUN chmod +x /run/postgresql/reload_certificates.sh
RUN touch /run/postgresql/certs/svid.crt /run/postgresql/certs/svid.key /run/postgresql/certs/root.crt
RUN chmod 600 /run/postgresql/certs/svid.crt /run/postgresql/certs/svid.key /run/postgresql/certs/root.crt
RUN chown postgres:postgres \
    /var/run/postgresql \
    /run/postgresql/reload_certificates.sh \
    /run/postgresql/certs/svid.crt \
    /run/postgresql/certs/svid.key \
    /run/postgresql/certs/root.crt
USER postgres
RUN mkdir /var/lib/postgresql/data
RUN chmod 700 /var/lib/postgresql/data
RUN initdb -D /var/lib/postgresql/data

USER root
COPY --from=helper-builder /service/spiffe-helper /opt/helper/spiffe-helper
