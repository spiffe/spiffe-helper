FROM golang:1.17-alpine AS helper-builder
RUN apk add build-base git
WORKDIR /service
RUN git clone -b upgrade-helper https://github.com/marcosdy/spiffe-helper.git .
RUN go build -tags netgo -a -v -o /service/spiffe-helper ./cmd/spiffe-helper

FROM ubuntu:22.04 AS mysql
RUN apt update
RUN apt install mysql-server -y
RUN mkdir -p /var/lib/mysql /var/run/mysqld 
RUN chmod 777 /var/run/mysqld

RUN mkdir -p /var/lib/mysql
RUN touch /var/lib/mysql/server-cert.pem /var/lib/mysql/server-key.pem /var/lib/mysql/ca.pem
RUN chmod 660 /var/lib/mysql/server-cert.pem /var/lib/mysql/server-key.pem /var/lib/mysql/ca.pem

USER root
COPY --from=helper-builder /service/spiffe-helper /opt/helper/spiffe-helper

EXPOSE 3306