FROM ubuntu:22.04 AS mysql

RUN apt update
RUN apt install mysql-server -y
RUN mkdir -p /var/lib/mysql /var/run/mysqld 
RUN chmod 777 /var/run/mysqld

RUN mkdir -p /var/lib/mysql
RUN touch /var/lib/mysql/server-cert.pem /var/lib/mysql/server-key.pem /var/lib/mysql/ca.pem
RUN chmod 660 /var/lib/mysql/server-cert.pem /var/lib/mysql/server-key.pem /var/lib/mysql/ca.pem

USER root
COPY --from=it-spiffe-helper /service/spiffe-helper /opt/helper/spiffe-helper
