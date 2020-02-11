# User authentication in Postgresql using SVIDs with DNS names

This is an example of how **spiffe-helper** can be used to authenticate users to a **PostgreSQL** database using x509 SVIDs.

Postgres provides a feature that allows users to authenticate using [certificate authentication](https://www.postgresql.org/docs/9.5/auth-methods.html#AUTH-CERT). The server validates that the CN (Common Name) attribute of the certificate presented by the client matches the database user name or a [mapped](https://www.postgresql.org/docs/9.5/auth-username-maps.html) value.

This guide sets up the authentication configuration for the username: `postgres-user`.


## Guide

### Considerations
The following assumptions are made:
+ Postgres 12 is used in this guide but each step should be easily applicable to other versions as well. Check the considerations for other versions in [helper.conf](./helper.conf).

+ At least one SPIRE server and one agent are deployed with trust domain `example.org`.

### 1. Install PosgreSQL
Install [PosgreSQL](https://www.postgresql.org/docs/12/tutorial-install.html) and make sure the service is up running.
```
systemctl status postgresql@12-main
```

### 2. Create the user
Create the `postgres-user` using the [provided script](create_user.sql).
It creates a test database (`testdb`) and grants privileges to it.
```sql
sudo -u postgres psql -f create_user.sql
```

### 3. Configure PosgreSQL SSL settings
Make PostgreSQL server to use the certificates and key provided by SPIRE by setting the following SSL configurables in the PostgreSQL configuration file (`postgresql.conf`).
```bash
ssl = on
ssl_cert_file = '/opt/spire/certs/postgresql/svid.pem'
ssl_key_file = '/opt/spire/certs/postgresql/svid.key'
ssl_ca_file = '/opt/spire/certs/postgresql/svid_bundle.pem'
```

Create the folder using the `postgres` user:
```
sudo -u postgres mkdir -p /opt/spire/certs/postgresql
```

### 4. Configure pg_hba.conf
Create the following rules in the `pg_hba.conf` file:
```
# TYPE      DATABASE        USER            ADDRESS                 METHOD

# Allows postgres user to connect using unix domain sockets (not required)
local       all             postgres                                trust

# Reject all nossl calls (not required)
hostnossl   all             all             0.0.0.0/0               reject

# Validate provided certificates
hostssl     all             all             0.0.0.0/0               cert clientcert=1
```

### 5. Start SPIRE server
Start SPIRE server using the SPIRE Server [configuration file](./spire-server.conf):
```bash
./spire-server run
```

### 6. Start SPIRE agent
The server configuration file sets `upstream_bundle=false`. In this case,
the server bundle must be set as the agent trust bundle.

```bash
./spire-server bundle show > conf/agent/dummy_root_ca.crt
```

Get a join token:

```bash
TOKEN=$((./spire-server token generate -spiffeID spiffe://example.org/agent)| awk '{print $2}')
```

Start the agent using the SPIRE Agent [configuration file](./spire-agent.conf):
```bash
./spire-agent run -joinToken $TOKEN
```

### 7. Create a user for the PostgreSQL client workload
Create a unix user with name `postgresql-client`. This is the user that will run the PostgreSQL client workload.
```bash
useradd postgresql-client
```

### 8. Create the registration entries
Create the following registration entries:

+ For the PostgreSQL client, the DNS name must match the database user name. The selector used for this entry is the user name: `postgresql-client`.
```bash
./spire-server entry create \
    -spiffeID spiffe://example.org/psql-client \
    -parentID spiffe://example.org/agent \
    -selector unix:user:postgresql-client \
    -ttl 60 \
    -dns postgres-user
```

+ For the PostgreSQL server, we use the postgres user name as selector:
```bash
./spire-server entry create \
    -spiffeID spiffe://example.org/postgresql-server \
    -parentID spiffe://example.org/agent \
    -selector unix:user:postgres \
    -ttl 60
```

Note that `ttl` is lowered to 60 seconds in both cases just for demo purposes.


### 8. Start spiffe-helper
Start spiffe-helper using this example [configuration file](examples/postgresql/helper.conf) with the `postgres` user:

```
sudo -u postgres ./spiffe-helper -config examples/postgresql/helper.conf
```

The spiffe-helper is now notified by the WorkloadAPI on each SVID rotation. It updates the certificates and signal PostgreSQL to reload the configuration.

### 9. Connect to postgresql
Create an `svids` folder owned by the `postgresql-client` user to store the SVIDs retrieved from the Workload API.

```bash
mkdir examples/postgresql/svids
sudo chown postgresql-client:postgresql-client examples/postgresql/svids
```

Connect to posgresql running the provided script with the `postgresql-client` user.
```
sudo -u postgresql-client examples/postgresql/connect.sh
```
