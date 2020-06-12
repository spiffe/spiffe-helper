# User authentication in MySQL using SVIDs with DNS names

This is an example of how **spiffe-helper** can be used to authenticate users to a **MySQL** database using x509 SVIDs.

MySQL can be compiled using OpenSSL or yaSSL, both of them enable secure connections based on the OpenSSL API.
In order to handle SVIDs, we need to make sure the MySQL distribution we are using was compiled using OpenSSL and not yaSSL.

This statement returns a row if OpenSSL was used and an empty result if yaSSL was used:

```sql
SHOW STATUS LIKE 'Rsa_public_key';
```

This guide sets up the authentication configuration for the username: `mysql-user`.

## Guide

### Considerations
The following assumptions are made:
+ Mysql 8.0 is used in this guide but each step should be easily applicable to other versions as well.
+ At least one SPIRE server and one agent are deployed with trust domain `example.org`.

### 1. Install MySQL
Install [MySQL](https://dev.mysql.com/doc/mysql-installation-excerpt/8.0/en/) and make sure the service is up running.
```
service mysql status
```

### 2. Create the user
Create the `mysql-user` using the [provided script](create_user.sql).
The script creates a user that requires clients to authenticate presenting a valid X.509 certificate containing `mysql-user` as CN.
```sql
sudo mysql -u root < examples/mysql/create_user.sql
```

### 3. Configure MySQL SSL settings
This guide uses the MySQL default certificates path for simplicity. You may want to create a backup of these files.

```bash
cp /var/lib/mysql/server-cert.pem /var/lib/mysql/server-cert.pem.bk
cp /var/lib/mysql/server-key.pem /var/lib/mysql/server-key.pem.bk
cp /var/lib/mysql/ca.pem /var/lib/mysql/ca.pem.bk
```
Update the file permissions allowing the os user access to update the certificates:
```bash
chmod 660 /var/lib/mysql/server-cert.pem
chmod 660 /var/lib/mysql/server-key.pem
chmod 660 /var/lib/mysql/ca.pem
```
Make sure the os user belongs to the same groups as the user running the mysql server.

It is also possible to use a different directory. In that case, you should update the MySQL and the spiffe-helper configuration files.

### 4. Start SPIRE server
Start SPIRE server using the SPIRE Server [configuration file](./spire-server.conf):
```bash
./spire-server run
```

### 5. Start SPIRE agent
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

### 6. Create a user for the MySQL client workload
Create a unix user with name `mysql-client`. This is the user that will run the MySQL client workload.
```bash
useradd mysql-client
```

### 7. Create the registration entries
Create the following registration entries:

+ For the MySQL client workload, the DNS name must match the database user name. The selector used for this entry is the user name: `mysql-client`.
```bash
./spire-server entry create \
    -spiffeID spiffe://example.org/mysql-client \
    -parentID spiffe://example.org/agent \
    -selector unix:user:mysql-client \
    -ttl 60 \
    -dns mysql-user
```

+ For the MySQL server, we use the root user name as selector:
```bash
./spire-server entry create \
    -spiffeID spiffe://example.org/mysql-server \
    -parentID spiffe://example.org/agent \
    -selector unix:user:root \
    -ttl 60
```

Note that `ttl` is lowered to 60 seconds in both cases just for demo purposes.


### 8. Start spiffe-helper
Start spiffe-helper using this example [configuration file](examples/mysql/helper.conf) with the `root` user:

```
sudo ./spiffe-helper -config examples/mysql/helper.conf
```

The spiffe-helper is now notified by the WorkloadAPI on each SVID rotation. It updates the certificates and signal MySQL to reload the configuration.

### 9. Connect to MySQL
Create an `svids` folder owned by the `mysql-client` user to store the SVIDs retrieved from the Workload API.

```bash
mkdir examples/mysql/svids
sudo chown mysql-client:mysql-client examples/mysql/svids
```

Connect to mysql running the provided script with the `mysql-client` user.
```
sudo -u mysql-client examples/mysql/connect.sh
```
