# User authentication in MySQL using SVIDs with DNS names

This is an example of how **spiffe-helper** can be used to authenticate users to a **MySQL** database using x509 SVIDs.

MySQL can be compiled using OpenSSL or yaSSL, both of them enable secure connections based on the OpenSSL API.
In order to handle SVIDs, we need to make sure that the MySQL distribution that we are using was compiled using OpenSSL and not yaSSL.

This statement returns a row if OpenSSL was used and an empty result if yaSSL was used:

```sql
SHOW STATUS LIKE 'Rsa_public_key';
```

This guide sets up the authentication configuration for the username: `mysql-user`.

## Guide

### Considerations
The following assumptions are made:
+ At least one SPIRE server and one agent are deployed.

+ Mysql 8.0 is used in this guide but each step should be easily applicable to other versions as well.

### 1. Install MySQL
Install [MySQL](https://dev.mysql.com/doc/mysql-installation-excerpt/8.0/en/) and make sure the service is up running.
```
service mysql status
```

### 2. Create the user
Create the `mysql-user` using the [provided script](create_user.sql).
```sql
sudo mysql -u root < examples/mysql/create_user.sql
```

### 3. Configure MySQL SSL settings
This guide uses the MySQL default certificates path for simplicity. You may want to create a backup of these files.

```bash
mv /var/lib/mysql/server-cert.pem /var/lib/mysql/server-cert.pem.bk
mv /var/lib/mysql/server-key.pem /var/lib/mysql/server-key.pem.bk
mv /var/lib/mysql/ca.pem /var/lib/mysql/ca.pem.bk
```

It is also possible to use a different directory. If that case, you should update the MySQL and the spiffe-helper configuration files.

### 4. Start SPIRE server
Start the SPIRE server using this example [configuration file](agent.conf):
```bash
./spire-server run
```

### 5. Start SPIRE agent
Start the SPIRE agent using this example [configuration file](agent.conf):
```bash
./spire-server bundle show > conf/agent/dummy_root_ca.crt
TOKEN=$(./spire-server token generate -spiffeID spiffe://example.org/agent)| awk '{print $2}')
./spire-agent run -joinToken $TOKEN
```

### 6. Create the registration entries
Create the following registration entries:

+ For the MySQL client, the DNS name must match the database user name. The selector used in this case is your current user id.
```bash
./spire-server entry create \
    -spiffeID spiffe://example.org/mysql-client \
    -parentID spiffe://example.org/agent \
    -selector unix:uid:1000 \
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


### 7. Start spiffe-helper
Start spiffe-helper using this example [configuration file](examples/mysql/helper.conf) with the `root` user:

```
sudo ./spiffe-helper -config examples/mysql/helper.conf
```

### 8. Connect to MySQL
Connect to mysql running the provided script with your current user.
```
examples/mysql/connect.sh
```
