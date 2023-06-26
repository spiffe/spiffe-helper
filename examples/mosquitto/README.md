# User authentication in Mosquitto using SVIDs with DNS names

This is an example of how **spiffe-helper** can be used to authenticate users to
a **Mosquitto** broker using x509 SVIDs.

Mosquitto can be configured to use the CN of a certificate as a username to
authenticate the client. This is done by setting the following two options in
the `mosquitto.conf` file:
```
require_certificate true
use_identity_as_username true
```

## Guide

### Prerequisites

We will do this test using three virtual machines (VMs) running Ubuntu 22.04 on
the same virtual network. The setup will be as follows:
| hostname | IP | Description |
| --- | --- | --- |
| node0 | 10.211.55.2 | SPIRE server |
| node1 | 10.211.55.20 | Mosquitto broker |
| node2 | 10.211.55.21 | Mosquitto client |

### 1. Configure and Run Spire Server on Node0

Download or build the latest version of SPIRE and extract it to `/opt/spire` on
`node0`. Edit the `conf/server/server.conf` file to set the `bind_address` to
`10.211.55.2` and the `trust_domain` to `example.org`. The rest of the
configuration can be left as is.

After editing the configuration file the `server` config should look similar to
this:
```
server {
    bind_address = "10.211.55.2"
    bind_port = "8081"
    socket_path = "/tmp/spire-server/private/api.sock"
    trust_domain = "example.org"
    data_dir = "./.data"
    log_level = "DEBUG"
}
```

Start the server with:
```bash
cd /opt/spire
./bin/spire-server run -config conf/server/server.conf
```

*NOTE:* Make sure `/opt/spire` directory has the right permissions for the
server to write to it.

### 2. Configure and Run Spire Agent on Node1 & Node2

Just like with the server, install Spire under `/opt/spire` and edit the agent
configuration file to set the `bind_address` to the IP of the spire server (i.e.
node0) and the `trust_domain` to `example.org`. The rest of the configuration
can be left as is.

Before we can start the agents up on `node1` and `node2` we need to register
them with the server.

### 3. Register Node1 Agent

On `node0` run the following command:
```bash
./bin/spire-server token generate -spiffeID spiffe://example.org/node1
```
This will output a join token. Copy it and run the following command on `node1`:
```bash
./bin/spire-agent run -config ./conf/agent/agent.conf -joinToken ${JOIN_TOKEN}
```
Make sure to replace `${JOIN_TOKEN}` with the token you got from the server.

### 4. Register Node2 Agent

On `node0` run the following command:
```bash
./bin/spire-server token generate -spiffeID spiffe://example.org/node2
```
This will output a join token. Copy it and run the following command on `node2`:
```bash
./bin/spire-agent run -config ./conf/agent/agent.conf -joinToken ${JOIN_TOKEN}
```
Make sure to replace `${JOIN_TOKEN}` with the token you got from the server.

### 5. Install Mosquitto Broker on Node1

Install latest [Mosquitto](https://mosquitto.org/) broker on `node1`. You can
best use the package that comes with the distribution. On Ubuntu this is done by
running:
```bash
sudo apt install mosquitto
```

Once installed, make sure to stop it as we will be running it with the
spiffe-helper instead:
```bash
sudo systemctl stop mosquitto
```

### 6. Register Mosquitto Broker Workload with Spire Server

On `node0` run the following command:
```bash
cd /opt/spire
./bin/spire-server entry create \
                   -spiffeID spiffe://example.org/mosquitto-server \
                   -parentID spiffe://example.org/node1 \
                   -selector unix:user:mosquitto \
                   -ttl 600 \
                   -dns node1
```

For `-dns` we use the hostname that the client will use to connect to the
broker. In this case we are using the hostname of `node1`. We also use the
unix attestation selector with user `mosquitto` to identify the workload.

For testing purposes we also set the `-ttl` to 10 minutes.

### 6. Configure Spiffe Helper and Run Mosquitto Broker on Node1

Download and build the spiffe helper on `node1`. Note that we will be running
the spiffe helper with user `mosquitto` so make sure that the location where
you install the spiffe-helper binary has the right permissions for reading the
configuration files:
```bash
chmod -R o+r ./examples/mosquitto
```

Now start up the mosquitto broker using the spiffe helper:
```bash
sudo mkdir -p /opt/spire/certs/mosquitto
sudo chown mosquitto:mosquitto /opt/spire/certs/mosquitto
sudo -u mosquitto ./bin/spiffe-helper -config ./examples/mosquitto/helper.conf
```

### 7. Install Mosquitto Client on Node2

Make sure to install the mosquitto client tools on node2. On Ubuntu this is done
with:
```bash
sudo apt install mosquitto-clients
```

We will be running the client under a dedicated user called `mosquitto-client`.
Create the user with:
```bash
sudo useradd mosquitto-client
```

### 7. Register the Mosquitto Client Workload with Spire Server

On `node0` run the following command:
```bash
cd /opt/spire
./bin/spire-server entry create \
                   -spiffeID spiffe://example.org/mosquitto-client \
                   -parentID spiffe://example.org/node2 \
                   -selector unix:user:mosquitto-client \
                   -ttl 600 \
                   -dns jdoe
```

For `-dns` we use the username that the client will use to connect to the
broker. In this case we are using the username `jdoe`. We also use the unix
attestation selector with user `mosquitto-client` to identify the workload.

For testing purposes we also set the `-ttl` to 10 minutes.

### 8. Run the Mosquitto Client

First create a directory for the client certificates:
```bash
mkdir -p /tmp/mosquitto/svids
sudo chown mosquitto-client:mosquitto-client /tmp/mosquitto/svids
```

Copy over the script [./connect.sh] to `node2` and run it with:
```bash
sudo -u mosquitto-client ./examples/mosquitto/connect.sh
```

The script will connect to the broker and subscribe to the topic `test`. To send
a message simply type something and hit enter.

If you check the script, it is important to see that we use the hostname as
we set it in the `-dns` flag when registering the client workload. If you don't
do this (e.g. use the IP address instead) the connection will fail with:
```
Error: host name verification failed.
OpenSSL Error[0]: error:0A000086:SSL routines::certificate verify failed
Error: A TLS error occurred.
```

To view the published messages on the broker, you can go to `node1` and run:
```bash
mosquitto_sub -t test/#
```
