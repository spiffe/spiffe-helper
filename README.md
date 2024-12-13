> # Help improve SPIFFE Helper
>
> Fill out this [questionnaire](https://docs.google.com/forms/d/1MwHyAiLXnGuUpymwBCfBJei25lur2jaD-056L5Hp1Js) so we can learn more about your use case.

# SPIFFE Helper

The SPIFFE Helper is a simple utility for fetching X.509 SVID certificates from the SPIFFE Workload API, launch a process that makes use of the certificates and continuously get new certificates before they expire. The launched process is signaled to reload the certificates when is needed.

## Usage
`$ spiffe-helper -config <config_file>`

`<config_file>`: file path to the configuration file.

If `-config` is not specified, the default value `helper.conf` is assumed. 

The flag `-exitWhenReady` is also supported.

## Configuration
The configuration file is an [HCL](https://github.com/hashicorp/hcl) formatted file that defines the following configurations:

 | Configuration                       | Description                                                                                                                       | Example Value                                                                                                                                                        |
 |-------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
 | `agent_address`                     | Socket address of SPIRE Agent.                                                                                                    | `"/tmp/agent.sock"`                                                                                                                                                  |
 | `cmd`                               | The path to the process to launch.                                                                                                | `"ghostunnel"`                                                                                                                                                       |
 | `cmd_args`                          | The arguments of the process to launch.                                                                                           | `"server --listen localhost:8002 --target localhost:8001--keystore certs/svid_key.pem --cacert certs/svid_bundle.pem --allow-uri-san spiffe://example.org/Database"` |
 | `cert_dir`                          | Directory name to store the fetched certificates. This directory must be created previously.                                      | `"certs"`                                                                                                                                                            |
 | `daemon_mode`                       | Toggle running as a daemon, keeping X.509 and JWT up to date; or just fetch X.509 and JWT and exit 0                              | `true`                                                                                                                                                               |
 | `add_intermediates_to_bundle`       | Add intermediate certificates into Bundle file instead of SVID file.                                                              | `true`                                                                                                                                                               |
 | `renew_signal`                      | The signal that the process to be launched expects to reload the certificates. It is not supported on Windows.                    | `"SIGUSR1"`                                                                                                                                                          |
 | `svid_file_name`                    | File name to be used to store the X.509 SVID public certificate in PEM format.                                                    | `"svid.pem"`                                                                                                                                                         |
 | `svid_key_file_name`                | File name to be used to store the X.509 SVID private key and public certificate in PEM format.                                    | `"svid_key.pem"`                                                                                                                                                     |
 | `svid_bundle_file_name`             | File name to be used to store the X.509 SVID Bundle in PEM format.                                                                | `"svid_bundle.pem"`                                                                                                                                                  |
 | `jwt_svids`                         | An array with the audience, optional extra audiences array, and file name to store the JWT SVIDs. File is Base64-encoded string). | `[{jwt_audience="your-audience", jwt_extra_audiences=["your-extra-audience-1", "your-extra-audience-2"], jwt_svid_file_name="jwt_svid.token"}]`                      |
 | `jwt_bundle_file_name`              | File name to be used to store JWT Bundle in JSON format.                                                                          | `"jwt_bundle.json"`                                                                                                                                                  |
 | `include_federated_domains`         | Include trust domains from federated servers in the CA bundle.                                                                    | `true`                                                                                                                                                               |
 | `cert_file_mode`                    | The octal file mode to use when saving the X.509 public certificate file.                                                         | `0644`                                                                                                                                                               |
 | `key_file_mode`                     | The octal file mode to use when saving the X.509 private key file.                                                                | `0600`                                                                                                                                                               |
 | `jwt_bundle_file_mode`              | The octal file mode to use when saving a JWT Bundle file.                                                                         | `0600`                                                                                                                                                               |
 | `jwt_svid_file_mode`                | The octal file mode to use when saving a JWT SVID file.                                                                           | `0600`                                                                                                                                                               |
 | `health_checks.enable_health_check` | Whether to start an HTTP server at the configured endpoint for the daemon health. Doesn't apply for non-daemon mode.              | `false`                                                                                                                                                              |
 | `health_checks.health_check_port`   | The port to run the HTTP health server.                                                                                           | `8081`                                                                                                                                                               |
| `health_checks.health_check_path`   | The URL path for the health check                                                                                                 | `/healthz`                                                                                                                                                           |

### Configuration example
```
agent_address = "/tmp/spire-agent/public/api.sock"
cmd = "ghostunnel"
cmd_args = "server --listen localhost:8002 --target localhost:8001 --keystore certs/svid_key.pem --cacert certs/svid_bundle.pem --allow-uri-san spiffe://example.org/Database"
cert_dir = "certs"
renew_signal = "SIGUSR1"
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
jwt_svids = [{jwt_audience="your-audience",jwt_extra_audiences=["your-extra-audience-1", "your-extra-audience-2"], jwt_svid_file_name="jwt_svid.token"}]
jwt_bundle_file_name = "bundle.json"
cert_file_mode = 0444
key_file_mode = 0444
jwt_bundle_file_mode = 0444
jwt_svid_file_mode = 0444
```

### Windows example
```
agent_address = "spire-agent\\public\\api"
cert_dir = "certs"
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
jwt_svids = [{jwt_audience="your-audience",jwt_extra_audiences=["your-extra-audience-1", "your-extra-audience-2"], jwt_svid_file_name="jwt_svid.token"}]
jwt_bundle_file_name = "bundle.json"
```
