> # Help improve SPIFFE Helper
>
> Fill out this [questionnaire](https://docs.google.com/forms/d/1MwHyAiLXnGuUpymwBCfBJei25lur2jaD-056L5Hp1Js) so we can learn more about your use case.

# SPIFFE Helper

The SPIFFE Helper is a simple utility for fetching X.509 SVID certificates from the SPIFFE Workload API, launch a process that makes use of the certificates and continuously get new certificates before they expire. The launched process is signaled to reload the certificates when is needed.

## Usage
`$ spiffe-helper -config <config_file>`

`<config_file>`: file path to the configuration file.

If `-config` is not specified, the default value `helper.conf` is assumed. 

## Configuration
The configuration file is an [HCL](https://github.com/hashicorp/hcl) formatted file that defines the following configurations:

 | Configuration                 | Description                                                                                                    | Example Value                                                                                                                                                        |
 |-------------------------------|----------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
 | `agent_address`               | Socket address of SPIRE Agent.                                                                                 | `"/tmp/agent.sock"`                                                                                                                                                  |
 | `cmd`                         | The path to the process to launch.                                                                             | `"ghostunnel"`                                                                                                                                                       |
 | `cmd_args`                    | The arguments of the process to launch.                                                                        | `"server --listen localhost:8002 --target localhost:8001--keystore certs/svid_key.pem --cacert certs/svid_bundle.pem --allow-uri-san spiffe://example.org/Database"` |
 | `cert_dir`                    | Directory name to store the fetched certificates. This directory must be created previously.                   | `"certs"`                                                                                                                                                            |
 | `exit_when_ready`             | Fetch x509 certificate and then exit(0)                                                                        | `true`               |
 | `add_intermediates_to_bundle` | Add intermediate certificates into Bundle file instead of SVID file.                                           | `true`                                                                                                                                                               |
 | `renew_signal`                | The signal that the process to be launched expects to reload the certificates. It is not supported on Windows. | `"SIGUSR1"`                                                                                                                                                          |
 | `svid_file_name`              | File name to be used to store the X.509 SVID public certificate in PEM format.                                 | `"svid.pem"`                                                                                                                                                         |
 | `svid_key_file_name`          | File name to be used to store the X.509 SVID private key and public certificate in PEM format.                 | `"svid_key.pem"`                                                                                                                                                     |
 | `svid_bundle_file_name`       | File name to be used to store the X.509 SVID Bundle in PEM format.                                             | `"svid_bundle.pem"`                                                                                                                                                  |
 | `jwt_audience`                | JWT SVID audience.                                                                                             | `"your-audience"`                                                                                                                                                    |
 | `jwt_svid_file_name`          | File name to be used to store JWT SVID in Base64-encoded string.                                               | `"jwt_svid.token"`                                                                                                                                                   |
 | `jwt_bundle_file_name`        | File name to be used to store JWT Bundle in JSON format.                                                       | `"jwt_bundle.json"`                                                                                                                                                  |
| `plugins`                      | Block of plugins.                                                                                              |   |


### Configuration example
```hcl
agent_address = "/tmp/spire-agent/public/api.sock"
cmd = "ghostunnel"
cmd_args = "server --listen localhost:8002 --target localhost:8001 --keystore certs/svid_key.pem --cacert certs/svid_bundle.pem --allow-uri-san spiffe://example.org/Database"
cert_dir = "certs"
renew_signal = "SIGUSR1"
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
jwt_audience = "your-audience"
jwt_svid_file_name = "jwt.token"
jwt_bundle_file_name = "bundle.json"
plugins {
    "plugin_name" {
        path="/tmp/plugins/plugin_name"
        checksum="7ae182614c5b2f96b0c6655a6bf3e1e64fb0dbb9142fa50c8cf0002c5c5bb9c5"
        custom_config="random_value"
    }
}
```

### Windows example
```hcl
agent_address = "spire-agent\\public\\api"
cert_dir = "certs"
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
jwt_audience = "your-audience"
jwt_svid_file_name = "jwt.token"
jwt_bundle_file_name = "bundle.json"
plugins {
    "plugin_name" {
        path="c:\\tmp\\plugins\\plugin_name"
        checksum="7ae182614c5b2f96b0c6655a6bf3e1e64fb0dbb9142fa50c8cf0002c5c5bb9c5"
        custom_config="random_value"
    }
}
```
