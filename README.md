> # Help improve SPIFFE Helper
>
> Fill out this [questionnaire](https://docs.google.com/forms/d/1MwHyAiLXnGuUpymwBCfBJei25lur2jaD-056L5Hp1Js) so we can learn more about your use case.

# SPIFFE Helper

The SPIFFE Helper is a simple utility for fetching X.509 SVID certificates from the SPIFFE Workload API, launch a process that makes use of the certificates and continuously get new certificates before they expire. The launched process is signaled to reload the certificates when is needed.

## Usage
`$ spiffe-helper -config <config_file> [-config-format <format>]`

`<config_file>`: file path to the configuration file. If not specified, the default value `helper.conf` is assumed. If the file does not exist or is empty, configuration will be loaded from environment variables.

CLI options:

 | Flag name                       | Description                                                         |
 |---------------------------------|---------------------------------------------------------------------|
 | `-config`                       | Path to the configuration file (default: `helper.conf`). If the file does not exist, configuration will be loaded from environment variables. |
 | `-config-format`                | Configuration format: `hcl`, `json`, `yaml`, or `auto` (default: `auto`). Format is automatically detected from file extension when set to `auto`. |
 | `-help`                         | Print interactive help                                              |
 | `-daemon-mode={true\|false}`    | Boolean true or false. Overrides `daemon_mode` in the config file.  |
 | `-version`                      | Print version number                                                |

## Configuration

The configuration file can be in HCL, JSON, or YAML format. The format is automatically detected from the file extension (`.conf` for HCL, `.json` for JSON, `.yaml` or `.yml` for YAML), or can be explicitly specified using the `-config-format` flag.

:warning: **HCL format is deprecated** and will be removed in version 0.11.0. Use JSON or YAML instead.

If the configuration file is not specified, does not exist, or is empty, all configuration can be provided via environment variables (see [Environment Variables](#environment-variables) section below).

The following configurations are available:

 | Configuration                 | Description                                                                                                                       | Example Value                                                                                                                                                        |
 |-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
 | `agent_address`               | Socket address of SPIRE Agent.                                                                                                    | `"/tmp/agent.sock"`                                                                                                                                                  |
 | `cmd`                         | The path to the process to launch and monitor and signal for certificate renewals. Ignored if `daemon_mode=false`                 | `"ghostunnel"`                                                                                                                                                       |
 | `cmd_args`                    | The arguments of the process to launch. Split by spaces into an argument vector.                                                  | `"server --listen localhost:8002 --target localhost:8001--keystore certs/svid_key.pem --cacert certs/svid_bundle.pem --allow-uri-san spiffe://example.org/Database"` |
 | `pid_file_name`               | Path to a file containing a process ID to signal when certificates are renewed. Not required when using 'cmd'.                    | `"/var/run/ghostunnel.pid"`                                                                                                                                          |
 | `cert_dir`                    | Directory name to store the fetched certificates. This directory must be created previously.                                      | `"certs"`                                                                                                                                                            |
 | `daemon_mode`                 | Toggle running as a daemon, keeping X.509 and JWT up to date; or just fetch X.509 and JWT and exit 0. Does not background itself. | `true`                                                                                                                                                               |
 | `add_intermediates_to_bundle` | Add intermediate certificates into Bundle file instead of SVID file.                                                              | `true`                                                                                                                                                               |
 | `renew_signal`                | The signal that the process to be launched expects to reload the certificates. It is not supported on Windows.                    | `"SIGUSR1"`                                                                                                                                                          |
 | `svid_file_name`              | File name to be used to store the X.509 SVID public certificate in PEM format.                                                    | `"svid.pem"`                                                                                                                                                         |
 | `svid_key_file_name`          | File name to be used to store the X.509 SVID private key and public certificate in PEM format.                                    | `"svid_key.pem"`                                                                                                                                                     |
 | `svid_bundle_file_name`       | File name to be used to store the X.509 SVID Bundle in PEM format.                                                                | `"svid_bundle.pem"`                                                                                                                                                  |
 | `jwt_svids`                   | An array with the audience, optional extra audiences array, and file name to store the JWT SVIDs. File is Base64-encoded string). | `[{jwt_audience="your-audience", jwt_extra_audiences=["your-extra-audience-1", "your-extra-audience-2"], jwt_svid_file_name="jwt_svid.token"}]`                      |
 | `jwt_bundle_file_name`        | File name to be used to store JWT Bundle in JSON format.                                                                          | `"jwt_bundle.json"`                                                                                                                                                  |
 | `include_federated_domains`   | Include trust domains from federated servers in the CA bundle.                                                                    | `true`                                                                                                                                                               |
 | `cert_file_mode`              | The octal file mode to use when saving the X.509 public certificate file.                                                         | `0644`                                                                                                                                                               |
 | `key_file_mode`               | The octal file mode to use when saving the X.509 private key file.                                                                | `0600`                                                                                                                                                               |
 | `jwt_bundle_file_mode`        | The octal file mode to use when saving a JWT Bundle file.                                                                         | `0600`                                                                                                                                                               |
 | `jwt_svid_file_mode`          | The octal file mode to use when saving a JWT SVID file.                                                                           | `0600`                                                                                                                                                               |
 | `hint`                        | Hint to use to pick the SPIFFE ID.                                                                                                | ``                                                                                                                                                                   |
 | `omit_expired`                | Omits expired CA certificates from the SVID bundle when renewed. Defaults to `false`.                                             | `false`                                                                                                                                                              |

**Notes**:

* If `cmd` is specified, spiffe-helper will connect its `stdin`, `stdout` and
  `stderr` to that of the command it invokes. If this is not desired, close
  these file descriptors before invoking spiffe-helper.

### Configuration Format

The configuration file format can be specified using the `-config-format` flag or automatically detected from the file extension:

 | Format | File Extensions | Description |
 |--------|----------------|-------------|
 | `hcl` | `.conf` | HashiCorp Configuration Language (deprecated, will be removed in 0.11.0) |
 | `json` | `.json` | JSON format |
 | `yaml` | `.yaml`, `.yml` | YAML format |
 | `auto` | Any | Automatically detect format from file extension (default) |

When using `auto` format (the default), the format is determined by the file extension:
- `.conf` files are parsed as HCL
- `.json` files are parsed as JSON
- `.yaml` or `.yml` files are parsed as YAML

If the configuration file is not specified, does not exist, or is empty, the configuration will be loaded entirely from environment variables (see [Environment Variables](#environment-variables) section below).

### Environment Variables

All configuration fields can be set via environment variables. Environment variables use the `SPIFFE_HLP_` prefix followed by the field name in UPPER_SNAKE_CASE format.

For example:
- `agent_address` → `SPIFFE_HLP_AGENT_ADDRESS`
- `svid_file_name` → `SPIFFE_HLP_SVID_FILE_NAME`
- `jwt_bundle_file_name` → `SPIFFE_HLP_JWT_BUNDLE_FILE_NAME`

Environment variables override values from the configuration file. If a configuration file is provided, environment variables will override matching fields. If no configuration file is specified or the file does not exist, the entire configuration can be provided via environment variables.

#### Special Handling for `jwt_svids`

The `jwt_svids` array cannot be set directly via a single environment variable due to limitations with arrays of structs. Instead, use indexed environment variables with the following format:

**Format 1: Count-based indices**
Set `SPIFFE_HLP_JWT_SVIDS` to a count (e.g., `"2"`), which will use indices 0, 1, ..., count-1:

```bash
export SPIFFE_HLP_JWT_SVIDS="2"
export SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE="audience-0"
export SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME="file-0.token"
export SPIFFE_HLP_JWT_SVIDS_0_EXTRA_AUDIENCES="extra1,extra2"
export SPIFFE_HLP_JWT_SVIDS_1_AUDIENCE="audience-1"
export SPIFFE_HLP_JWT_SVIDS_1_SVID_FILE_NAME="file-1.token"
```

**Format 2: Comma-separated indices**
Set `SPIFFE_HLP_JWT_SVIDS` to a comma-separated list of indices (e.g., `"0,2,5"`):

```bash
export SPIFFE_HLP_JWT_SVIDS="0,2,5"
export SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE="audience-0"
export SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME="file-0.token"
export SPIFFE_HLP_JWT_SVIDS_2_AUDIENCE="audience-2"
export SPIFFE_HLP_JWT_SVIDS_2_SVID_FILE_NAME="file-2.token"
export SPIFFE_HLP_JWT_SVIDS_2_EXTRA_AUDIENCES="extra1,extra2,extra3"
export SPIFFE_HLP_JWT_SVIDS_5_AUDIENCE="audience-5"
export SPIFFE_HLP_JWT_SVIDS_5_SVID_FILE_NAME="file-5.token"
```

For each index `i`, the following environment variables are read:
- `SPIFFE_HLP_JWT_SVIDS_i_AUDIENCE` - The JWT audience (required)
- `SPIFFE_HLP_JWT_SVIDS_i_SVID_FILE_NAME` - The file name to store the JWT SVID
- `SPIFFE_HLP_JWT_SVIDS_i_EXTRA_AUDIENCES` - Comma-separated list of extra audiences (optional)

If `SPIFFE_HLP_JWT_SVIDS_i_AUDIENCE` is not set for an index, that index is skipped (allows sparse arrays).

### Health Checks Configuration

SPIFFE Helper can expose and endpoint that can be used for health checking

 | Configuration                    | Description                                                                                                          | Example Value |
 |----------------------------------|----------------------------------------------------------------------------------------------------------------------|---------------|
 | `health_checks.listener_enabled` | Whether to start an HTTP server at the configured endpoint for the daemon health. Doesn't apply for non-daemon mode. | `false`       |
 | `health_checks.bind_port`        | The port to run the HTTP health server.                                                                              | `8081`        |
 | `health_checks.liveness_path`    | The URL path for the liveness health check                                                                           | `/live`       |
 | `health_checks.readiness_path`   | The URL path for the readiness health check                                                                          | `/ready`      |

### Operating modes and configuration details

spiffe-helper has two primary operating modes - "daemon mode" (the default),
where it runs continuously and manages the certificates, and "non-daemon mode",
where it fetches the certificates once and exits.

The helper can be used in several ways, as detailed below:

* Signal an external process when the certificates are renewed.
* Run a command that reloads an external process when the certificates are renewed.
* Run a command that uses the certificates, and signal it when they are renewed
  (not recommended)
* Fetch the certificates once and exit.

Note that "daemon mode" does not actually detach itself from the controlling
process and background itself like a unix "daemon". It just keeps running until
terminated by a signal or a fatal error.

`spiffe-helper` does not have all the features of a proper process supervisor,
so it's usually best to let a dedicated process supervisor like systemd manage
the process that uses the certificates. Use `spiffe-helper` to fetch and renew
the certificates and wake the external process via `cmd` or `pid_file_name`
when the certificates are reloaded.

#### Use in daemon-mode with file watcher

If the process using the certificates can watch the on-disk files for changes,
spiffe-helper can be run in `daemon_mode` with no `cmd` or `pid_file_name`. It
will fetch and renew the certificates, overwrite them on disk, and the process
will pick up the changes.

This approach is recommended where possible.

#### Use in daemon-mode with `cmd` to run a process or a reload command

`cmd` and `cmd_args` are used in `daemon_mode` to run a command whenever the
certificates are renewed. This can be a long-lived process that uses the
certificates, or a short-lived command that signals a reload mechanism
for an externally-managed process.

:warning: **cmd_args is not parsed according to shell-like rules**. The
`cmd_args` will be split into individual arguments using space separation
unless the argument is enclosed in double quotes, which are consumed. Double
quotes must be backslash escaped in the hcl string. For example:

```hcl
cmd_args = "\"this is one argument\""
```

Double quotes within the argument string must be escaped by doubling them so
they are not interpreted as argument delimiters. E.g.:

```hcl
cmd_args = "\"this is a single argument with ONE double-quote \"\" in it\""
```

Single quotes are NOT respected for argument quoting, and do not protect double
quotes. For example:

```hcl
cmd = "sh"
cmd_args = "-c 'echo hello world'"
```

will run `sh` with the argument-vector ["-c", "'echo", "hello", "world'"], not
["-c", "echo hello world"], which will fail with `Syntax error: Unterminated
quoted string`.

`cmd_args` is *not* subject to shell metacharacter expansion or interpretation.
If you need to use shell features, you must invoke a shell explicitly, e.g.
`cmd = "/bin/sh"` and `cmd_args = "-c \"echo hello\""`. Be careful with shell
invocations, as they can introduce security vulnerabilities and should be
avoided where possible.

The command's stdout and stderr will be attached to spiffe-helper's stdout
and stderr. Its stdin will be closed.

The process specified by `cmd` and `cmd_args` will not be launched for the
first time until the certificates are fetched successfully.

`spiffe-helper` continues running if the process created by `cmd` exits. The
process is not re-launched immediately if it exits.

If the process is still running next time the certs are renewed,
`spiffe-helper` will signal it with `renew_signal`. If it has exited,
`spiffe-helper` will re-launch it instead. This can be used to manage
certificate reloading in externally-managed processes that do not support
reloading certificates with a signal.

#### Use in daemon-mode with `pid_file_name` to signal an externally-managed process

If running in `daemon_mode` with `pid_file_name` set, the pid in
`pid_file_name` is sent the signal `renew_signal` to reload the certificates
when they are renewed.

`pid_file_name` is re-read every time the process is to be signaled, so it can
be updated with a new pid if the process changes.

An error will be logged if the pid file cannot be opened, read, or the value
parsed, and the attempt to signal the process will be skipped. The process will
still be signalled next time the certificates are renewed.

#### Combining `cmd` and `pid_file_name`

Both `cmd` and `pid_file_name` can be used at the same time. `spiffe-helper` will
both run the specified command and signal the process in the pid file. This can be
useful to use `cmd` to start the process to be managed, and `pid_file_name` to signal
a reload mechanism that is not signal-based.

#### Use in one-shot non-daemon mode

If `daemon_mode` is false, `spiffe-helper` will fetch the certificates once and
exit. This can be useful for one-shot scripts or for use in a process supervisor
that does not require a long-lived process.

`cmd` and `pid_file_name` are ignored in non-daemon mode. No command will be
run and no signals will be sent. They may be disallowed in future.

`spiffe-helper` cannot be used as a transparent wrapper around another
command because it does not forward stdin, signals, file descriptors, exit
when the child process exits, or return the managed process's exit code as
its own exit code. Instead, consider running the other process separately,
under the control of a proper process supervisor like systemd, and signaling
it via `pid_file_name`.

:warning: A future release may support running a command and/or signalling an
external process in non-daemon mode, so it is recommended to leave `cmd`,
`renew_signal` and `pid_file_name` blank if `daemon_mode` is false.

### Configuration Examples

#### HCL Example

:warning: **HCL format is deprecated** and will be removed in version 0.11.0. Use JSON or YAML instead.
```hcl
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

#### JSON Example

```json
{
  "agent_address": "/tmp/spire-agent/public/api.sock",
  "cmd": "ghostunnel",
  "cmd_args": "server --listen localhost:8002 --target localhost:8001 --keystore certs/svid_key.pem --cacert certs/svid_bundle.pem --allow-uri-san spiffe://example.org/Database",
  "cert_dir": "certs",
  "renew_signal": "SIGUSR1",
  "svid_file_name": "svid.pem",
  "svid_key_file_name": "svid_key.pem",
  "svid_bundle_file_name": "svid_bundle.pem",
  "jwt_svids": [
    {
      "jwt_audience": "your-audience",
      "jwt_extra_audiences": ["your-extra-audience-1", "your-extra-audience-2"],
      "jwt_svid_file_name": "jwt_svid.token"
    }
  ],
  "jwt_bundle_file_name": "bundle.json",
  "cert_file_mode": 292,
  "key_file_mode": 292,
  "jwt_bundle_file_mode": 292,
  "jwt_svid_file_mode": 292
}
```

#### YAML Example

```yaml
agent_address: "/tmp/spire-agent/public/api.sock"
cmd: "ghostunnel"
cmd_args: "server --listen localhost:8002 --target localhost:8001 --keystore certs/svid_key.pem --cacert certs/svid_bundle.pem --allow-uri-san spiffe://example.org/Database"
cert_dir: "certs"
renew_signal: "SIGUSR1"
svid_file_name: "svid.pem"
svid_key_file_name: "svid_key.pem"
svid_bundle_file_name: "svid_bundle.pem"
jwt_svids:
  - jwt_audience: "your-audience"
    jwt_extra_audiences:
      - "your-extra-audience-1"
      - "your-extra-audience-2"
    jwt_svid_file_name: "jwt_svid.token"
jwt_bundle_file_name: "bundle.json"
cert_file_mode: 292
key_file_mode: 292
jwt_bundle_file_mode: 292
jwt_svid_file_mode: 292
```

#### Environment Variables Example

Configuration can be provided entirely via environment variables when no config file is specified or the file does not exist:

```bash
export SPIFFE_HLP_AGENT_ADDRESS="/tmp/spire-agent/public/api.sock"
export SPIFFE_HLP_CMD="ghostunnel"
export SPIFFE_HLP_CMD_ARGS="server --listen localhost:8002 --target localhost:8001 --keystore certs/svid_key.pem --cacert certs/svid_bundle.pem --allow-uri-san spiffe://example.org/Database"
export SPIFFE_HLP_CERT_DIR="certs"
export SPIFFE_HLP_RENEW_SIGNAL="SIGUSR1"
export SPIFFE_HLP_SVID_FILE_NAME="svid.pem"
export SPIFFE_HLP_SVID_KEY_FILE_NAME="svid_key.pem"
export SPIFFE_HLP_SVID_BUNDLE_FILE_NAME="svid_bundle.pem"
export SPIFFE_HLP_JWT_BUNDLE_FILE_NAME="bundle.json"
export SPIFFE_HLP_CERT_FILE_MODE="292"
export SPIFFE_HLP_KEY_FILE_MODE="292"
export SPIFFE_HLP_JWT_BUNDLE_FILE_MODE="292"
export SPIFFE_HLP_JWT_SVID_FILE_MODE="292"

# JWT SVIDs using indexed environment variables
export SPIFFE_HLP_JWT_SVIDS="1"
export SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE="your-audience"
export SPIFFE_HLP_JWT_SVIDS_0_EXTRA_AUDIENCES="your-extra-audience-1,your-extra-audience-2"
export SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME="jwt_svid.token"
```

### Windows Example

```hcl
agent_address = "spire-agent\\public\\api"
cert_dir = "certs"
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
jwt_svids = [{jwt_audience="your-audience",jwt_extra_audiences=["your-extra-audience-1", "your-extra-audience-2"], jwt_svid_file_name="jwt_svid.token"}]
jwt_bundle_file_name = "bundle.json"
```

## Development and testing

This is a pretty straightforward Go project. You can use the standard Go tools
to build and test it.

Please run the tests for Windows for your PRs. `wine` is sufficient if you
don't have a convenient Windows machine or VM, and you don't need the Windows
Go SDK to cross-compile the test suite and run it. Install `wine` with
`sudo apt-get install wine` or similar, then run the tests with `make test-wine`.
