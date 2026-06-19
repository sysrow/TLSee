# tlsee

A small, friendly TLS certificate inspector. `tlsee scan <target>` connects to
a host's TLS port, retrieves the presented certificate chain, and prints a
clear, aligned report: the certificate's SAN DNS names, issuer and subject, the
validity window with days remaining, whether the chain is trusted, whether the
hostname matches, the negotiated TLS version and cipher suite, and the host's
resolved A/AAAA DNS records.

Verification is intentionally skipped during the handshake so that any
certificate can be inspected, including expired, self-signed, or wrong-host
certificates. Trust and hostname matching are then evaluated and reported as
separate facts. It works against public hosts and internal targets alike
(`localhost:8443`, `127.0.0.1`, internal IPs).

By default it also performs a **SAN liveness check**: every DNS name in the
certificate's SAN list is resolved (A/AAAA) and TCP-probed on the scanned port,
so dead or stale entries are surfaced -- a name that no longer resolves, or
whose host is unreachable. This catches names left on a certificate after the
service behind them was decommissioned.

Built with the Go standard library only. No third-party dependencies.

## Build

```bash
go build -o tlsee .
```

## Usage

```bash
# External host
tlsee scan example.com

# Local TLS server on a non-default port
tlsee scan localhost:8443

# Other accepted target forms
tlsee scan https://example.com
tlsee scan 127.0.0.1:8443
tlsee scan [::1]:8443

# JSON output
tlsee scan example.com --json

# Version
tlsee version
```

## Flags

`tlsee scan <target> [flags]`

| Flag          | Default | Description                                                  |
| ------------- | ------- | ------------------------------------------------------------ |
| `--port`      | `443`   | Port to use when the target omits one.                       |
| `--timeout`   | `10s`   | Dial and handshake timeout.                                  |
| `--sni`       | host    | SNI server name override (defaults to the target host).      |
| `--json`      | `false` | Emit JSON instead of text.                                   |
| `--color`     | `auto`  | Color output: `auto`, `always`, or `never`.                  |
| `--warn-days` | `30`    | Warn when the certificate expires within this many days.     |
| `--no-check`  | `false` | Skip the SAN liveness check (resolve + TCP-probe of each name).|
| `--insecure`  | `false` | Always exit `0` even when the certificate has problems.      |

Color is emitted only when `--color=always`, or when `--color=auto` and stdout
is a terminal and `NO_COLOR` is unset. JSON output is never colored.

## SAN liveness

For each DNS name in the certificate's SAN list, `tlsee` reports one of:

| State                   | Meaning                                                        |
| ----------------------- | ------------------------------------------------------------- |
| `open`                  | Resolves and every address accepts a connection on the port.  |
| `partial`               | Resolves and some addresses are reachable (e.g. IPv4 up, IPv6 down). |
| `unreachable`           | Resolves but no address accepts a connection.                 |
| `NO DNS (stale?)`       | Does not resolve at all -- likely a stale name on the cert.   |
| `wildcard (not probed)` | A `*.` name, which cannot be resolved directly.               |

Names that are `unreachable` or `NO DNS` are counted as **dead SANs** and shown
in the status headline. Each probe uses a short timeout (capped at 3s) and runs
concurrently. Dead SANs are reported but do **not** change the exit code, which
reflects the certificate's own validity. Use `--no-check` to skip the check for
a faster scan.

## Exit codes

| Code | Meaning                                                                  |
| ---- | ------------------------------------------------------------------------ |
| `0`  | Healthy: trusted chain, hostname matches, valid, and not expiring soon. Also when help is explicitly requested (`help`, `-h`, `--help`), which is written to stdout. |
| `1`  | Runtime error: bad flags, missing target, unknown command, or connection failure. |
| `2`  | Usage shown for no arguments, or a certificate problem: expired, not yet valid, untrusted, hostname mismatch, or expiring within `--warn-days`. A certificate problem is suppressed by `--insecure`. |

With `--insecure`, the certificate is still retrieved and printed; only the
exit code is forced to `0`.
