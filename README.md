# clientcert processor

[![CI](https://github.com/danielwegener/otelcol-processor-clientcert/actions/workflows/ci.yml/badge.svg)](https://github.com/danielwegener/otelcol-processor-clientcert/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/danielwegener/otelcol-processor-clientcert.svg)](https://pkg.go.dev/github.com/danielwegener/otelcol-processor-clientcert)
[![Go Report Card](https://goreportcard.com/badge/github.com/danielwegener/otelcol-processor-clientcert)](https://goreportcard.com/report/github.com/danielwegener/otelcol-processor-clientcert)
[![codecov](https://codecov.io/gh/danielwegener/otelcol-processor-clientcert/branch/main/graph/badge.svg)](https://codecov.io/gh/danielwegener/otelcol-processor-clientcert)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Extracts mTLS peer certificate fields from the gRPC connection context and writes them as resource attributes on every telemetry signal (traces, metrics, logs, profiles) passing through the pipeline.

Because the values come from the server-verified TLS handshake, they cannot be forged by the sending process — unlike application-asserted resource attributes such as `service.instance.id`.

| Signal   | Supported |
|----------|-----------|
| Traces   | ✓         |
| Metrics  | ✓         |
| Logs     | ✓         |

## Configuration

```yaml
processors:
  clientcert:
    # Certificate fields to extract. All writes use upsert semantics so a
    # client-asserted attribute with the same key is always overwritten.
    attributes:
      - target_key: tls.client.cn           # resource attribute to write
        source: subject_cn                  # field to read from the cert
      - target_key: tls.client.san
        source: subject_alt_names
      - target_key: tls.client.fingerprint
        source: sha256_fingerprint

    # What to do when no peer certificate is present (plaintext or server-only TLS).
    # passthrough (default) | drop | error
    on_missing_cert: passthrough
```

### `source` values

| Value               | Content                                         |
|---------------------|-------------------------------------------------|
| `subject_cn`        | `Subject.CommonName`                            |
| `subject_alt_names` | DNS SANs, IP SANs, and email SANs, comma-joined |
| `issuer_cn`         | `Issuer.CommonName`                             |
| `issuer_org`        | `Issuer.Organization[0]`                        |
| `sha256_fingerprint`| Hex-encoded SHA-256 of the DER-encoded cert     |
| `serial_number`     | Decimal serial number                           |
| `not_after`         | RFC3339 expiry timestamp (UTC)                  |

### `on_missing_cert` values

| Value         | Behaviour                                                           |
|---------------|---------------------------------------------------------------------|
| `passthrough` | Signal passes through unchanged (default)                           |
| `drop`        | Signal is discarded; no error returned to sender                    |
| `error`       | Error is returned to sender; signal is not forwarded                |

## Pipeline wiring

Place the processor immediately after the mTLS receiver so the gRPC peer context is still intact:

```yaml
receivers:
  otlp/mtls:
    protocols:
      grpc:
        endpoint: 0.0.0.0:54317
        tls:
          cert_file: /etc/certs/server.crt
          key_file: /etc/certs/server.key
          client_ca_file: /etc/certs/ca.crt

processors:
  clientcert:
    attributes:
      - target_key: tls.client.cn
        source: subject_cn
  memory_limiter: ...
  batch: ...

service:
  pipelines:
    traces:
      receivers: [otlp/mtls]
      processors: [clientcert, memory_limiter, batch]
      exporters: [otlp/jaeger]
```

## Use with OCB

Add to your `builder-config.yaml`:

```yaml
processors:
  - gomod: github.com/danielwegener/otelcol-processor-clientcert v0.1.0
```

## Scope

Only gRPC receivers are supported. The processor reads the peer certificate via
`google.golang.org/grpc/peer.FromContext` and `credentials.TLSInfo`; it has no
effect on signals received over plain HTTP/2 or plaintext transports.
