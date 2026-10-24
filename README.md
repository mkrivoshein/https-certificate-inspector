# https-certificate-inspector

A small Spring Boot service that fetches the X.509 certificate chain presented by an HTTPS endpoint and returns key facts about each certificate as JSON.

## Requirements

- Java 25 (BellSoft Liberica). The build requires a BellSoft Java 25 toolchain; if none is installed, Gradle downloads one automatically into `~/.gradle/jdks` (via the [Foojay toolchain resolver](https://github.com/gradle/foojay-toolchains)). The first build then needs network access.

## Run locally

```bash
./gradlew bootRun       # starts the service on port 8001
./gradlew build         # compile + tests
./gradlew test          # tests only
```

## API

| Method | Path                | Description                                                                                |
|--------|---------------------|--------------------------------------------------------------------------------------------|
| GET    | `/inspect/{domain}` | Connects to `https://{domain}` and returns the certificate chain. `{domain}` is validated. |
| GET    | `/v1/domain/{hostname}/ssl` | SecurityTrails-compatible certificate lookup (see below). `/v1/domain/{hostname}/tls` is an alias. |
| GET    | `/health`           | Liveness probe; returns `OK`.                                                              |
| GET    | `/actuator/**`      | Spring Boot Actuator endpoints.                                                            |

### Example

```bash
curl http://localhost:8001/inspect/example.com
```

```json
{
  "domain": "example.com",
  "certificates": [
    {
      "subject": "CN=example.com,...",
      "issuer": "CN=...",
      "serialNumber": "...",
      "validFrom": "...",
      "validUntil": "...",
      "signatureAlgorithm": "SHA256withRSA",
      "version": 3
    }
  ]
}
```

Requests that fail domain validation return `400 Bad Request`.

### SecurityTrails-compatible endpoint

`GET /v1/domain/{hostname}/ssl` mirrors SecurityTrails' [Get Domain SSL](https://docs.securitytrails.com/) API, so a SecurityTrails client can switch by changing its base URL from `https://api.securitytrails.com/v1` to `http://<host>:8001/v1`. `GET /v1/domain/{hostname}/tls` returns the same response.

```bash
curl "http://localhost:8001/v1/domain/example.com/ssl?apikey=ignored"
```

```json
{
  "endpoint": "/v1/domain/example.com/ssl",
  "meta": {
    "max_page": 1,
    "page": 1,
    "query": {"apikey": "********", "domain": "example.com", "include_subdomains": "False", "page": "1", "status": "valid"},
    "total_pages": 1
  },
  "record_count": 1,
  "records": [
    {
      "dns_names": ["*.example.com", "example.com"],
      "fingerprints": {"sha1": "899CB259...", "sha256": "85CA6AB0..."},
      "issuer": {"common_name": "...", "country": ["US"], "organization": ["..."]},
      "not_after": 1798239395,
      "not_before": 1790462951,
      "serial_number": "2569673129085639595562975411803018896",
      "subject": {"common_name": "example.com"}
    }
  ]
}
```

This service **keeps no history**: it does a live TLS handshake and only sees the certificate the server presents right now. Compared to SecurityTrails:

| Parameter / field    | Behaviour here                                                                                                   |
|----------------------|------------------------------------------------------------------------------------------------------------------|
| `apikey`             | Accepted and ignored (no authentication). Echoed as `********` in `meta.query`, never in clear.                  |
| `status`             | `valid` (default), `expired`, `all`; applied to the live certificate only, so past certificates never appear.    |
| `include_subdomains` | Only `false` is supported; `true` returns `400`.                                                                 |
| `page`               | Query parameter or JSON body. There is at most one record, so page 1 holds it and later pages are empty.         |
| `records`            | The leaf certificate, if it matches `{hostname}` (including wildcards) and `status`; otherwise empty.            |
| Errors               | `400` for invalid input, `502` when the certificate can't be retrieved, `504` on timeout; all `{"message": ...}`. |

## Observability

Tracing is enabled via Micrometer Tracing with the OpenTelemetry bridge. Trace and span IDs are included in every log line. This README does not guarantee that spans are exported via OTLP by default; verify the runtime OpenTelemetry exporter configuration before relying on remote span export.

## Container image

The image is built with [Jib](https://github.com/GoogleContainerTools/jib) on top of `bellsoft/liberica-runtime-container:jre-25-glibc` and published by CI to:

```
europe-docker.pkg.dev/agencyapi/containers/https-certificate-inspector
```

Publishing requires GCP credentials and is handled by the GitHub Actions pipeline; do not run `./gradlew jib` locally without explicit registry access.

## License

See [LICENSE](LICENSE).
