# https-certificate-inspector

A small Spring Boot service that connects to an HTTPS endpoint, reads the X.509 certificates it presents, and returns key facts about them as JSON. It offers two APIs:

- `/inspect/{domain}`: the full certificate chain, in this service's own format.
- `/v1/domain/{hostname}/ssl`: the domain's certificate in the same format as SecurityTrails' Get Domain SSL API, so SecurityTrails clients can switch to this service by changing their base URL.

Certificates are read live on every request; the service keeps no history.

## Requirements

- Java 25 (BellSoft Liberica). The build requires a BellSoft Java 25 toolchain; if none is installed, Gradle downloads one automatically into `~/.gradle/jdks` (via the [Foojay toolchain resolver](https://github.com/gradle/foojay-toolchains)). The first build then needs network access.

## Run locally

```bash
./gradlew bootRun       # starts the service on port 8001
./gradlew build         # compile + tests
./gradlew test          # tests only
```

## API

| Method | Path                        | Description                                                                                       |
|--------|-----------------------------|---------------------------------------------------------------------------------------------------|
| GET    | `/inspect/{domain}`         | Connects to `https://{domain}` and returns the certificate chain. `{domain}` is validated.        |
| GET    | `/v1/domain/{hostname}/ssl` | SecurityTrails-compatible lookup of the domain's certificate (see below).                         |
| GET    | `/v1/domain/{hostname}/tls` | Alias of `/v1/domain/{hostname}/ssl`; same response.                                              |
| GET    | `/health`                   | Liveness probe; returns `OK`.                                                                     |
| GET    | `/actuator/**`              | Spring Boot Actuator endpoints.                                                                   |

### `/inspect/{domain}`

Returns every certificate the server presents (the domain's certificate followed by any intermediates).

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

Requests that fail domain validation return `400 Bad Request` with a plain-text message.

### `/v1/domain/{hostname}/ssl` (SecurityTrails-compatible)

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

## HTTPS and mTLS

By default the service listens on plain HTTP (port 8001). If a server certificate and private key are provided at startup, HTTPS is enabled. If a client CA is also provided, the app requires client certificates and verifies them against that CA.

### Settings

Each setting can be given as a Spring property (e.g. `--inspector.tls.certificate=...` or in `application.yml`) or as an environment variable. If more than one is set, the first non-blank value in the order listed wins.

| Property | Environment variables | Required | Description |
|----------|-----------------------|----------|-------------|
| `inspector.tls.certificate` | `INSPECTOR_TLS_CERTIFICATE`, `INSPECTOR_TLS_CERT` | For HTTPS | Server certificate (PEM). The first certificate is the one presented to clients; any following ones are sent as the chain. |
| `inspector.tls.private-key` | `INSPECTOR_TLS_PRIVATE_KEY`, `INSPECTOR_TLS_KEY` | For HTTPS | Unencrypted PEM private key matching the server certificate. |
| `inspector.tls.client-ca` | `INSPECTOR_TLS_CLIENT_CA` | No | PEM file with one or more CA certificates. Enables mTLS: clients must present a certificate signed by one of these CAs. |

The resulting mode:

| Settings supplied | Result |
|-------------------|--------|
| None | Plain HTTP |
| Certificate + private key | HTTPS |
| Certificate + private key + client CA | HTTPS with mandatory client certificates (mTLS) |
| Any other combination (e.g. only a certificate, or only a client CA) | Startup fails with `IllegalStateException` |

Accepted location formats for all three settings:

| Format | Example | Notes |
|--------|---------|-------|
| Absolute path | `/run/tls/server.crt` | Converted to a `file:` URL; can be hot-reloaded. |
| Relative path | `tls/server.crt` | Resolved against the process working directory, then as above. |
| `file:` URL | `file:///run/tls/server.crt` | Can be hot-reloaded. |
| `classpath:` resource | `classpath:tls/server.crt` | Read once at startup. |
| `https:` URL | `https://example.com/server.crt` | Read once at startup. |
| `http:` URL | — | Rejected at startup: TLS material must not be fetched in plain text. |

### Examples

HTTPS:

```bash
INSPECTOR_TLS_CERT=/run/tls/server.crt \
INSPECTOR_TLS_KEY=/run/tls/server.key \
./gradlew bootRun
```

mTLS:

```bash
INSPECTOR_TLS_CERT=/run/tls/server.crt \
INSPECTOR_TLS_KEY=/run/tls/server.key \
INSPECTOR_TLS_CLIENT_CA=/run/tls/client-ca.crt \
./gradlew bootRun
```

Docker can publish a different host port while the app still listens on container port `8001`:

```bash
docker run -p 8443:8001 \
  -e INSPECTOR_TLS_CERT=/run/tls/server.crt \
  -e INSPECTOR_TLS_KEY=/run/tls/server.key \
  -e INSPECTOR_TLS_CLIENT_CA=/run/tls/client-ca.crt \
  -v /host/tls:/run/tls:ro \
  europe-docker.pkg.dev/agencyapi/containers/https-certificate-inspector
```

### Certificate rotation

When every configured location is on the filesystem, replacing the files on disk (e.g. via cert-manager or a mounted Kubernetes secret) is picked up by the running server without a restart, after Spring Boot's ~10 second quiet period. Replace the certificate and key together. Material loaded from `classpath:` or `https:` cannot be watched and is only read at startup.

### Expiry monitor

When TLS is configured, the app checks the certificates the server is actually using (including hot-reloaded ones) at startup and then every 5 minutes, on a daemon thread named `inspector-cert-expiry-monitor`. If the server certificate, or any client CA certificate when mTLS is enabled, expires within 10 minutes of a check, or the certificates cannot be read, the process exits with status `1` so the container supervisor can restart it.

This is a last resort for material that was not rotated in time. An expired certificate left in place, including a stale CA in the client CA file, makes the container restart repeatedly until it is replaced. The 5 minute interval and 10 minute window are fixed and not configurable.

### Spring Boot properties set by the app

The settings above are translated at startup into the Spring Boot properties below. They take precedence over the same properties set anywhere else, so set the `inspector.tls.*` values rather than these.

| Spring Boot property | Value | When |
|----------------------|-------|------|
| `server.ssl.enabled` | `true` | HTTPS |
| `server.ssl.bundle` | `inspector` | HTTPS |
| `spring.ssl.bundle.pem.inspector.keystore.certificate` | `inspector.tls.certificate` | HTTPS |
| `spring.ssl.bundle.pem.inspector.keystore.private-key` | `inspector.tls.private-key` | HTTPS |
| `spring.ssl.bundle.pem.inspector.truststore.certificate` | `inspector.tls.client-ca` | mTLS |
| `server.ssl.client-auth` | `need` | mTLS |
| `spring.ssl.bundle.pem.inspector.reload-on-update` | `true` | All locations are filesystem paths or `file:` URLs |

## Observability

Tracing is enabled via Micrometer Tracing with the OpenTelemetry bridge. Each request runs in its own span (`inspect` for `/inspect/{domain}`, `domain-ssl` for `/v1/domain/{hostname}/ssl` and `/tls`), and trace and span IDs are included in every log line. This README does not guarantee that spans are exported via OTLP by default; verify the runtime OpenTelemetry exporter configuration before relying on remote span export.

## Container image

The image is built with [Jib](https://github.com/GoogleContainerTools/jib) on top of `bellsoft/liberica-runtime-container:jre-25-glibc` and published by CI to:

```
europe-docker.pkg.dev/agencyapi/containers/https-certificate-inspector
```

Publishing requires GCP credentials and is handled by the GitHub Actions pipeline; do not run `./gradlew jib` locally without explicit registry access.

## License

See [LICENSE](LICENSE).
