# https-certificate-inspector

A small Spring Boot service that fetches the X.509 certificate chain presented by an HTTPS endpoint and returns key facts about each certificate as JSON.

## Requirements

- Java 25 (Adoptium). The Gradle toolchain will download it automatically if it's not already available.

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

## HTTPS and mTLS

By default the service listens on plain HTTP (port 8001). If a server certificate and private key are provided at startup, HTTPS is enabled. If a client CA is also provided, the app requires client certificates and verifies them against that CA.

| Property | Environment aliases | Description |
|----------|---------------------|-------------|
| `inspector.tls.certificate` | `INSPECTOR_TLS_CERTIFICATE`, `INSPECTOR_TLS_CERT` | Server certificate path/resource |
| `inspector.tls.private-key` | `INSPECTOR_TLS_PRIVATE_KEY`, `INSPECTOR_TLS_KEY` | Server private key path/resource |
| `inspector.tls.client-ca` | `INSPECTOR_TLS_CLIENT_CA` | Client CA path/resource; enables mTLS |

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

Absolute filesystem paths are converted to `file:` resource URLs automatically. Relative paths, `classpath:`, and explicit `file:` URLs are passed through to Spring Boot SSL bundles. TLS material is loaded at startup, so rotating any of these files on disk requires restarting the app/container.

When TLS is configured, the app checks the server certificate, and the client CA when present, immediately and then every 5 minutes using a daemon scheduled executor named `inspector-cert-expiry-monitor`. If any checked certificate expires within 10 minutes of the check time, the process exits with a non-zero status so the container supervisor can restart it and pick up fresh TLS material.

## Observability

Tracing is enabled via Micrometer Tracing with the OpenTelemetry bridge. Trace and span IDs are included in every log line. This README does not guarantee that spans are exported via OTLP by default; verify the runtime OpenTelemetry exporter configuration before relying on remote span export.

## Container image

The image is built with [Jib](https://github.com/GoogleContainerTools/jib) on top of `eclipse-temurin:25-noble` and published by CI to:

```
europe-docker.pkg.dev/agencyapi/containers/https-certificate-inspector
```

Publishing requires GCP credentials and is handled by the GitHub Actions pipeline; do not run `./gradlew jib` locally without explicit registry access.

## License

See [LICENSE](LICENSE).
