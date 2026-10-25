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

Plain filesystem paths, absolute or relative to the working directory, are resolved to absolute `file:` resource URLs. `classpath:`, `https:` and explicit `file:` URLs are passed through to the Spring Boot SSL bundle; plain `http:` locations are rejected.

When all TLS material lives on the filesystem, the bundle is configured with `reload-on-update`, so replacing the files on disk (e.g. cert-manager or a mounted Kubernetes secret) is picked up by the running server without a restart, after Spring Boot's ~10 second quiet period. Material loaded from `classpath:` or `https:` cannot be watched and is only read at startup.

When TLS is configured, the app checks the certificates the server is actually using (the live `inspector` SSL bundle, including any hot-reloaded material) immediately and then every 5 minutes, using a daemon scheduled executor named `inspector-cert-expiry-monitor`. If the server certificate, or any client CA certificate when mTLS is enabled, expires within 10 minutes of the check, the process exits with a non-zero status so the container supervisor can restart it. This is a last resort for material that was not rotated in time: an expired certificate left in place, including a stale CA in the client CA file, will make the container restart repeatedly until it is replaced.

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
