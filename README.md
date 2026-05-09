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

Invalid domains return `400 Bad Request`.

## Observability

Tracing is enabled via Micrometer Tracing with the OpenTelemetry bridge. Spans are exported via OTLP to `http://localhost:4317` by default (see `src/main/resources/application.yml`). Trace and span IDs are included in every log line.

## Container image

The image is built with [Jib](https://github.com/GoogleContainerTools/jib) on top of `eclipse-temurin:25-noble` and published by CI to:

```
europe-docker.pkg.dev/agencyapi/containers/https-certificate-inspector
```

Publishing requires GCP credentials and is handled by the GitHub Actions pipeline; do not run `./gradlew jib` locally without explicit registry access.

## License

See [LICENSE](LICENSE).
