# AGENTS.md

Guidance for AI agents (e.g. Claude Code) working in this repository. Read [README.md](README.md) first for the user-facing overview, API, and run instructions; this file only covers things that aren't obvious from the README or the code.

## Layout

All Java sources live under `src/main/java/org/agencyapi/x509/inspector/`:

| Path | Purpose |
|------|---------|
| `CertificateInspector.java` | Spring Boot entry point. |
| `CertificateInspectorController.java` | REST controller for `/inspect/{domain}`. Owns the `inspect` span and the exception → status mapping. |
| `CertificateInspectorReply.java` | Response record + nested `CertificateInfo` projection of `X509Certificate` and per-address `AddressInfo`. |
| `AddressInspector.java` | Resolves A/AAAA records and handshakes with every address in parallel (capped across requests); used by both controllers. Owns the per-address `inspect-address` spans. |
| `DomainResolver.java` | A/AAAA lookups with dnsjava, so every published address is inspected; falls back to the OS resolver when dnsjava can't resolve the name. |
| `DomainSslController.java` / `DomainSslReply.java` | SecurityTrails-compatible `/v1/domain/{hostname}/ssl` (and `/tls`) endpoint and its snake_case response records. Owns the `domain-ssl` span. |
| `CertificateFetcher.java` / `CertificateUtils.java` / `IpUtils.java` | Certificate retrieval and helpers. Connecting to a specific IP goes through an `SSLSocket` with explicit SNI: `HttpsURLConnection` sends no SNI when the URL host is an IP address. |
| `OpenTelemetryConfig.java` | Tracing wiring. |
| `validators/` | Jakarta `ConstraintValidator` implementations (e.g. `@Domain`). |
| `config/ConditionalTlsEnvironmentPostProcessor.java` | Flips Spring's HTTPS/mTLS settings on at startup if TLS properties are supplied. |
| `config/ServerCertificateExpiryMonitor.java` | Daemon that exits the app if any certificate in the live `inspector` SSL bundle is within 10 min of expiry. |
| `config/TlsConfigurationProperties.java` | Package-private helper resolving `inspector.tls.*` from properties or env vars. |
| `src/main/resources/application.yml` | Port `8001`, OTLP endpoint, log pattern with `traceId`/`spanId`. |
| `src/main/resources/META-INF/spring.factories` | Registers `ConditionalTlsEnvironmentPostProcessor`. |

Tests live under `src/test/` and use JUnit 5 + AssertJ (via `spring-boot-starter-test`); public fixture certificates for the inspection endpoints are in `src/test/resources/certificates/`.

## HTTP, HTTPS, and mTLS

Plain HTTP when no TLS settings are present. Supplying both a server certificate and private key enables HTTPS; adding a client CA enables mTLS (`server.ssl.client-auth=need`). See README "HTTPS and mTLS" for the property/env table and examples.

When changing this code, keep the following invariants:

- The post-processor must throw `IllegalStateException` if `certificate` or `private-key` is missing while any TLS setting is present — partial TLS config is never silently ignored.
- The Spring SSL bundle name is `inspector` (`spring.ssl.bundle.pem.inspector.*`); changing it requires updating tests and any external SSL bundle references.
- `ServerCertificateExpiryMonitor` reads certificates from `SslBundles`, never from disk, so it checks what the server is actually serving after a hot reload.
- Filesystem TLS locations are normalized to absolute `file:` URIs, and `reload-on-update` is enabled only when every location is a `file:` URI (Spring Boot cannot watch `classpath:`/`https:` content).
- `ServerCertificateExpiryMonitor` must call `System.exit` (via `SpringApplication.exit`) — graceful return defeats the container-restart-on-expiry contract.
- Don't commit private keys or real deployment TLS material. Public test certificates are fine; tests that need a key pair (e.g. the expiry monitor) generate throwaway material with the JDK's `keytool` into a JUnit `@TempDir`.

## Coding conventions

- Java 25; prefer `var`, records, sealed types, pattern matching where it improves clarity.
- Spring constructor injection only — no field `@Autowired`.
- Input validation uses Jakarta constraints; put new annotations in the `validators` package and surface violations via the existing `ConstraintViolationException` handler in the controller.
- Keep the `inspect` span (and any new spans) — observability is a hard requirement, not decoration.
- Don't hand-edit dependency versions that Dependabot manages (Spring Boot, Jib, dnsjava); let the bot raise PRs.

## CI / GitHub Actions

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push / PR | Build and test |
| `publish.yml` | Push to `main` | Build and push container image |
| `release.yml` | Tag | Cut a release |
| `dependency-review.yml` | PR | Check for vulnerable dependencies |
| `dependency-submission.yml` | Push | Submit dependency graph to GitHub |

Secrets (`GOOGLE_CREDENTIALS`, etc.) live in GitHub Actions — never hard-code or echo them.

## Things to leave alone unless asked

- The Artifact Registry coordinates and Jib `to.image` in `build.gradle`.
- The OTLP endpoint default in `application.yml` (`http://localhost:4317`) — keep this local-dev/default endpoint as configured, but do not assume it means OTLP span exporting is wired by default.
- Port `8001` — referenced from the container config and external callers.
