# AGENTS.md

Guidance for AI agents (e.g. Claude Code) working in this repository. Read [README.md](README.md) first for the user-facing overview, API, and run instructions; this file only covers things that aren't obvious from the README or the code.

## Layout

All Java sources live under `src/main/java/org/agencyapi/x509/inspector/`:

| Path | Purpose |
|------|---------|
| `CertificateInspector.java` | Spring Boot entry point. |
| `CertificateInspectorController.java` | REST controller. Owns the `inspect` span and exception → 400 mapping. |
| `CertificateInspectorReply.java` | Response record + nested `CertificateInfo` projection of `X509Certificate`. |
| `CertificateFetcher.java` / `CertificateUtils.java` / `IpUtils.java` | Certificate retrieval and helpers. |
| `OpenTelemetryConfig.java` | Tracing wiring. |
| `validators/` | Jakarta `ConstraintValidator` implementations (e.g. `@Domain`). |
| `src/main/resources/application.yml` | Port `8001`, OTLP endpoint, log pattern with `traceId`/`spanId`. |

There is no `src/test/` yet — when adding tests, use JUnit 5 (already on the classpath via `spring-boot-starter-test`).

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
