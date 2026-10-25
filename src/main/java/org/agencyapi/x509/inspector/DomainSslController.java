package org.agencyapi.x509.inspector;

import io.micrometer.tracing.Tracer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.agencyapi.x509.inspector.validators.Domain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * SecurityTrails-compatible "Get Domain SSL" endpoint, so SecurityTrails clients can switch by changing their base URL.
 * Certificates come from a live TLS handshake: no history is kept, so only the certificate currently served is returned.
 */
@RestController
@Validated
public class DomainSslController {
    private static final Logger logger = LoggerFactory.getLogger(DomainSslController.class);

    static final String MASKED_API_KEY = "********";

    private final Tracer tracer;
    private final CertificateFetcher certificateFetcher;

    public DomainSslController(Tracer tracer, CertificateFetcher certificateFetcher) {
        this.tracer = tracer;
        this.certificateFetcher = certificateFetcher;
    }

    record ErrorReply(String message) {
    }

    record PageRequest(Integer page) {
    }

    static final class UpstreamException extends RuntimeException {
        private final HttpStatus status;

        UpstreamException(HttpStatus status, String message, Throwable cause) {
            super(message, cause);
            this.status = status;
        }
    }

    @ExceptionHandler(ConstraintViolationException.class)
    ResponseEntity<ErrorReply> handleConstraintViolationException(ConstraintViolationException e) {
        logger.warn("Input validation error: " + e.getMessage());
        var message = e.getConstraintViolations().stream()
                .map(ConstraintViolation::getMessage)
                .collect(Collectors.joining("; "));
        return badRequest(message);
    }

    @ExceptionHandler({IllegalArgumentException.class, MethodArgumentTypeMismatchException.class, HttpMessageNotReadableException.class})
    ResponseEntity<ErrorReply> handleBadRequest(Exception e) {
        logger.warn("Bad request: " + e.getMessage());
        return badRequest(e instanceof MethodArgumentTypeMismatchException mismatch
                ? "Invalid value for parameter " + mismatch.getName()
                : e instanceof HttpMessageNotReadableException ? "Invalid request body" : e.getMessage());
    }

    @ExceptionHandler(UpstreamException.class)
    ResponseEntity<ErrorReply> handleUpstreamException(UpstreamException e) {
        logger.warn(e.getMessage(), e.getCause());
        return ResponseEntity.status(e.status).body(new ErrorReply(e.getMessage()));
    }

    @GetMapping({"/v1/domain/{hostname}/ssl", "/v1/domain/{hostname}/tls"})
    @SuppressWarnings("unused")
    public DomainSslReply domainSsl(@PathVariable("hostname") @Domain String hostname,
                                    @RequestParam(name = "apikey", required = false) String apiKey,
                                    @RequestParam(name = "include_subdomains", defaultValue = "false") boolean includeSubdomains,
                                    @RequestParam(name = "status", defaultValue = "valid") String status,
                                    @RequestParam(name = "page", required = false) Integer page,
                                    @RequestBody(required = false) PageRequest pageRequest,
                                    HttpServletRequest request) {
        var newSpan = tracer.nextSpan().name("domain-ssl");
        try (var withSpan = tracer.withSpan(newSpan.start())) {
            logger.info("Domain SSL query for {}", hostname);

            var certificateStatus = DomainSslReply.Status.parse(status);
            if (includeSubdomains) {
                throw new IllegalArgumentException("include_subdomains is not supported");
            }
            var requestedPage = page != null ? page : pageRequest != null && pageRequest.page() != null ? pageRequest.page() : 1;
            if (requestedPage < 1) {
                throw new IllegalArgumentException("page must be 1 or greater");
            }

            var query = new DomainSslReply.Query(
                    apiKey == null ? null : MASKED_API_KEY,
                    hostname,
                    includeSubdomains ? "True" : "False",
                    String.valueOf(requestedPage),
                    certificateStatus.value());

            // everything fits on the first page, later pages are empty
            var certificates = requestedPage == 1
                    ? fetchLeafCertificate(hostname, certificateStatus)
                    : List.<X509Certificate>of();
            return DomainSslReply.create(request.getRequestURI(), query, requestedPage, certificates);
        } catch (RuntimeException e) {
            newSpan.error(e);
            throw e;
        } finally {
            newSpan.end();
        }
    }

    private List<X509Certificate> fetchLeafCertificate(String hostname, DomainSslReply.Status status) {
        List<X509Certificate> chain;
        try {
            chain = certificateFetcher.fetchCertificate("https://" + hostname, true);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("The requested domain has invalid characters", e);
        } catch (SocketTimeoutException e) {
            throw new UpstreamException(HttpStatus.GATEWAY_TIMEOUT, "Timed out connecting to " + hostname, e);
        } catch (IOException e) {
            throw new UpstreamException(HttpStatus.BAD_GATEWAY, "Unable to retrieve certificate from " + hostname, e);
        }

        // the server presents the leaf certificate first, followed by intermediates
        return chain.stream()
                .limit(1)
                .filter(cert -> CertificateUtils.verifyCertificateForDomain(cert, hostname))
                .filter(cert -> status.matches(cert, Instant.now()))
                .toList();
    }

    private static ResponseEntity<ErrorReply> badRequest(String message) {
        return ResponseEntity.badRequest().body(new ErrorReply(message));
    }
}
