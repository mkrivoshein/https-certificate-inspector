package org.agencyapi.x509.inspector;

import io.micrometer.tracing.Tracer;
import jakarta.validation.ConstraintViolationException;
import org.agencyapi.x509.inspector.validators.Domain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URISyntaxException;

@RestController
@Validated
public class CertificateInspectorController {
    private static final Logger logger = LoggerFactory.getLogger(CertificateInspectorController.class);

    private final Tracer tracer;
    private final CertificateFetcher certificateFetcher;

    public CertificateInspectorController(Tracer tracer, CertificateFetcher certificateFetcher) {
        this.tracer = tracer;
        this.certificateFetcher = certificateFetcher;
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    String handleConstraintViolationException(ConstraintViolationException e) {
        logger.warn("Input validation error: " + e.getMessage());
        return "Input validation error: " + e.getMessage();
    }

    @GetMapping("/inspect/{domain}")
    @SuppressWarnings("unused")
    public CertificateInspectorReply sslTest(@PathVariable("domain") @Domain String domain) {
        var newSpan = tracer.nextSpan().name("inspect");
        try (var withSpan = tracer.withSpan(newSpan.start())) {
            logger.info("SSL test query for {}", domain);
            var certificates = certificateFetcher.fetchCertificate("https://" + domain, true);
            certificates.forEach(CertificateUtils::printCertificateDetails);
            return CertificateInspectorReply.create(domain, certificates);
        } catch (IOException|URISyntaxException e) {
            throw new RuntimeException("Unable to handle SSL test for " + domain);
        } finally {
            newSpan.end();
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }
}
