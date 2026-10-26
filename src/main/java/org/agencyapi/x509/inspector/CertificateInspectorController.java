package org.agencyapi.x509.inspector;

import com.google.common.net.InetAddresses;
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
import java.net.UnknownHostException;
import java.util.stream.Collectors;

@RestController
@Validated
public class CertificateInspectorController {
    private static final Logger logger = LoggerFactory.getLogger(CertificateInspectorController.class);

    private final Tracer tracer;
    private final AddressInspector addressInspector;

    public CertificateInspectorController(Tracer tracer, AddressInspector addressInspector) {
        this.tracer = tracer;
        this.addressInspector = addressInspector;
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    String handleConstraintViolationException(ConstraintViolationException e) {
        logger.warn("Input validation error: " + e.getMessage());
        return "Input validation error: " + e.getMessage();
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    String handleIllegalArgumentException(IllegalArgumentException e) {
        logger.warn("Bad request: " + e.getMessage());
        return e.getMessage();
    }

    @ExceptionHandler(UnknownHostException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    String handleUnknownHostException(UnknownHostException e) {
        logger.warn(e.getMessage());
        return e.getMessage();
    }

    @ExceptionHandler(IOException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    String handleIOException(IOException e) {
        logger.warn(e.getMessage(), e);
        return e.getMessage();
    }

    /**
     * Inspects the certificate chain presented by every A and AAAA address of the domain. Responds 502 when no address
     * completes a handshake.
     */
    @GetMapping("/inspect/{domain}")
    @SuppressWarnings("unused")
    public CertificateInspectorReply sslTest(@PathVariable("domain") @Domain String domain) throws IOException {
        var newSpan = tracer.nextSpan().name("inspect");
        try (var withSpan = tracer.withSpan(newSpan.start())) {
            logger.info("SSL test query for {}", domain);
            var results = addressInspector.inspect(domain);
            if (results.stream().noneMatch(AddressInspector.AddressResult::reachable)) {
                throw new IOException("Unable to retrieve certificates from any address of " + domain + ": " + results.stream()
                        .map(result -> InetAddresses.toAddrString(result.address()) + " " + result.error().getMessage())
                        .collect(Collectors.joining("; ")));
            }
            results.stream()
                    .filter(AddressInspector.AddressResult::reachable)
                    .findFirst()
                    .ifPresent(result -> result.handshake().certificates().forEach(CertificateUtils::printCertificateDetails));
            return CertificateInspectorReply.create(domain, results);
        } catch (IOException | RuntimeException e) {
            newSpan.error(e);
            throw e;
        } finally {
            newSpan.end();
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }
}
