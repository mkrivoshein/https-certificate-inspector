package org.agencyapi.x509.inspector;

import com.google.common.net.InetAddresses;
import io.micrometer.tracing.Span;
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
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.agencyapi.x509.inspector.IpUtils.isValidIpAddress;

@RestController
@Validated
public class CertificateInspectorController {
    private static final Logger logger = LoggerFactory.getLogger(CertificateInspectorController.class);

    private final Tracer tracer;
    private final CertificateFetcher certificateFetcher;
    private final DomainResolver domainResolver;

    public CertificateInspectorController(Tracer tracer, CertificateFetcher certificateFetcher, DomainResolver domainResolver) {
        this.tracer = tracer;
        this.certificateFetcher = certificateFetcher;
        this.domainResolver = domainResolver;
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

    @GetMapping("/inspect/{domain}")
    @SuppressWarnings("unused")
    public CertificateInspectorReply sslTest(@PathVariable("domain") @Domain String domain) {
        var newSpan = tracer.nextSpan().name("inspect");
        try (var withSpan = tracer.withSpan(newSpan.start())) {
            logger.info("SSL test query for {}", domain);
            var certificates = certificateFetcher.fetchCertificate("https://" + domain, true);
            var ocspStaplingEnabled = certificateFetcher.checkOcspStapling(domain, 443, true);
            certificates.forEach(CertificateUtils::printCertificateDetails);
            return CertificateInspectorReply.create(domain, certificates, ocspStaplingEnabled);
        } catch (IOException|URISyntaxException e) {
            throw new RuntimeException("Unable to handle SSL test for " + domain);
        } finally {
            newSpan.end();
        }
    }

    /**
     * Resolves the domain's A and AAAA records and inspects the certificate chain each address presents, sending the
     * domain as SNI. The handshakes run in parallel; an address that can't be reached is reported with an error
     * instead of failing the request.
     */
    @GetMapping("/inspect/{domain}/addresses")
    @SuppressWarnings("unused")
    public AddressInspectorReply inspectAddresses(@PathVariable("domain") @Domain String domain) throws IOException {
        var newSpan = tracer.nextSpan().name("inspect-addresses");
        try (var withSpan = tracer.withSpan(newSpan.start())) {
            logger.info("Address inspection query for {}", domain);
            if (isValidIpAddress(domain)) {
                throw new IllegalArgumentException("Only domain names are supported, " + domain + " looks like an IP address");
            }

            var addresses = domainResolver.resolve(domain);
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                var futures = addresses.stream()
                        .map(address -> executor.submit(() -> inspectAddress(newSpan, domain, address)))
                        .toList();
                return new AddressInspectorReply(domain, futures.stream().map(CertificateInspectorController::join).toList());
            }
        } catch (IOException | RuntimeException e) {
            newSpan.error(e);
            throw e;
        } finally {
            newSpan.end();
        }
    }

    private AddressInspectorReply.AddressInfo inspectAddress(Span parent, String domain, InetAddress address) {
        var span = tracer.nextSpan(parent).name("inspect-address").tag("address", InetAddresses.toAddrString(address));
        try (var withSpan = tracer.withSpan(span.start())) {
            var result = certificateFetcher.fetchCertificate(address, domain, 443, true);
            return AddressInspectorReply.AddressInfo.inspected(address, result);
        } catch (IOException e) {
            logger.info("Unable to inspect {} at {}: {}", domain, InetAddresses.toAddrString(address), e.toString());
            span.error(e);
            return AddressInspectorReply.AddressInfo.failed(address, e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        } finally {
            span.end();
        }
    }

    private static <T> T join(Future<T> future) {
        try {
            return future.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while inspecting addresses", e);
        } catch (ExecutionException e) {
            throw e.getCause() instanceof RuntimeException runtime ? runtime : new IllegalStateException(e.getCause());
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }
}
