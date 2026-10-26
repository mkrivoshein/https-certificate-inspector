package org.agencyapi.x509.inspector;

import com.google.common.net.InetAddresses;
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

import static org.agencyapi.x509.inspector.IpUtils.isValidIpAddress;

/**
 * Resolves a domain's A and AAAA records and does a TLS handshake with every address, sending the domain as SNI, so
 * a server that presents a different certificate on one of its addresses is not missed. The handshakes run in
 * parallel; an address that can't be reached is reported with its error instead of failing the whole inspection.
 */
@Component
public class AddressInspector {
    private static final Logger logger = LoggerFactory.getLogger(AddressInspector.class);

    static final int PORT = 443;
    // caps the address handshakes in flight across all requests; further addresses wait for a free slot
    static final int MAX_CONCURRENT_HANDSHAKES = 32;

    private final Tracer tracer;
    private final DomainResolver domainResolver;
    private final CertificateFetcher certificateFetcher;
    private final Semaphore handshakeSlots = new Semaphore(MAX_CONCURRENT_HANDSHAKES);

    public AddressInspector(Tracer tracer, DomainResolver domainResolver, CertificateFetcher certificateFetcher) {
        this.tracer = tracer;
        this.domainResolver = domainResolver;
        this.certificateFetcher = certificateFetcher;
    }

    /**
     * Outcome of inspecting one address: exactly one of {@code handshake} and {@code error} is set.
     */
    public record AddressResult(InetAddress address, CertificateFetcher.HandshakeResult handshake, IOException error) {
        public boolean reachable() {
            return handshake != null;
        }
    }

    /**
     * @return one result per resolved address, IPv4 addresses first, in the order {@link DomainResolver} returned them
     * @throws java.net.UnknownHostException if the domain has neither A nor AAAA records
     * @throws IOException if a DNS lookup fails
     * @throws IllegalArgumentException if {@code domain} is an IP address or can't be sent as SNI
     */
    public List<AddressResult> inspect(String domain) throws IOException {
        if (isValidIpAddress(domain)) {
            throw new IllegalArgumentException("Only domain names are supported, " + domain + " looks like an IP address");
        }

        var addresses = domainResolver.resolve(domain);
        var parent = tracer.currentSpan();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var futures = addresses.stream()
                    .map(address -> executor.submit(() -> inspectAddress(parent, domain, address)))
                    .toList();
            return futures.stream().map(AddressInspector::join).toList();
        }
    }

    private AddressResult inspectAddress(Span parent, String domain, InetAddress address) {
        var span = (parent != null ? tracer.nextSpan(parent) : tracer.nextSpan())
                .name("inspect-address")
                .tag("address", InetAddresses.toAddrString(address));
        try (var withSpan = tracer.withSpan(span.start())) {
            handshakeSlots.acquire();
            try {
                return new AddressResult(address, certificateFetcher.fetchCertificate(address, domain, PORT, true), null);
            } finally {
                handshakeSlots.release();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting to inspect " + InetAddresses.toAddrString(address), e);
        } catch (IOException e) {
            logger.info("Unable to inspect {} at {}: {}", domain, InetAddresses.toAddrString(address), e.toString());
            span.error(e);
            return new AddressResult(address, null, e);
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
}
