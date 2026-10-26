package org.agencyapi.x509.inspector;

import io.micrometer.tracing.Tracer;
import org.junit.jupiter.api.Test;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.agencyapi.x509.inspector.TestCertificates.leaf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AddressInspectorTest {
    private final DomainResolver domainResolver = mock(DomainResolver.class);
    private final CertificateFetcher certificateFetcher = mock(CertificateFetcher.class);
    private final AddressInspector inspector = new AddressInspector(Tracer.NOOP, domainResolver, certificateFetcher);

    @Test
    void returnsOneResultPerAddressInResolverOrder() throws Exception {
        var first = address("192.0.2.1");
        var second = address("2001:db8::1");
        when(domainResolver.resolve("example.com")).thenReturn(List.of(first, second));
        when(certificateFetcher.fetchCertificate(eq(first), anyString(), anyInt(), anyBoolean()))
                .thenThrow(new ConnectException("Connection refused"));
        when(certificateFetcher.fetchCertificate(eq(second), anyString(), anyInt(), anyBoolean()))
                .thenReturn(new CertificateFetcher.HandshakeResult(List.of(leaf()), true));

        var results = inspector.inspect("example.com");

        assertThat(results).extracting(AddressInspector.AddressResult::address).containsExactly(first, second);
        assertThat(results.get(0).reachable()).isFalse();
        assertThat(results.get(0).error()).hasMessage("Connection refused");
        assertThat(results.get(1).reachable()).isTrue();
        assertThat(results.get(1).handshake().ocspStapled()).isTrue();
    }

    @Test
    void limitsConcurrentHandshakesButInspectsEveryAddress() throws Exception {
        var addresses = IntStream.rangeClosed(1, AddressInspector.MAX_CONCURRENT_HANDSHAKES + 8)
                .mapToObj(i -> address("192.0.2." + i))
                .toList();
        when(domainResolver.resolve("example.com")).thenReturn(addresses);
        var inFlight = new AtomicInteger();
        var maxInFlight = new AtomicInteger();
        when(certificateFetcher.fetchCertificate(any(InetAddress.class), anyString(), anyInt(), anyBoolean())).thenAnswer(_ -> {
            maxInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
            Thread.sleep(50);
            inFlight.decrementAndGet();
            return new CertificateFetcher.HandshakeResult(List.of(leaf()), false);
        });

        assertThat(inspector.inspect("example.com")).hasSize(addresses.size()).allMatch(AddressInspector.AddressResult::reachable);
        assertThat(maxInFlight.get()).isBetween(2, AddressInspector.MAX_CONCURRENT_HANDSHAKES);
    }

    @Test
    void rejectsIpAddresses() {
        assertThatThrownBy(() -> inspector.inspect("192.0.2.1")).isInstanceOf(IllegalArgumentException.class);

        verifyNoInteractions(domainResolver);
    }

    @Test
    void inspectsASingleAddressWithoutSni() throws Exception {
        var address = address("2001:db8::1");
        when(certificateFetcher.fetchCertificate(address, null, AddressInspector.PORT, true))
                .thenReturn(new CertificateFetcher.HandshakeResult(List.of(leaf()), false));

        var result = inspector.inspect(address);

        assertThat(result.address()).isEqualTo(address);
        assertThat(result.reachable()).isTrue();
        assertThat(result.handshake().certificates()).containsExactly(leaf());
        verifyNoInteractions(domainResolver);
    }

    @Test
    void reportsTheErrorOfASingleUnreachableAddress() throws Exception {
        var address = address("192.0.2.1");
        when(certificateFetcher.fetchCertificate(address, null, AddressInspector.PORT, true))
                .thenThrow(new ConnectException("Connection refused"));

        var result = inspector.inspect(address);

        assertThat(result.reachable()).isFalse();
        assertThat(result.error()).hasMessage("Connection refused");
    }

    private static InetAddress address(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
