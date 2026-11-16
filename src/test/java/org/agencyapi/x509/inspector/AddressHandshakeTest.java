package org.agencyapi.x509.inspector;

import com.google.common.net.InetAddresses;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Exercises {@link CertificateFetcher#fetchCertificate(InetAddress, String, int, boolean)} against local TLS servers on
 * the IPv4 and IPv6 loopback addresses, checking that the domain is sent as SNI even though the connection is by IP,
 * and that no SNI at all is sent when there is no domain.
 */
@Timeout(30)
class AddressHandshakeTest {
    private static final String DOMAIN = "example.test";

    @TempDir
    static Path directory;

    private static SSLContext serverContext;

    private final CertificateFetcher fetcher = new CertificateFetcher();

    @BeforeAll
    static void createServerContext() throws Exception {
        serverContext = LocalTlsServer.serverContext(directory, DOMAIN);
    }

    @Test
    void sendsDomainAsSniWhenConnectingByIpv4Address() throws Exception {
        var address = InetAddress.getByName("127.0.0.1");
        try (var server = startServer(address)) {
            var result = fetcher.fetchCertificate(address, DOMAIN, server.port(), true);

            assertThat(result.certificates()).hasSize(1);
            assertThat(result.certificates().getFirst().getSubjectX500Principal().getName()).isEqualTo("CN=" + DOMAIN);
            assertThat(result.ocspStapled()).isFalse();
            assertThat(server.nextRequestedServerName()).isEqualTo(DOMAIN);
        }
    }

    @Test
    void sendsDomainAsSniWhenConnectingByIpv6Address() throws Exception {
        var address = InetAddress.getByName("::1");
        LocalTlsServer server;
        try {
            server = startServer(address);
        } catch (IOException e) {
            assumeTrue(false, "IPv6 loopback is not available: " + e.getMessage());
            return;
        }
        try (server) {
            var result = fetcher.fetchCertificate(address, DOMAIN, server.port(), true);

            assertThat(result.certificates()).hasSize(1);
            assertThat(server.nextRequestedServerName()).isEqualTo(DOMAIN);
        }
    }

    @Test
    void sendsNoSniAndReturnsTheDefaultCertificateWhenInspectingIpv4Address() throws Exception {
        var address = InetAddress.getByName("127.0.0.1");
        try (var server = startServer(address)) {
            var result = fetcher.fetchCertificate(address, null, server.port(), true);

            assertThat(result.certificates()).hasSize(1);
            assertThat(result.certificates().getFirst().getSubjectX500Principal().getName()).isEqualTo("CN=" + DOMAIN);
            assertThat(server.nextRequestedServerName()).isEmpty();
        }
    }

    @Test
    void sendsNoSniAndReturnsTheDefaultCertificateWhenInspectingIpv6Address() throws Exception {
        var address = InetAddress.getByName("::1");
        LocalTlsServer server;
        try {
            server = startServer(address);
        } catch (IOException e) {
            assumeTrue(false, "IPv6 loopback is not available: " + e.getMessage());
            return;
        }
        try (server) {
            var result = fetcher.fetchCertificate(address, null, server.port(), true);

            assertThat(result.certificates()).hasSize(1);
            assertThat(result.certificates().getFirst().getSubjectX500Principal().getName()).isEqualTo("CN=" + DOMAIN);
            assertThat(server.nextRequestedServerName()).isEmpty();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"::ffff:127.0.0.1", "::ffff:7f00:1"})
    void connectsOverIpv4WithoutSniForAnIpv4MappedIpv6Address(String literal) throws Exception {
        // parsed the way the controller parses it; the server only listens on IPv4, so a handshake proves the family
        var address = InetAddresses.forString(literal);
        try (var server = startServer(InetAddress.getByName("127.0.0.1"))) {
            var result = fetcher.fetchCertificate(address, null, server.port(), true);

            assertThat(address).isInstanceOf(Inet4Address.class);
            assertThat(result.certificates().getFirst().getSubjectX500Principal().getName()).isEqualTo("CN=" + DOMAIN);
            assertThat(server.nextRequestedServerName()).isEmpty();
        }
    }

    @Test
    void sendsNoSniForAnAddressThatCarriesAHostName() throws Exception {
        // an address resolved from a name remembers it; without SNI turned off explicitly the JDK would send it
        var address = InetAddress.getByAddress(DOMAIN, new byte[]{127, 0, 0, 1});
        try (var server = startServer(address)) {
            fetcher.fetchCertificate(address, null, server.port(), true);

            assertThat(server.nextRequestedServerName()).isEmpty();
        }
    }

    @Test
    void sendsAbsoluteDomainWithoutTheRootDotAsSni() throws Exception {
        var address = InetAddress.getByName("127.0.0.1");
        try (var server = startServer(address)) {
            fetcher.fetchCertificate(address, DOMAIN + ".", server.port(), true);

            assertThat(server.nextRequestedServerName()).isEqualTo(DOMAIN);
        }
    }

    @Test
    void failsHandshakeWithUntrustedCertificateUnlessTrustingAll() throws Exception {
        var address = InetAddress.getByName("127.0.0.1");
        try (var server = startServer(address)) {
            assertThatThrownBy(() -> fetcher.fetchCertificate(address, DOMAIN, server.port(), false))
                    .isInstanceOf(SSLHandshakeException.class);
        }
    }

    @Test
    void failsWhenNothingIsListening() throws Exception {
        int closedPort;
        try (var socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        assertThatThrownBy(() -> fetcher.fetchCertificate(InetAddress.getByName("127.0.0.1"), DOMAIN, closedPort, true))
                .isInstanceOf(IOException.class);
    }

    @Test
    void rejectsNamesThatCannotBeSentAsSni() {
        assertThatThrownBy(() -> fetcher.fetchCertificate(InetAddress.getByName("127.0.0.1"), "example..test", 443, true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static LocalTlsServer startServer(InetAddress address) throws IOException {
        return LocalTlsServer.start(serverContext, address, 0);
    }
}
