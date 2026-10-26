package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Exercises {@link CertificateFetcher#fetchCertificate(InetAddress, String, int, boolean)} against local TLS servers on
 * the IPv4 and IPv6 loopback addresses, checking that the domain is sent as SNI even though the connection is by IP.
 */
@Timeout(30)
class AddressHandshakeTest {
    private static final String DOMAIN = "example.test";

    @TempDir
    static Path directory;

    private static SSLContext serverContext;
    private static final ExecutorService acceptors = Executors.newCachedThreadPool();
    // the SNI host names each accepted handshake requested, "" when the client sent none
    private static final BlockingQueue<String> requestedServerNames = new LinkedBlockingQueue<>();

    private final CertificateFetcher fetcher = new CertificateFetcher();

    @BeforeAll
    static void createServerContext() throws Exception {
        Keytool.genKeyPair(directory, "server.p12", "server", "CN=" + DOMAIN, "-ext", "san=dns:" + DOMAIN);
        var keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(directory.resolve("server.p12"))) {
            keyStore.load(in, Keytool.PASSWORD.toCharArray());
        }
        var keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, Keytool.PASSWORD.toCharArray());
        serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keyManagers.getKeyManagers(), null, null);
    }

    @AfterAll
    static void stopServers() {
        acceptors.shutdownNow();
    }

    @Test
    void sendsDomainAsSniWhenConnectingByIpv4Address() throws Exception {
        var address = InetAddress.getByName("127.0.0.1");
        try (var server = startServer(address)) {
            var result = fetcher.fetchCertificate(address, DOMAIN, server.getLocalPort(), true);

            assertThat(result.certificates()).hasSize(1);
            assertThat(result.certificates().getFirst().getSubjectX500Principal().getName()).isEqualTo("CN=" + DOMAIN);
            assertThat(result.ocspStapled()).isFalse();
            assertThat(requestedServerNames.poll(5, TimeUnit.SECONDS)).isEqualTo(DOMAIN);
        }
    }

    @Test
    void sendsDomainAsSniWhenConnectingByIpv6Address() throws Exception {
        var address = InetAddress.getByName("::1");
        ServerSocket server;
        try {
            server = startServer(address);
        } catch (IOException e) {
            assumeTrue(false, "IPv6 loopback is not available: " + e.getMessage());
            return;
        }
        try (server) {
            var result = fetcher.fetchCertificate(address, DOMAIN, server.getLocalPort(), true);

            assertThat(result.certificates()).hasSize(1);
            assertThat(requestedServerNames.poll(5, TimeUnit.SECONDS)).isEqualTo(DOMAIN);
        }
    }

    @Test
    void sendsAbsoluteDomainWithoutTheRootDotAsSni() throws Exception {
        var address = InetAddress.getByName("127.0.0.1");
        try (var server = startServer(address)) {
            fetcher.fetchCertificate(address, DOMAIN + ".", server.getLocalPort(), true);

            assertThat(requestedServerNames.poll(5, TimeUnit.SECONDS)).isEqualTo(DOMAIN);
        }
    }

    @Test
    void failsHandshakeWithUntrustedCertificateUnlessTrustingAll() throws Exception {
        var address = InetAddress.getByName("127.0.0.1");
        try (var server = startServer(address)) {
            assertThatThrownBy(() -> fetcher.fetchCertificate(address, DOMAIN, server.getLocalPort(), false))
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

    private static SSLServerSocket startServer(InetAddress address) throws IOException {
        var server = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0, 50, address);
        requestedServerNames.clear();
        acceptors.submit(() -> {
            while (!server.isClosed()) {
                try (var socket = (SSLSocket) server.accept()) {
                    socket.startHandshake();
                    var names = ((ExtendedSSLSession) socket.getSession()).getRequestedServerNames();
                    requestedServerNames.add(names.stream()
                            .filter(SNIHostName.class::isInstance)
                            .map(name -> ((SNIHostName) name).getAsciiName())
                            .findFirst()
                            .orElse(""));
                } catch (IOException _) {
                    // the client closing mid-handshake, or the server socket closing, is expected here
                }
            }
        });
        return server;
    }
}
