package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises {@link CertificateFetcher#checkOcspStapling} against a local TLS server. The JDK server does not staple
 * OCSP responses unless {@code jdk.tls.server.enableStatusRequestExtension} is set, so the server here never staples.
 */
@Timeout(30)
class OcspStaplingCheckTest {
    @TempDir
    static Path directory;

    private static SSLServerSocket serverSocket;
    private static ExecutorService acceptor;

    private final CertificateFetcher fetcher = new CertificateFetcher();

    @BeforeAll
    static void startTlsServer() throws Exception {
        Keytool.genKeyPair(directory, "server.p12", "server", "CN=localhost", "-ext", "san=dns:localhost");
        var keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(directory.resolve("server.p12"))) {
            keyStore.load(in, Keytool.PASSWORD.toCharArray());
        }
        var keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, Keytool.PASSWORD.toCharArray());
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), null, null);

        serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(0);
        acceptor = Executors.newSingleThreadExecutor();
        acceptor.submit(() -> {
            while (!serverSocket.isClosed()) {
                try (var socket = (SSLSocket) serverSocket.accept()) {
                    socket.startHandshake();
                } catch (IOException _) {
                    // the client closing mid-handshake, or the server socket closing, is expected here
                }
            }
        });
    }

    @AfterAll
    static void stopTlsServer() throws IOException {
        serverSocket.close();
        acceptor.shutdownNow();
    }

    @Test
    void reportsNoStaplingWhenServerDoesNotStaple() {
        assertThat(fetcher.checkOcspStapling("localhost", serverSocket.getLocalPort(), true)).isFalse();
    }

    @Test
    void reportsNoStaplingWhenCertificateIsNotTrusted() {
        // the self-signed server certificate fails default validation; the handshake error is swallowed
        assertThat(fetcher.checkOcspStapling("localhost", serverSocket.getLocalPort(), false)).isFalse();
    }

    @Test
    void reportsNoStaplingWhenNothingIsListening() throws IOException {
        int closedPort;
        try (var socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        assertThat(fetcher.checkOcspStapling("localhost", closedPort, true)).isFalse();
    }

    @Test
    void reportsNoStaplingWhenHostDoesNotResolve() {
        assertThat(fetcher.checkOcspStapling("nonexistent.invalid", 443, true)).isFalse();
    }
}
