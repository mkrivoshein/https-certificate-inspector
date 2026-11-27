package org.agencyapi.x509.inspector;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * A TLS server on a local address that completes handshakes and records the SNI host name each client requested, so
 * tests can check what the inspector sends. It serves a self-signed certificate generated with {@link Keytool}.
 */
final class LocalTlsServer implements AutoCloseable {
    private final SSLServerSocket socket;
    // the SNI host names each accepted handshake requested, "" when the client sent none
    private final BlockingQueue<String> requestedServerNames = new LinkedBlockingQueue<>();

    private LocalTlsServer(SSLServerSocket socket) {
        this.socket = socket;
        Thread.ofVirtual().name("local-tls-server-" + socket.getLocalPort()).start(this::accept);
    }

    /**
     * Generates a key pair for {@code dnsName} in {@code directory} and returns a server context presenting it, with
     * {@code CN=<dnsName>} as subject.
     */
    static SSLContext serverContext(Path directory, String dnsName) throws Exception {
        Keytool.genKeyPair(directory, "server.p12", "server", "CN=" + dnsName, "-ext", "san=dns:" + dnsName);
        var keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(directory.resolve("server.p12"))) {
            keyStore.load(in, Keytool.PASSWORD.toCharArray());
        }
        var keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, Keytool.PASSWORD.toCharArray());
        var context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), null, null);
        return context;
    }

    /**
     * @param port the port to listen on, or 0 for a free one
     * @throws IOException if the address or port can't be bound, e.g. when IPv6 loopback is unavailable
     */
    static LocalTlsServer start(SSLContext context, InetAddress address, int port) throws IOException {
        return new LocalTlsServer((SSLServerSocket) context.getServerSocketFactory().createServerSocket(port, 50, address));
    }

    int port() {
        return socket.getLocalPort();
    }

    /**
     * @return the SNI host name the next handshake requested, "" if it sent none, or {@code null} if no handshake
     *         completed within 5 seconds
     */
    String nextRequestedServerName() throws InterruptedException {
        return requestedServerNames.poll(5, TimeUnit.SECONDS);
    }

    void forgetRequestedServerNames() {
        requestedServerNames.clear();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    private void accept() {
        while (!socket.isClosed()) {
            try (var client = (SSLSocket) socket.accept()) {
                client.startHandshake();
                var names = ((ExtendedSSLSession) client.getSession()).getRequestedServerNames();
                requestedServerNames.add(names.stream()
                        .filter(SNIHostName.class::isInstance)
                        .map(name -> ((SNIHostName) name).getAsciiName())
                        .findFirst()
                        .orElse(""));
            } catch (IOException _) {
                // the client closing mid-handshake, or the server socket closing, is expected here
            }
        }
    }
}
