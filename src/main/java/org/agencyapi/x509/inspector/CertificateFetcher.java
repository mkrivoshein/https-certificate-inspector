package org.agencyapi.x509.inspector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.agencyapi.x509.inspector.IpUtils.isValidIpAddress;

@Component
public class CertificateFetcher {
    private static final Logger logger = LoggerFactory.getLogger(CertificateFetcher.class);
    /**
     * Sends an HTTP HEAD request and retrieves the SSL/TLS certificate(s)
     * @param urlString The URL to connect to (must be HTTPS)
     * @return List of X509Certificate objects from the server
     * @throws IOException if connection fails
     */
    public List<X509Certificate> fetchCertificate(String urlString, boolean trustAllCerts) throws IOException, URISyntaxException {
        var url = new URI(urlString).toURL();
        var domainName = url.getHost();

        if (isValidIpAddress(domainName)) {
            throw new IllegalArgumentException("Only hostname based URLs are supported, " + domainName + " looks like an IP address");
        }

        return fetchCertificate(url, domainName, trustAllCerts);
    }

    /**
     * Result of a TLS handshake with one server address.
     * @param certificates the chain the server presented, leaf first
     * @param ocspStapled whether the server stapled an OCSP response during the handshake
     */
    public record HandshakeResult(List<X509Certificate> certificates, boolean ocspStapled) {
    }

    /**
     * Connects to a specific IPv4 or IPv6 address and performs a TLS handshake, sending {@code domainName} as SNI,
     * so each address a domain resolves to can be inspected. {@link HttpsURLConnection} sends no SNI when the URL host
     * is an IP address, which is why this opens the socket directly instead.
     * @param address The address to connect to
     * @param domainName The domain name to send as SNI (e.g., "www.google.com"), or {@code null} to send no SNI, so
     *                   the server presents its default certificate
     * @param port The port to connect to (typically 443 for HTTPS)
     * @param trustAllCerts Whether to trust all certificates (use with caution)
     * @return the presented certificates and whether an OCSP response was stapled
     * @throws IOException if the connection or handshake fails
     */
    public HandshakeResult fetchCertificate(InetAddress address, String domainName, int port, boolean trustAllCerts)
            throws IOException {
        // SNI carries no root dot, so an absolute name such as "example.com." is sent as "example.com";
        // names that cannot be sent as SNI are rejected before any connection is made.
        // An empty list explicitly turns SNI off, rather than leaving the JDK to derive a name from the address.
        List<SNIServerName> serverNames = domainName == null
                ? List.of()
                : List.of(new SNIHostName(domainName.endsWith(".") ? domainName.substring(0, domainName.length() - 1) : domainName));
        SSLContext sslContext;
        try {
            sslContext = trustAllCerts ? trustAllContext() : SSLContext.getDefault();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Unable to configure the TLS context", e);
        }

        try (var sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
            var params = sslSocket.getSSLParameters();
            params.setServerNames(serverNames);
            sslSocket.setSSLParameters(params);

            sslSocket.connect(new InetSocketAddress(address, port), 5000);
            sslSocket.setSoTimeout(5000);
            sslSocket.startHandshake();

            // no hostname verification: the application would prefer to download all certificates
            var session = sslSocket.getSession();
            var certificates = Arrays.stream(session.getPeerCertificates())
                    .filter(cert -> cert instanceof X509Certificate)
                    .map(cert -> (X509Certificate) cert)
                    .toList();
            var ocspStapled = session instanceof ExtendedSSLSession extSession && !extSession.getStatusResponses().isEmpty();
            return new HandshakeResult(certificates, ocspStapled);
        }
    }

    /**
     * Fetches certificate by connecting to a specific IPv4 address while using a domain name for SNI
     * @param url The URL to connect to (e.g., "142.250.185.46")
     * @param domainName The domain name for SNI and Host header (e.g., "www.google.com")
     * @param trustAllCerts Whether to trust all certificates (use with caution)
     * @return List of X509Certificate objects from the server
     * @throws IOException if connection fails
     */
    public List<X509Certificate> fetchCertificate(URL url, String domainName, boolean trustAllCerts)
            throws IOException {
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IllegalArgumentException("URL must use HTTPS protocol");
        }

        HttpsURLConnection connection = null;

        try {
            connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            // Set the Host header to use the domain name
            connection.setRequestProperty("Host", domainName);

            if (trustAllCerts) {
                try {
                    setupTrustAllCerts(connection);
                } catch (NoSuchAlgorithmException|KeyManagementException e) {
                    throw new IllegalStateException("Unable to configure trust for all certificates", e);
                }
            }

            // Disable hostname verification since the application would prefer to download all certificates
            connection.setHostnameVerifier((_, _) -> true);

            // Connect to trigger SSL handshake
            connection.connect();

            // Get the certificates
            Certificate[] certificates = connection.getServerCertificates();

            // Convert to X509Certificate array
            var x509Certs = Arrays.stream(certificates)
                    .filter(cert -> cert instanceof X509Certificate)
                    .map(cert -> (X509Certificate) cert)
                    .toArray(X509Certificate[]::new);

            return Arrays.asList(x509Certs);

        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Checks whether the server has OCSP Stapling enabled by examining the TLS handshake.
     * Returns false (rather than throwing) if the check cannot be completed.
     * @param host The hostname to connect to
     * @param port The port to connect to (typically 443)
     * @param trustAllCerts Whether to skip certificate validation
     * @return true if the server sends an OCSP stapling response during the TLS handshake
     */
    public boolean checkOcspStapling(String host, int port, boolean trustAllCerts) {
        try {
            var sslContext = trustAllCerts ? trustAllContext() : SSLContext.getDefault();

            try (SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket()) {
                SSLParameters params = sslSocket.getSSLParameters();
                params.setServerNames(List.of(new SNIHostName(host)));
                sslSocket.setSSLParameters(params);

                sslSocket.connect(new InetSocketAddress(host, port), 5000);
                sslSocket.setSoTimeout(5000);
                sslSocket.startHandshake();

                SSLSession session = sslSocket.getSession();
                if (session instanceof ExtendedSSLSession extSession) {
                    return !extSession.getStatusResponses().isEmpty();
                }
                return false;
            }
        } catch (Exception e) {
            logger.debug("OCSP stapling check failed for {}:{}: {}", host, port, e.getMessage());
            return false;
        }
    }

    /**
     * Sets up SSL context to trust all certificates
     */
    private void setupTrustAllCerts(HttpsURLConnection connection) throws NoSuchAlgorithmException, KeyManagementException {
        connection.setSSLSocketFactory(trustAllContext().getSocketFactory());
    }

    private SSLContext trustAllContext() throws NoSuchAlgorithmException, KeyManagementException {
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, buildTrustAllManagers(), new SecureRandom());
        return sslContext;
    }

    private TrustManager[] buildTrustAllManagers() {
        return new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };
    }
}
