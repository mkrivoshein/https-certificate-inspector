package org.agencyapi.x509.inspector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.IOException;
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

import static org.agencyapi.x509.inspector.IpUtils.isValidIPv4;
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
     * Fetches certificate by connecting to a specific IPv4 address while using a domain name for SNI
     * @param ipv4Address The IPv4 address to connect to (e.g., "142.250.185.46")
     * @param domainName The domain name for SNI and Host header (e.g., "www.google.com")
     * @param port The port to connect to (typically 443 for HTTPS)
     * @param trustAllCerts Whether to trust all certificates (use with caution)
     * @return List of X509Certificate objects from the server
     * @throws IOException if connection fails
     * @throws URISyntaxException if URL construction fails
     */
    public List<X509Certificate> fetchCertificate(String ipv4Address, String domainName, int port, boolean trustAllCerts)
            throws IOException, URISyntaxException {
        // Validate IPv4 address format
        if (!isValidIPv4(ipv4Address)) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ipv4Address);
        }

        // Build URL using the IPv4 address
        var urlString = String.format("https://%s:%d/", ipv4Address, port);
        var url = new URI(urlString).toURL();

        return fetchCertificate(url, domainName, trustAllCerts);
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
            SSLContext sslContext;
            if (trustAllCerts) {
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, buildTrustAllManagers(), new SecureRandom());
            } else {
                sslContext = SSLContext.getDefault();
            }

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
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, buildTrustAllManagers(), new java.security.SecureRandom());
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
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
