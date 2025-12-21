package org.agencyapi.x509.inspector;

import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.agencyapi.x509.inspector.IpUtils.isValidIPv4;
import static org.agencyapi.x509.inspector.IpUtils.isValidIpAddress;

@Component
public class CertificateFetcher {
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
     * Sets up SSL context to trust all certificates
     */
    private void setupTrustAllCerts(HttpsURLConnection connection) throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllManager = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };

        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllManager, new java.security.SecureRandom());
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
    }
}
