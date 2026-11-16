package org.agencyapi.x509.inspector;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.FileSystemUtils;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Inspects IP addresses end to end: real HTTP requests to the running app, which handshakes with local TLS servers on
 * the IPv4 and IPv6 loopback addresses (pointed at with {@code inspector.handshake-port}). Covers routing of IP
 * literals in the path, validation, parsing, address inspection and the handshake itself, without external network.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Timeout(60)
class InspectIpAddressEndToEndTest {
    private static final String DEFAULT_NAME = "default.example.test";

    private static Path directory;
    private static LocalTlsServer ipv4Server;
    // null when IPv6 loopback is unavailable, or the IPv4 server's port is taken on it
    private static LocalTlsServer ipv6Server;

    @LocalServerPort
    private int port;

    private final HttpClient client = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();

    /**
     * Keeps the app's startup check of a public site off the network; handshakes with an address still go through the
     * real {@link CertificateFetcher}.
     */
    @TestConfiguration
    static class OfflineStartup {
        @Bean
        @Primary
        CertificateFetcher offlineStartupCertificateFetcher() {
            return new CertificateFetcher() {
                @Override
                public List<X509Certificate> fetchCertificate(String urlString, boolean trustAllCerts) {
                    return List.of();
                }
            };
        }
    }

    @DynamicPropertySource
    static void pointHandshakesAtLocalServers(DynamicPropertyRegistry registry) {
        registry.add("inspector.handshake-port", InspectIpAddressEndToEndTest::startServers);
    }

    // both servers share one port, as the app connects to every address on the same one
    private static synchronized int startServers() {
        if (ipv4Server == null) {
            SSLContext context;
            try {
                directory = Files.createTempDirectory("inspect-ip-end-to-end");
                context = LocalTlsServer.serverContext(directory, DEFAULT_NAME);
                ipv4Server = LocalTlsServer.start(context, InetAddress.getByName("127.0.0.1"), 0);
            } catch (Exception e) {
                throw new IllegalStateException("Unable to start the local TLS server", e);
            }
            try {
                ipv6Server = LocalTlsServer.start(context, InetAddress.getByName("::1"), ipv4Server.port());
            } catch (IOException _) {
                ipv6Server = null;
            }
        }
        return ipv4Server.port();
    }

    @AfterAll
    static void stopServers() throws IOException {
        for (var server : new LocalTlsServer[]{ipv4Server, ipv6Server}) {
            if (server != null) {
                server.close();
            }
        }
        if (directory != null) {
            FileSystemUtils.deleteRecursively(directory);
        }
    }

    @BeforeEach
    void forgetEarlierHandshakes() {
        ipv4Server.forgetRequestedServerNames();
        if (ipv6Server != null) {
            ipv6Server.forgetRequestedServerNames();
        }
    }

    @Test
    void inspectsTheDefaultCertificateOfAnIpv4AddressWithoutSni() throws Exception {
        var reply = inspect("127.0.0.1");

        assertDefaultCertificate(reply, "127.0.0.1", "A");
        assertThat(ipv4Server.nextRequestedServerName()).isEmpty();
    }

    @Test
    void inspectsTheDefaultCertificateOfAnIpv6AddressWithoutSni() throws Exception {
        assumeTrue(ipv6Server != null, "IPv6 loopback is not available");

        var reply = inspect("::1");

        assertDefaultCertificate(reply, "::1", "AAAA");
        assertThat(ipv6Server.nextRequestedServerName()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"::ffff:127.0.0.1", "::ffff:7f00:1"})
    void inspectsAnIpv4MappedIpv6AddressOverIpv4(String literal) throws Exception {
        // routes an IPv6-style path even where IPv6 loopback is unavailable
        var reply = inspect(literal);

        assertDefaultCertificate(reply, "127.0.0.1", "A");
        assertThat(ipv4Server.nextRequestedServerName()).isEmpty();
    }

    @Test
    void rejectsAZonedAddress() throws Exception {
        var response = get("/inspect/fe80::1%25eth0");

        assertThat(response.statusCode()).isEqualTo(400);
    }

    private DocumentContext inspect(String address) throws Exception {
        var response = get("/inspect/" + address);
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JsonPath.parse(response.body());
    }

    private HttpResponse<String> get(String path) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static void assertDefaultCertificate(DocumentContext json, String address, String type) {
        assertThat(json.<String>read("$.domain")).isEqualTo(address);
        assertThat(json.<String>read("$.certificates[0].subject")).isEqualTo("CN=" + DEFAULT_NAME);
        assertThat(json.<List<Object>>read("$.addresses")).hasSize(1);
        assertThat(json.<String>read("$.addresses[0].address")).isEqualTo(address);
        assertThat(json.<String>read("$.addresses[0].type")).isEqualTo(type);
        assertThat(json.<String>read("$.addresses[0].certificates[0].subject")).isEqualTo("CN=" + DEFAULT_NAME);
    }
}
