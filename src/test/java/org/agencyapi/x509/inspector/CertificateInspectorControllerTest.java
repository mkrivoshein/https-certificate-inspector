package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.agencyapi.x509.inspector.TestCertificates.ca;
import static org.agencyapi.x509.inspector.TestCertificates.leaf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers {@code /inspect/{domain}}: the certificates of every A and AAAA address, the top-level fields taken from the
 * first reachable address, the OCSP fields ({@code ocspStaplingEnabled} and each certificate's {@code ocspUrl}), and
 * the default certificate of an IP address, inspected without SNI.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
class CertificateInspectorControllerTest {
    private static final String OCSP_URL = "http://ocsp.example.test";
    private static final InetAddress IPV4 = address("192.0.2.1");
    private static final InetAddress IPV6 = address("2001:db8::1");

    @TempDir
    static Path directory;

    private static X509Certificate leafWithOcsp;
    private static X509Certificate issuerWithoutOcsp;

    @Autowired
    private WebApplicationContext context;

    @MockitoBean
    private CertificateFetcher certificateFetcher;

    @MockitoBean
    private DomainResolver domainResolver;

    private MockMvc mockMvc;

    @BeforeAll
    static void generateCertificates() throws Exception {
        Keytool.genKeyPair(directory, "chain.p12", "leaf", "CN=example.com", "-ext", "aia=ocsp:uri:" + OCSP_URL);
        Keytool.genKeyPair(directory, "chain.p12", "issuer", "CN=Example Issuer");
        leafWithOcsp = Keytool.exportCertificate(directory, "chain.p12", "leaf");
        issuerWithoutOcsp = Keytool.exportCertificate(directory, "chain.p12", "issuer");
    }

    @BeforeEach
    void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4));
        serve(IPV4, false, leafWithOcsp, issuerWithoutOcsp);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void reportsStaplingResult(boolean stapled) throws Exception {
        serve(IPV4, stapled, leafWithOcsp, issuerWithoutOcsp);

        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ocspStaplingEnabled").value(stapled))
                .andExpect(jsonPath("$.addresses[0].ocspStaplingEnabled").value(stapled));
    }

    @Test
    void reportsOcspUrlPerCertificateAndOmitsItWhenAbsent() throws Exception {
        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.certificates", hasSize(2)))
                .andExpect(jsonPath("$.certificates[0].ocspUrl").value(OCSP_URL))
                // the key itself is left out, not sent as "ocspUrl": null
                .andExpect(jsonPath("$.certificates[1]", not(hasKey("ocspUrl"))))
                .andExpect(jsonPath("$.certificates[1].serialNumber").exists());
    }

    @Test
    void inspectsEveryResolvedAddress() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        serve(IPV4, true, leaf(), ca());
        serve(IPV6, false, leafWithOcsp);

        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domain").value("example.com"))
                // the top-level fields keep their meaning: the chain of the first address
                .andExpect(jsonPath("$.ocspStaplingEnabled").value(true))
                .andExpect(jsonPath("$.certificates", hasSize(2)))
                .andExpect(jsonPath("$.certificates[0].serialNumber").value(leaf().getSerialNumber().toString()))
                .andExpect(jsonPath("$.addresses", hasSize(2)))
                .andExpect(jsonPath("$.addresses[0].address").value("192.0.2.1"))
                .andExpect(jsonPath("$.addresses[0].type").value("A"))
                .andExpect(jsonPath("$.addresses[0].ocspStaplingEnabled").value(true))
                .andExpect(jsonPath("$.addresses[0].certificates", hasSize(2)))
                .andExpect(jsonPath("$.addresses[0]", not(hasKey("error"))))
                .andExpect(jsonPath("$.addresses[1].address").value("2001:db8::1"))
                .andExpect(jsonPath("$.addresses[1].type").value("AAAA"))
                .andExpect(jsonPath("$.addresses[1].ocspStaplingEnabled").value(false))
                .andExpect(jsonPath("$.addresses[1].certificates[0].serialNumber").value(leafWithOcsp.getSerialNumber().toString()));
    }

    @Test
    void sendsTheDomainAsSniToEachAddress() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        serve(IPV6, false, leaf());

        mockMvc.perform(get("/inspect/example.com")).andExpect(status().isOk());

        verify(certificateFetcher).fetchCertificate(IPV4, "example.com", 443, true);
        verify(certificateFetcher).fetchCertificate(IPV6, "example.com", 443, true);
    }

    @Test
    void reportsUnreachableAddressAndTakesTopLevelFieldsFromTheNextOne() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        when(certificateFetcher.fetchCertificate(eq(IPV4), anyString(), anyInt(), anyBoolean()))
                .thenThrow(new ConnectException("Connection refused"));
        serve(IPV6, true, leaf());

        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ocspStaplingEnabled").value(true))
                .andExpect(jsonPath("$.certificates", hasSize(1)))
                .andExpect(jsonPath("$.addresses[0].error").value("Connection refused"))
                .andExpect(jsonPath("$.addresses[0]", not(hasKey("certificates"))))
                .andExpect(jsonPath("$.addresses[0]", not(hasKey("ocspStaplingEnabled"))))
                .andExpect(jsonPath("$.addresses[1].certificates", hasSize(1)));
    }

    @Test
    void returnsBadGatewayWhenNoAddressIsReachable() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        when(certificateFetcher.fetchCertificate(any(InetAddress.class), anyString(), anyInt(), anyBoolean()))
                .thenThrow(new ConnectException("Connection refused"));

        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isBadGateway())
                .andExpect(content().string(containsString("192.0.2.1 Connection refused")))
                .andExpect(content().string(containsString("2001:db8::1 Connection refused")));
    }

    @Test
    void returnsNotFoundWhenTheDomainHasNoAddresses() throws Exception {
        when(domainResolver.resolve("example.com")).thenThrow(new UnknownHostException("No A or AAAA records found for example.com"));

        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("No A or AAAA records")));
    }

    @Test
    void returnsBadGatewayWhenDnsLookupFails() throws Exception {
        when(domainResolver.resolve("example.com")).thenThrow(new IOException("DNS AAAA lookup for example.com. failed: timed out"));

        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isBadGateway())
                .andExpect(content().string(containsString("timed out")));
    }

    @Test
    void inspectsTheDefaultCertificateOfAnIpv4AddressWithoutSni() throws Exception {
        mockMvc.perform(get("/inspect/192.0.2.1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domain").value("192.0.2.1"))
                .andExpect(jsonPath("$.certificates", hasSize(2)))
                .andExpect(jsonPath("$.addresses", hasSize(1)))
                .andExpect(jsonPath("$.addresses[0].address").value("192.0.2.1"))
                .andExpect(jsonPath("$.addresses[0].type").value("A"))
                .andExpect(jsonPath("$.addresses[0].certificates", hasSize(2)));

        verify(certificateFetcher).fetchCertificate(IPV4, null, 443, true);
        verifyNoInteractions(domainResolver);
    }

    @ParameterizedTest
    @ValueSource(strings = {"2001:db8::1", "2001:DB8:0:0:0:0:0:1"})
    void inspectsTheDefaultCertificateOfAnIpv6AddressWithoutSni(String address) throws Exception {
        serve(IPV6, true, leaf());

        mockMvc.perform(get("/inspect/" + address))
                .andExpect(status().isOk())
                // written in its short form, like the addresses of a domain
                .andExpect(jsonPath("$.domain").value("2001:db8::1"))
                .andExpect(jsonPath("$.ocspStaplingEnabled").value(true))
                .andExpect(jsonPath("$.certificates", hasSize(1)))
                .andExpect(jsonPath("$.addresses", hasSize(1)))
                .andExpect(jsonPath("$.addresses[0].address").value("2001:db8::1"))
                .andExpect(jsonPath("$.addresses[0].type").value("AAAA"));

        verify(certificateFetcher).fetchCertificate(IPV6, null, 443, true);
        verifyNoInteractions(domainResolver);
    }

    @Test
    void returnsBadGatewayWhenTheIpAddressIsUnreachable() throws Exception {
        when(certificateFetcher.fetchCertificate(eq(IPV4), any(), anyInt(), anyBoolean()))
                .thenThrow(new ConnectException("Connection refused"));

        mockMvc.perform(get("/inspect/192.0.2.1"))
                .andExpect(status().isBadGateway())
                .andExpect(content().string(containsString("192.0.2.1: Connection refused")));
    }

    @Test
    void rejectsIpv6AddressesWithAZoneId() throws Exception {
        mockMvc.perform(get("/inspect/fe80::1%25eth0"))
                .andExpect(status().isBadRequest());

        verify(certificateFetcher, never()).fetchCertificate(any(InetAddress.class), any(), anyInt(), anyBoolean());
    }

    @Test
    void validatesTheDomain() throws Exception {
        mockMvc.perform(get("/inspect/localhost"))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(domainResolver);
    }

    private void serve(InetAddress address, boolean stapled, X509Certificate... chain) throws IOException {
        // any() rather than anyString(): an IP address is inspected without SNI, so with a null server name
        when(certificateFetcher.fetchCertificate(eq(address), any(), anyInt(), anyBoolean()))
                .thenReturn(new CertificateFetcher.HandshakeResult(List.of(chain), stapled));
    }

    private static InetAddress address(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
