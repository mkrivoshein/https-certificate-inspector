package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.agencyapi.x509.inspector.TestCertificates.*;
import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
class DomainSslControllerTest {
    @Autowired
    private WebApplicationContext context;

    private static final InetAddress IPV4 = address("192.0.2.1");
    private static final InetAddress IPV6 = address("2001:db8::1");

    @MockitoBean
    private CertificateFetcher certificateFetcher;

    @MockitoBean
    private DomainResolver domainResolver;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
        when(domainResolver.resolve(anyString())).thenReturn(List.of(IPV4));
        serve(IPV4, leaf(), ca());
    }

    @ParameterizedTest
    @ValueSource(strings = {"ssl", "tls"})
    void returnsSecurityTrailsShapedReply(String suffix) throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/" + suffix).param("apikey", "secret-key"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.endpoint").value("/v1/domain/example.com/" + suffix))
                .andExpect(jsonPath("$.meta.page").value(1))
                .andExpect(jsonPath("$.meta.max_page").value(1))
                .andExpect(jsonPath("$.meta.total_pages").value(1))
                .andExpect(jsonPath("$.meta.query.apikey").value(DomainSslController.MASKED_API_KEY))
                .andExpect(jsonPath("$.meta.query.domain").value("example.com"))
                .andExpect(jsonPath("$.meta.query.include_subdomains").value("False"))
                .andExpect(jsonPath("$.meta.query.page").value("1"))
                .andExpect(jsonPath("$.meta.query.status").value("valid"))
                .andExpect(jsonPath("$.record_count").value(1))
                .andExpect(jsonPath("$.records", hasSize(1)))
                .andExpect(jsonPath("$.records[0].dns_names", contains("*.example.com", "example.com", "www.example.com")))
                .andExpect(jsonPath("$.records[0].fingerprints.sha1").value(LEAF_SHA1))
                .andExpect(jsonPath("$.records[0].fingerprints.sha256").value(LEAF_SHA256))
                .andExpect(jsonPath("$.records[0].issuer.common_name").value("Example Test CA"))
                .andExpect(jsonPath("$.records[0].issuer.country", equalTo(List.of("US"))))
                .andExpect(jsonPath("$.records[0].issuer.organization", equalTo(List.of("Example Trust"))))
                .andExpect(jsonPath("$.records[0].subject.common_name").value("example.com"))
                .andExpect(jsonPath("$.records[0].not_before").value(LEAF_NOT_BEFORE))
                .andExpect(jsonPath("$.records[0].not_after").value(LEAF_NOT_AFTER))
                .andExpect(jsonPath("$.records[0].serial_number").value(LEAF_SERIAL));

        verify(certificateFetcher).fetchCertificate(IPV4, "example.com", 443, true);
    }

    @Test
    void omitsApiKeyFromQueryEchoWhenNotSent() throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.meta.query.apikey").doesNotExist());
    }

    @Test
    void matchesSubdomainsCoveredByWildcard() throws Exception {
        mockMvc.perform(get("/v1/domain/api.example.com/ssl"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.record_count").value(1));
    }

    @Test
    void matchesDnsNameListedAfterBinarySubjectAlternativeName() throws Exception {
        serve(IPV4, otherNameFirst(), ca());

        mockMvc.perform(get("/v1/domain/othername.example.com/ssl"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.record_count").value(1))
                .andExpect(jsonPath("$.records[0].dns_names", equalTo(List.of("othername.example.com"))));
    }

    @Test
    void returnsNoRecordsWhenCertificateDoesNotMatchHostname() throws Exception {
        mockMvc.perform(get("/v1/domain/example.org/ssl"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.record_count").value(0))
                .andExpect(jsonPath("$.records", empty()));
    }

    @Test
    void filtersCurrentCertificateByStatus() throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/ssl").param("status", "expired"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.meta.query.status").value("expired"))
                .andExpect(jsonPath("$.records", empty()));

        mockMvc.perform(get("/v1/domain/example.com/ssl").param("status", "all"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records", hasSize(1)));
    }

    @Test
    void laterPagesAreEmpty() throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/ssl").param("page", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.meta.page").value(2))
                .andExpect(jsonPath("$.meta.query.page").value("2"))
                .andExpect(jsonPath("$.records", empty()));

        verifyNoInteractions(domainResolver, certificateFetcher);
    }

    @Test
    void acceptsPageInRequestBody() throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/ssl")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"page\": 2}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.meta.page").value(2))
                .andExpect(jsonPath("$.records", empty()));
    }

    @Test
    void rejectsIncludeSubdomains() throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/ssl").param("include_subdomains", "true"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("include_subdomains is not supported"));
    }

    @Test
    void acceptsSecurityTrailsBooleanSpelling() throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/ssl").param("include_subdomains", "False"))
                .andExpect(status().isOk());
    }

    @Test
    void rejectsUnknownStatus() throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/ssl").param("status", "revoked"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("Invalid status")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "abc"})
    void rejectsInvalidPage(String page) throws Exception {
        mockMvc.perform(get("/v1/domain/example.com/ssl").param("page", page))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").isNotEmpty());
    }

    @Test
    void rejectsInvalidDomainWithJsonMessage() throws Exception {
        mockMvc.perform(get("/v1/domain/localhost/ssl"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("value should be a valid domain"));
    }

    @Test
    void returnsDistinctLeafCertificatesAcrossAddresses() throws Exception {
        var third = address("192.0.2.2");
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, third, IPV6));
        serve(third, leaf(), ca());
        serve(IPV6, otherNameFirst(), ca());

        // othername.example.com's certificate doesn't cover example.com, and the second copy of leaf() is a duplicate
        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.record_count").value(1))
                .andExpect(jsonPath("$.records[0].fingerprints.sha256").value(LEAF_SHA256));

        verify(certificateFetcher).fetchCertificate(IPV6, "example.com", 443, true);
    }

    @Test
    void returnsEveryMatchingCertificateWhenAddressesServeDifferentOnes() throws Exception {
        when(domainResolver.resolve("othername.example.com")).thenReturn(List.of(IPV4, IPV6));
        serve(IPV6, otherNameFirst(), ca());

        // leaf() covers *.example.com, otherNameFirst() covers othername.example.com
        mockMvc.perform(get("/v1/domain/othername.example.com/ssl"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.record_count").value(2))
                .andExpect(jsonPath("$.records[0].fingerprints.sha256").value(LEAF_SHA256))
                .andExpect(jsonPath("$.records[1].dns_names", equalTo(List.of("othername.example.com"))));
    }

    @Test
    void skipsUnreachableAddresses() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV6, IPV4));
        when(certificateFetcher.fetchCertificate(eq(IPV6), anyString(), anyInt(), anyBoolean()))
                .thenThrow(new ConnectException("Network is unreachable"));

        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.record_count").value(1));
    }

    @Test
    void mapsConnectionTimeoutToGatewayTimeout() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        when(certificateFetcher.fetchCertificate(any(InetAddress.class), anyString(), anyInt(), anyBoolean()))
                .thenThrow(new SocketTimeoutException("timeout"));

        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isGatewayTimeout())
                .andExpect(jsonPath("$.message").value("Timed out connecting to example.com"));
    }

    @Test
    void mapsConnectionFailureToBadGateway() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        when(certificateFetcher.fetchCertificate(eq(IPV4), anyString(), anyInt(), anyBoolean()))
                .thenThrow(new SocketTimeoutException("timeout"));
        when(certificateFetcher.fetchCertificate(eq(IPV6), anyString(), anyInt(), anyBoolean()))
                .thenThrow(new ConnectException("refused"));

        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.message").value("Unable to retrieve certificate from example.com"));
    }

    @Test
    void returnsNotFoundWhenTheDomainHasNoAddresses() throws Exception {
        when(domainResolver.resolve("example.com")).thenThrow(new UnknownHostException("No A or AAAA records found for example.com"));

        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("No A or AAAA records found for example.com"));
    }

    @Test
    void mapsDnsFailureToBadGateway() throws Exception {
        when(domainResolver.resolve("example.com")).thenThrow(new IOException("DNS A lookup for example.com. failed: timed out"));

        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.message").value("Unable to resolve example.com"));
    }

    @Test
    void rejectsIpAddressesWithJsonMessage() throws Exception {
        mockMvc.perform(get("/v1/domain/192.0.2.1/ssl"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("looks like an IP address")));
    }

    private void serve(InetAddress address, X509Certificate... chain) throws IOException {
        when(certificateFetcher.fetchCertificate(eq(address), anyString(), anyInt(), anyBoolean()))
                .thenReturn(new CertificateFetcher.HandshakeResult(List.of(chain), false));
    }

    private static InetAddress address(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
