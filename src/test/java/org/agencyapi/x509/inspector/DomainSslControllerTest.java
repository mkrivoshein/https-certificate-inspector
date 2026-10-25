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

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.List;

import static org.agencyapi.x509.inspector.TestCertificates.*;
import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
class DomainSslControllerTest {
    @Autowired
    private WebApplicationContext context;

    @MockitoBean
    private CertificateFetcher certificateFetcher;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
        when(certificateFetcher.fetchCertificate(anyString(), anyBoolean())).thenReturn(List.of(leaf(), ca()));
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

        verify(certificateFetcher).fetchCertificate(eq("https://example.com"), eq(true));
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
        when(certificateFetcher.fetchCertificate(anyString(), anyBoolean())).thenReturn(List.of(otherNameFirst(), ca()));

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

        verifyNoInteractions(certificateFetcher);
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
    void mapsConnectionTimeoutToGatewayTimeout() throws Exception {
        when(certificateFetcher.fetchCertificate(anyString(), anyBoolean())).thenThrow(new SocketTimeoutException("timeout"));

        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isGatewayTimeout())
                .andExpect(jsonPath("$.message").value("Timed out connecting to example.com"));
    }

    @Test
    void mapsConnectionFailureToBadGateway() throws Exception {
        when(certificateFetcher.fetchCertificate(anyString(), anyBoolean())).thenThrow(new ConnectException("refused"));

        mockMvc.perform(get("/v1/domain/example.com/ssl"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.message").value("Unable to retrieve certificate from example.com"));
    }

    @Test
    void inspectEndpointIsUnchanged() throws Exception {
        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domain").value("example.com"))
                .andExpect(jsonPath("$.certificates", hasSize(2)))
                .andExpect(jsonPath("$.certificates[0].serialNumber").value(LEAF_SERIAL));
    }
}
