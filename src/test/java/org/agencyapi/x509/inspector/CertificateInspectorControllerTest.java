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

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers the OCSP fields that {@code /inspect/{domain}} reports: {@code ocspStaplingEnabled} and each certificate's {@code ocspUrl}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
class CertificateInspectorControllerTest {
    private static final String OCSP_URL = "http://ocsp.example.test";

    @TempDir
    static Path directory;

    private static X509Certificate leafWithOcsp;
    private static X509Certificate issuerWithoutOcsp;

    @Autowired
    private WebApplicationContext context;

    @MockitoBean
    private CertificateFetcher certificateFetcher;

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
        when(certificateFetcher.fetchCertificate(anyString(), anyBoolean())).thenReturn(List.of(leafWithOcsp, issuerWithoutOcsp));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void reportsStaplingResult(boolean stapled) throws Exception {
        when(certificateFetcher.checkOcspStapling(anyString(), anyInt(), anyBoolean())).thenReturn(stapled);

        mockMvc.perform(get("/inspect/example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ocspStaplingEnabled").value(stapled));
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
    void checksStaplingOnTheRequestedDomain() throws Exception {
        mockMvc.perform(get("/inspect/example.com")).andExpect(status().isOk());

        verify(certificateFetcher).checkOcspStapling("example.com", 443, true);
    }
}
