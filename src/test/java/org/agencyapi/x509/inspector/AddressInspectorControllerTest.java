package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.agencyapi.x509.inspector.TestCertificates.ca;
import static org.agencyapi.x509.inspector.TestCertificates.leaf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers {@code /inspect/{domain}/addresses}, which inspects the certificate chain of every A and AAAA address.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
class AddressInspectorControllerTest {
    private static final InetAddress IPV4 = address("192.0.2.1");
    private static final InetAddress IPV6 = address("2001:db8::1");

    @Autowired
    private WebApplicationContext context;

    @MockitoBean
    private CertificateFetcher certificateFetcher;

    @MockitoBean
    private DomainResolver domainResolver;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
    }

    @Test
    void inspectsEveryResolvedAddress() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        when(certificateFetcher.fetchCertificate(eq(IPV4), anyString(), anyInt(), anyBoolean()))
                .thenReturn(new CertificateFetcher.HandshakeResult(List.of(leaf(), ca()), true));
        when(certificateFetcher.fetchCertificate(eq(IPV6), anyString(), anyInt(), anyBoolean()))
                .thenReturn(new CertificateFetcher.HandshakeResult(List.of(leaf()), false));

        mockMvc.perform(get("/inspect/example.com/addresses"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domain").value("example.com"))
                .andExpect(jsonPath("$.addresses", hasSize(2)))
                .andExpect(jsonPath("$.addresses[0].address").value("192.0.2.1"))
                .andExpect(jsonPath("$.addresses[0].type").value("A"))
                .andExpect(jsonPath("$.addresses[0].ocspStaplingEnabled").value(true))
                .andExpect(jsonPath("$.addresses[0].certificates", hasSize(2)))
                .andExpect(jsonPath("$.addresses[0].certificates[0].serialNumber").value(leaf().getSerialNumber().toString()))
                .andExpect(jsonPath("$.addresses[0]", not(hasKey("error"))))
                .andExpect(jsonPath("$.addresses[1].address").value("2001:db8::1"))
                .andExpect(jsonPath("$.addresses[1].type").value("AAAA"))
                .andExpect(jsonPath("$.addresses[1].ocspStaplingEnabled").value(false))
                .andExpect(jsonPath("$.addresses[1].certificates", hasSize(1)));
    }

    @Test
    void sendsTheDomainAsSniToEachAddress() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        when(certificateFetcher.fetchCertificate(any(InetAddress.class), anyString(), anyInt(), anyBoolean()))
                .thenReturn(new CertificateFetcher.HandshakeResult(List.of(leaf()), false));

        mockMvc.perform(get("/inspect/example.com/addresses")).andExpect(status().isOk());

        verify(certificateFetcher).fetchCertificate(IPV4, "example.com", 443, true);
        verify(certificateFetcher).fetchCertificate(IPV6, "example.com", 443, true);
    }

    @Test
    void reportsUnreachableAddressWithoutFailingTheOthers() throws Exception {
        when(domainResolver.resolve("example.com")).thenReturn(List.of(IPV4, IPV6));
        when(certificateFetcher.fetchCertificate(eq(IPV4), anyString(), anyInt(), anyBoolean()))
                .thenReturn(new CertificateFetcher.HandshakeResult(List.of(leaf()), false));
        when(certificateFetcher.fetchCertificate(eq(IPV6), anyString(), anyInt(), anyBoolean()))
                .thenThrow(new ConnectException("Network is unreachable"));

        mockMvc.perform(get("/inspect/example.com/addresses"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.addresses[0].certificates", hasSize(1)))
                .andExpect(jsonPath("$.addresses[1].type").value("AAAA"))
                .andExpect(jsonPath("$.addresses[1].error").value("Network is unreachable"))
                .andExpect(jsonPath("$.addresses[1]", not(hasKey("certificates"))))
                .andExpect(jsonPath("$.addresses[1]", not(hasKey("ocspStaplingEnabled"))));
    }

    @Test
    void limitsConcurrentHandshakesButInspectsEveryAddress() throws Exception {
        var addresses = IntStream.rangeClosed(1, CertificateInspectorController.MAX_CONCURRENT_HANDSHAKES + 8)
                .mapToObj(i -> address("192.0.2." + i))
                .toList();
        when(domainResolver.resolve("example.com")).thenReturn(addresses);
        var inFlight = new AtomicInteger();
        var maxInFlight = new AtomicInteger();
        when(certificateFetcher.fetchCertificate(any(InetAddress.class), anyString(), anyInt(), anyBoolean())).thenAnswer(_ -> {
            maxInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
            Thread.sleep(50);
            inFlight.decrementAndGet();
            return new CertificateFetcher.HandshakeResult(List.of(leaf()), false);
        });

        mockMvc.perform(get("/inspect/example.com/addresses"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.addresses", hasSize(addresses.size())));

        assertThat(maxInFlight.get()).isBetween(2, CertificateInspectorController.MAX_CONCURRENT_HANDSHAKES);
    }

    @Test
    void returnsNotFoundWhenTheDomainHasNoAddresses() throws Exception {
        when(domainResolver.resolve("example.com")).thenThrow(new UnknownHostException("No A or AAAA records found for example.com"));

        mockMvc.perform(get("/inspect/example.com/addresses"))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("No A or AAAA records")));
    }

    @Test
    void returnsBadGatewayWhenDnsLookupFails() throws Exception {
        when(domainResolver.resolve("example.com")).thenThrow(new IOException("DNS AAAA lookup for example.com. failed: timed out"));

        mockMvc.perform(get("/inspect/example.com/addresses"))
                .andExpect(status().isBadGateway())
                .andExpect(content().string(containsString("timed out")));
    }

    @Test
    void rejectsIpAddresses() throws Exception {
        mockMvc.perform(get("/inspect/192.0.2.1/addresses"))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(domainResolver);
    }

    @Test
    void validatesTheDomain() throws Exception {
        mockMvc.perform(get("/inspect/localhost/addresses"))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(domainResolver);
    }

    private static InetAddress address(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
