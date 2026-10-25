package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class OcspUrlExtractionTest {
    private static final String OCSP_URL = "http://ocsp.example.test";
    private static final String CA_ISSUERS_URL = "http://ca.example.test/ca.crt";
    // longer than 127 bytes, so the URI's DER length needs the long form
    private static final String LONG_OCSP_URL = "http://ocsp.example.test/" + "a".repeat(130);

    @TempDir
    static Path directory;

    private static X509Certificate ocspOnly;
    private static X509Certificate caIssuersFirst;
    private static X509Certificate caIssuersOnly;
    private static X509Certificate noAia;
    private static X509Certificate longUrlFirstOfTwo;

    @BeforeAll
    static void generateCertificates() throws Exception {
        ocspOnly = certificate("ocsp-only", "aia=ocsp:uri:" + OCSP_URL);
        caIssuersFirst = certificate("ca-issuers-first", "aia=caIssuers:uri:" + CA_ISSUERS_URL + ",ocsp:uri:" + OCSP_URL);
        caIssuersOnly = certificate("ca-issuers-only", "aia=caIssuers:uri:" + CA_ISSUERS_URL);
        noAia = certificate("no-aia");
        longUrlFirstOfTwo = certificate("long-url", "aia=ocsp:uri:" + LONG_OCSP_URL + ",ocsp:uri:http://second-ocsp.example.test");
    }

    @Test
    void extractsOcspUrl() {
        assertThat(CertificateUtils.extractOcspUrl(ocspOnly)).isEqualTo(OCSP_URL);
    }

    @Test
    void skipsCaIssuersEntryListedBeforeOcsp() {
        assertThat(CertificateUtils.extractOcspUrl(caIssuersFirst)).isEqualTo(OCSP_URL);
    }

    @Test
    void returnsNullWhenAiaHasNoOcspEntry() {
        assertThat(CertificateUtils.extractOcspUrl(caIssuersOnly)).isNull();
    }

    @Test
    void returnsNullWithoutAiaExtension() {
        assertThat(CertificateUtils.extractOcspUrl(noAia)).isNull();
    }

    @Test
    void decodesLongFormLengthAndReturnsFirstOcspEntry() {
        assertThat(LONG_OCSP_URL).hasSizeGreaterThan(127);
        assertThat(CertificateUtils.extractOcspUrl(longUrlFirstOfTwo)).isEqualTo(LONG_OCSP_URL);
    }

    private static X509Certificate certificate(String alias, String... aia) throws Exception {
        var extraArgs = aia.length == 0 ? new String[0] : new String[]{"-ext", aia[0]};
        Keytool.genKeyPair(directory, "certificates.p12", alias, "CN=" + alias + ".example.test", extraArgs);
        return Keytool.exportCertificate(directory, "certificates.p12", alias);
    }
}
