package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.agencyapi.x509.inspector.TestCertificates.*;
import static org.junit.jupiter.api.Assertions.*;

class CertificateUtilsTest {
    @TempDir
    static Path directory;

    // certificates whose only name is the subject CN (no SAN extension), so only the CN fallback can match
    private static X509Certificate cnExampleCom;
    private static X509Certificate cnUpperCase;
    private static X509Certificate cnWildcard;
    private static X509Certificate cnLongerName;
    private static X509Certificate cnEscapedComma;

    @BeforeAll
    static void generateCnOnlyCertificates() throws Exception {
        cnExampleCom = cnOnly("cn-exact", "CN=example.com,O=Example Org");
        cnUpperCase = cnOnly("cn-upper", "CN=EXAMPLE.COM");
        cnWildcard = cnOnly("cn-wildcard", "CN=*.example.com");
        cnLongerName = cnOnly("cn-longer", "CN=example.com.evil");
        cnEscapedComma = cnOnly("cn-escaped-comma", "CN=example.com\\,O=Example Org");
    }

    @Test
    void matchesDnsNameAndWildcard() {
        assertTrue(CertificateUtils.verifyCertificateForDomain(leaf(), "example.com"));
        assertTrue(CertificateUtils.verifyCertificateForDomain(leaf(), "api.example.com"));
        assertFalse(CertificateUtils.verifyCertificateForDomain(leaf(), "example.org"));
    }

    @Test
    void matchesDnsNameListedAfterBinarySubjectAlternativeName() {
        assertTrue(CertificateUtils.verifyCertificateForDomain(otherNameFirst(), "othername.example.com"));
    }

    @Test
    void matchesCommonNameExactly() {
        assertTrue(CertificateUtils.verifyCertificateForDomain(cnExampleCom, "example.com"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.co", "xample.com", "www.example.com"})
    void doesNotMatchOtherNamesAgainstCommonName(String domain) {
        assertFalse(CertificateUtils.verifyCertificateForDomain(cnExampleCom, domain));
    }

    @Test
    void doesNotMatchCommonNameThatOnlyStartsWithTheDomain() {
        // CN=example.com.evil used to match example.com because the check was a substring search
        assertFalse(CertificateUtils.verifyCertificateForDomain(cnLongerName, "example.com"));
    }

    @Test
    void doesNotMatchEscapedCommaInsideCommonName() {
        // the CN value is "example.com,O=Example Org", not "example.com"
        assertFalse(CertificateUtils.verifyCertificateForDomain(cnEscapedComma, "example.com"));
    }

    @Test
    void matchesCommonNameIgnoringCase() {
        assertTrue(CertificateUtils.verifyCertificateForDomain(cnUpperCase, "example.com"));
    }

    @Test
    void appliesWildcardRulesToCommonName() {
        assertTrue(CertificateUtils.verifyCertificateForDomain(cnWildcard, "api.example.com"));
        assertFalse(CertificateUtils.verifyCertificateForDomain(cnWildcard, "example.com"));
        assertFalse(CertificateUtils.verifyCertificateForDomain(cnWildcard, "a.b.example.com"));
    }

    private static X509Certificate cnOnly(String alias, String dname) throws Exception {
        Keytool.genKeyPair(directory, "cn-only.p12", alias, dname);
        var certificate = Keytool.exportCertificate(directory, "cn-only.p12", alias);
        assertNull(certificate.getSubjectAlternativeNames(), "fixture must not carry SANs");
        return certificate;
    }
}
